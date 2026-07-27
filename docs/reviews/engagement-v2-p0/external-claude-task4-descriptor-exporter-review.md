# Revisão de segurança (somente-leitura) — exporter de schemas engagement-v2

Escopo: `scripts/export_engagement_v2_schemas.py`, com apoio de
`src/hackbot/engagement_v2/schemas.py`, `tests/engagement_v2/test_schemas.py` e
`.superpowers/sdd/2026-07-26-engagement-v2-security-contracts/task-4-report.md`.
Worktree: `.worktrees/engagement-v2-security-contracts`. Nenhum arquivo foi
editado; nenhum comando ofensivo/destrutivo foi executado.

---

## Veredicto

A confirmação do review anterior procede: **todas as defesas contra symlink do
exporter são baseadas em caminho (`lstat` via `Path.is_symlink`) e são
re-resolvidas por caminho no momento do uso** (`tempfile.mkstemp(dir=...)`,
`os.replace(temporary, target)`, `path.read_bytes()`, `os.open(destination)`).
Entre o check e o use existe uma janela TOCTOU clássica: um componente do caminho
(tipicamente o próprio diretório `destination` ou um pai) pode ser trocado por um
symlink depois da verificação e antes da operação. **Não há um único `O_NOFOLLOW`
nem uma única operação relativa a `dir_fd` no arquivo.**

Na configuração normal — `SCHEMA_ROOT` derivado de `Path(__file__).resolve()`
sob um repositório de propriedade do operador — a explorabilidade é baixa
(exige um pai gravável e hostil). Mas o contrato desta task é *drift-proof e
symlink-safe*, e a garantia atual é probabilística (largura da janela), não
estrutural. **Recomendo reimplementar write e `--check` com diretórios
descriptor-pinned (openat encadeado com `O_DIRECTORY|O_NOFOLLOW`), operações
relativas a `dir_fd`, `os.replace` com `src_dir_fd/dst_dir_fd` e `fsync` do fd de
diretório**, com **fail-closed rígido** quando a plataforma não oferece
`dir_fd`/`O_NOFOLLOW`.

Além do TOCTOU, encontrei duas lacunas funcionais de segurança que o TOCTOU
ofuscou: **`--check` não detecta arquivos extras** e **write não remove arquivos
obsoletos** — ou seja, um arquivo de schema injetado passa despercebido pelo
drift-gate.

Severidade agregada: **1 Critical, 3 Important, 4 Minor.** Nada bloqueia o uso
como ferramenta local de dev/CI, mas o Critical deve ser corrigido antes de
qualquer execução em diretório de destino não-exclusivamente-confiável.

---

## Desenho recomendado (o menor desenho seguro)

Princípio: **fixar o inode do diretório de destino em um descritor e nunca mais
tocar no caminho por string.** Depois que `dir_fd` aponta para o inode real,
qualquer troca posterior do *nome* `schemas/engagement-v2` por um symlink não
tem efeito — as escritas continuam indo para o inode fixado.

Restrições respeitadas: Python 3.11+, zero dependências runtime, apenas
`os`/`stdlib`. `tempfile.mkstemp` **não** aceita `dir_fd`, então o temporário é
criado à mão com `os.open(..., O_CREAT|O_EXCL|O_NOFOLLOW, 0o600, dir_fd=...)` e um
sufixo aleatório de `secrets.token_hex` (stdlib).

### 1. Gate de capacidade (fail-closed, uma vez, no início de `main`)

```python
_REQUIRED_DIR_FD = (os.open, os.mkdir, os.replace, os.unlink, os.stat)

def _require_secure_fs() -> None:
    missing = [name for name in ("O_DIRECTORY", "O_NOFOLLOW")
               if not hasattr(os, name)]
    if missing or not all(fn in os.supports_dir_fd for fn in _REQUIRED_DIR_FD) \
       or os.listdir not in os.supports_fd:
        raise RuntimeError(
            "refusing to run: platform lacks O_NOFOLLOW/dir_fd support "
            "required for symlink-safe schema export"
        )
```

Chave: **remover o `getattr(os, "O_DIRECTORY", 0)`** de hoje (linha 89). Aquele
fallback silencioso é o oposto de fail-closed.

### 2. Fixar o caminho por componentes (openat encadeado)

`SCHEMA_ROOT` = `REPOSITORY_ROOT / "schemas" / "engagement-v2"`. `REPOSITORY_ROOT`
já é canonicalizado por `.resolve()` no import, então é a raiz de confiança.
Abrir cada componente relativo abaixo dela com `O_NOFOLLOW|O_DIRECTORY` elimina
symlink em *qualquer* componente e o TOCTOU de pai:

```python
def _open_pinned_dir(root_fd: int, name: str, *, create: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=root_fd)      # ELOOP se symlink
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(name, 0o700, dir_fd=root_fd)
        return os.open(name, flags, dir_fd=root_fd)
```

Encadeia-se `schemas` → `engagement-v2` a partir de um fd aberto em
`REPOSITORY_ROOT`. `O_NOFOLLOW` faz `open` falhar com `ELOOP` se o componente
final for symlink; `O_DIRECTORY` garante que é diretório (ou `ENOTDIR`).
Traduzir `ELOOP`/`ENOTDIR`/`FileExistsError` em `RuntimeError("symlink
destination rejected: ...")` para preservar o contrato de mensagem já testado.

### 3. Write atômico relativo ao fd fixado

```python
def _write_one(dir_fd: int, name: str, content: bytes) -> None:
    tmp = f".{name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=dir_fd)
    try:
        os.fchmod(fd, 0o600)          # mantém: O_CREAT mode sofre umask
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp, dir_fd=dir_fd)
        raise
    finally:
        pass
os.fsync(dir_fd)   # uma vez, após todos os replaces
```

`O_EXCL` impede seguir/reutilizar um temporário plantado. `os.replace` com
ambos `src_dir_fd`/`dst_dir_fd` faz `renameat` dentro do inode fixado — o pai não
é re-resolvido por caminho, e `rename(2)` não segue symlink no componente final
de destino. `fsync(dir_fd)` torna os renames duráveis.

### 4. Poda de arquivos obsoletos/extras (write)

Depois de escrever o conjunto esperado, listar o diretório pelo fd e remover o
que não pertence — senão um schema injetado sobrevive a re-exports:

```python
expected = set(rendered)
for entry in os.listdir(dir_fd):
    if entry not in expected and not entry.endswith(".tmp"):
        os.unlink(entry, dir_fd=dir_fd)   # ou reportar e falhar, ver decisão
```

Decisão de produto: podar automaticamente **ou** recusar com erro. Para uma
ferramenta *drift-proof* eu recomendaria podar em write e **reportar como drift**
em `--check` (ver §5) — mas isso é uma escolha de contrato; sinalizo, não decido.

### 5. `--check` sem nenhuma escrita

Mesmo pin, porém **nunca** cria diretório, nunca abre com flag de escrita, nunca
faz `mkstemp`/`replace`/`fsync`:

```python
def _check(root_fd) -> tuple[str, ...]:
    try:
        dir_fd = _open_pinned_dir(root_fd, "engagement-v2", create=False)
    except FileNotFoundError:
        return tuple(sorted(rendered))          # tudo drift, sem criar
    # ELOOP -> RuntimeError (symlink) propaga
    drifted = []
    present = set(os.listdir(dir_fd))
    for name, expected in sorted(rendered.items()):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError:                          # ELOOP/ENOENT -> drift
            drifted.append(name); continue
        with os.fdopen(fd, "rb") as s:
            if s.read() != expected:
                drifted.append(name)
    drifted += sorted(present - set(rendered) - {n for n in present if n.endswith(".tmp")})
    return tuple(drifted)
```

`O_RDONLY|O_NOFOLLOW` no read fecha o redirecionamento por symlink que a leitura
atual (`path.read_bytes()`, que **segue** symlink) permite.

---

## Matriz de plataforma

| Recurso | Linux | macOS (darwin) | POSIX geral (BSD/Solaris) | Windows |
|---|---|---|---|---|
| `os.O_NOFOLLOW` | ✔ | ✔ | ✔ | **ausente** |
| `os.O_DIRECTORY` | ✔ | ✔ | ✔ | **ausente** |
| `dir_fd` em `open/mkdir/unlink/stat` (`os.supports_dir_fd`) | ✔ | ✔ | ✔ (POSIX.1-2008 `*at`) | **não** |
| `os.replace` com `src_dir_fd`/`dst_dir_fd` | ✔ | ✔ | ✔ (`renameat`) | **não** |
| `os.listdir(fd)` (`os.supports_fd`) | ✔ | ✔ | ✔ | **não** |
| `fsync` em fd de diretório | ✔ | ✔ (sem F_FULLFSYNC; ver nota) | ✔ | **não permitido** em handle de dir |
| Modo `0600` significativo | ✔ | ✔ | ✔ | parcial (ACL, não bits POSIX) |

Notas relevantes:

- **`O_NOFOLLOW` só protege o componente final** do `open`. Por isso o desenho
  encadeia um `openat` por componente a partir de `REPOSITORY_ROOT` — é o que a
  ausência de `O_RESOLVE_BENEATH`/`RESOLVE_NO_SYMLINKS` (não expostos pelo
  `os` do CPython em 3.11) exige. Não há necessidade de dependência: o
  encadeamento manual cobre.
- **macOS**: `fsync` não força flush até o prato (precisaria de `fcntl F_FULLFSYNC`
  via `fcntl.fcntl`, stdlib). Para um artefato de repositório isso é aceitável;
  a ordenação (dados→rename→fsync do dir) permanece correta. Risco residual de
  durabilidade só em queda de energia; não afeta o modelo de ameaça symlink.
- **Windows**: falta tudo que sustenta o pin. O código atual "funciona" por
  acidente (`getattr(...,0)` + `os.open` de diretório falhando de qualquer modo),
  o que é frágil. Recomendação: **fail-closed explícito** (o gate da §1). O
  exporter é ferramenta de dev/CI POSIX; recusar no Windows com mensagem clara é
  preferível a um caminho path-based inseguro.

---

## Testes determinísticos (race/symlink nos boundaries check→use)

Threads reais tornam o teste flaky. Torne a corrida determinística injetando a
troca **exatamente** no boundary, via monkeypatch, e prove que o pin a neutraliza.

1. **Symlink no destino, aberto com `O_NOFOLLOW`** (substitui os testes de
   `lstat`): pré-criar `engagement-v2` como symlink → `_open_pinned_dir` deve
   levantar `RuntimeError("symlink destination rejected")` por `ELOOP`, tanto em
   `[]` quanto em `["--check"]`. Idem para pai (`schemas` → symlink) e para
   arquivo final (`program.schema.json` → symlink) — este último provado agora
   por `open(O_NOFOLLOW)` falhar, não por `lstat`.

2. **Corrida vencida, neutralizada pelo pin (o teste-chave)**: envolver o
   helper de nome de temporário (ou `os.replace`) com um wrapper que, na
   primeira chamada, executa a troca maliciosa do *caminho* `SCHEMA_ROOT` por um
   symlink para um `attacker_dir`, e então delega. Assert: os bytes esperados
   aparecem no inode originalmente fixado e **`attacker_dir` permanece vazio**.
   Isso demonstra que ganhar a corrida não redireciona a escrita — é a prova
   positiva do descriptor-pin (o teste que o desenho path-based não consegue
   passar).

3. **Fail-closed de capacidade**: `monkeypatch.delattr(os, "O_NOFOLLOW")` e,
   separadamente, `monkeypatch.setattr(os, "supports_dir_fd", set())` →
   `main([])` e `main(["--check"])` levantam `RuntimeError` e **nada** é escrito
   (assert diretório inalterado / inexistente).

4. **Zero escrita em `--check` (fd-spy)**: envolver `os.open` para levantar se
   qualquer flag de escrita (`O_CREAT|O_WRONLY|O_RDWR`) for usada durante
   `--check`, e envolver `os.replace`/`os.mkdir`/`os.fsync` para falhar se
   chamados. Rodar `--check` em (a) destino idêntico, (b) com drift, (c) com
   arquivo extra, (d) destino ausente. Assert exit codes e que os wrappers
   nunca dispararam. Reforça os testes atuais de mtime before/after.

5. **Detecção de arquivo extra**: colocar `rogue.schema.json` no destino →
   `--check` retorna exit 1 listando `drift: rogue.schema.json` (ordenado); e
   (conforme decisão §4) write o remove. Cobre a lacuna que os testes atuais não
   exercem (eles só testam modificado/removido).

6. **Cleanup de temporário em falha de `replace`** (adaptar o teste existente):
   `os.replace` falha → assert `os.listdir(dir_fd)` não contém nenhum `*.tmp`
   (via fd, não `glob` de caminho) e que `os.fsync` do arquivo ocorreu.

7. **Spy de flags**: assert que `os.open` do arquivo recebeu
   `O_CREAT|O_EXCL|O_NOFOLLOW` e `dir_fd` não-nulo, e que `os.replace` recebeu
   `src_dir_fd` e `dst_dir_fd` — garante que a implementação não regrida para
   caminhos.

8. **`--check` não cria destino ausente** (manter o teste atual) e não segue
   symlink de leitura: destino com symlink de arquivo apontando para fora →
   `--check` marca drift/rejeita, sem ler o alvo externo.

---

## Findings

### Critical

**C1 — TOCTOU nas escritas: verificação e uso ambos por caminho, sem
`O_NOFOLLOW`/`dir_fd`.**
`scripts/export_engagement_v2_schemas.py:51-74` (`_write_one`) e `:77-94`
(`_write_files`). `_reject_symlink_components(target)` (l.53) faz `lstat` por
caminho; em seguida `tempfile.mkstemp(dir=destination)` (l.54) e
`os.replace(temporary, target)` (l.67) re-resolvem `destination`/pais por string.
`_write_files` mitiga com dupla checagem (l.78 e l.80) mas não fecha a janela.
Cenário de falha: em um `SCHEMA_ROOT` cujo pai seja gravável por outro
usuário/processo (tmp compartilhado, diretório de engagement multiusuário, CI
com workspace hostil), trocar `engagement-v2` (ou `schemas`) por um symlink
entre a checagem e o `replace` faz a escrita `0600` — inclusive `manifest.json`
— cair fora da árvore pretendida, no inode escolhido pelo atacante.
Correção mínima: descriptor-pin (Desenho §2–§3): `openat` encadeado com
`O_DIRECTORY|O_NOFOLLOW`, temporário com `O_CREAT|O_EXCL|O_NOFOLLOW` +
`dir_fd`, `os.replace(..., src_dir_fd, dst_dir_fd)`, `fsync(dir_fd)`.

### Important

**I1 — `--check` verifica symlink por caminho e depois lê seguindo symlink.**
`:33-48` (`_drifted_files`) e `:112-114`. `destination.is_symlink()`/
`_reject_symlink(path)` são `lstat`; `path.read_bytes()` (l.42) **segue**
symlink. Cenário: trocar um componente ou o arquivo final por symlink entre
`_reject_symlink` (l.40) e `read_bytes` (l.42) faz o `--check` ler o alvo
apontado pelo atacante, influenciando o resultado de drift/exit code (e lendo
conteúdo de fora da árvore). Não escreve, mas corrói a confiabilidade do gate.
Correção mínima: pin + `os.open(name, O_RDONLY|O_NOFOLLOW, dir_fd=...)`
(Desenho §5).

**I2 — Arquivos extras/obsoletos não são detectados nem removidos.**
`:33-48` (check itera só `rendered.items()`) e `:84-87` (write só grava o
conjunto esperado, nunca poda). Cenário: um `injected.schema.json` (plantado por
qualquer meio) sobrevive indefinidamente a `--check` (exit 0, "sem drift") e a
re-exports; um loader que faça `glob` do diretório o carrega como contrato
válido. O manifest lista só os esperados, mas o diretório vira superconjunto
silencioso. Confirmado pelos testes: `test_exporter_check_..._drift` só cobre
modificado/removido; nenhum teste cobre arquivo extra.
Correção mínima: em `--check`, comparar `set(os.listdir(dir_fd))` com
`set(rendered)` e reportar extras como drift; em write, podar (Desenho §4).
Decisão de contrato (podar vs. recusar) fica com o time.

**I3 — Degradação silenciosa de capacidade em vez de fail-closed.**
`:89` `directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)`. O
`getattr(..., 0)` transforma ausência de `O_DIRECTORY` em no-op em vez de recusa.
Como o desenho seguro passa a *depender* de `O_NOFOLLOW`/`dir_fd`, qualquer
plataforma sem esses recursos precisa **recusar**, não cair para path-based.
Cenário: rodar em ambiente sem `dir_fd` (Windows/embarcado) executaria o caminho
inseguro sem aviso.
Correção mínima: gate de capacidade fail-closed no início de `main` (Desenho §1)
e remover o fallback `getattr`.

### Minor

**M1 — `mkdir(exist_ok=True)` aceita destino que já é symlink-para-diretório.**
`:79`. `Path.mkdir(exist_ok=True)` suprime `FileExistsError` quando o alvo
resolve para diretório (segue symlink), então um `engagement-v2` que já seja
symlink-para-dir passa; só a re-checagem `lstat` da l.80 pega. Depende da ordem
de duas chamadas `lstat` — frágil. O descriptor-pin (`os.mkdir(..., dir_fd=)` +
reabrir com `O_NOFOLLOW`) elimina a ambiguidade.

**M2 — Sem atomicidade global do conjunto.** `:84-94`. Cada arquivo é
`replace`-ado individualmente; uma queda no meio deixa conjunto parcial. O
`manifest.json` é escrito por último (aparece por último em `rendered`,
`schemas.py:1200`), o que ajuda consumidores que validam via manifest, mas não
há barreira transacional. Aceitável para a ferramenta; anotar como residual.

**M3 — `fchmod` é redundante com o `0600` do `mkstemp`, porém correto — manter.**
`:61`. `tempfile.mkstemp` já cria `0600`; no desenho novo, `O_CREAT` sofre
`umask`, então **manter o `fchmod` explícito** garante exatamente `0600`
independente de `umask`. Informacional: não remover na refatoração.

**M4 — Mensagens de erro incluem o caminho do destino.** `:24`,`:82`. Baixo
impacto (ferramenta local de operador), mas em logs de CI compartilhados expõe
layout de diretório. Aceitável; anotar.

---

## Riscos residuais (após o desenho recomendado)

- **Raiz de confiança = `REPOSITORY_ROOT`.** O pin encadeia a partir de
  `Path(__file__).resolve()`, que segue symlinks no import. Se o próprio
  checkout viver sob um pai hostil, isso é canonicalizado uma vez no import —
  há uma janela minúscula nos pais *acima* de `REPOSITORY_ROOT` antes de abrir o
  fd de raiz, equivalente à confiança de simplesmente executar o script.
  **Severidade: baixa**; mitigável abrindo `REPOSITORY_ROOT` com `O_NOFOLLOW` e
  validando `st_dev/st_ino`, mas provavelmente overkill.
- **Durabilidade em macOS** (F_FULLFSYNC ausente): perda só em queda de energia;
  não afeta a propriedade anti-symlink. **Baixa.**
- **Não-atomicidade multi-arquivo (M2):** conjunto parcial após crash; próximo
  `--check` detecta e próximo write conserta. **Baixa.**
- **Decisão de poda (I2):** se optarem por *reportar* em vez de *remover* extras,
  operadores precisam agir no drift; se *remover*, um arquivo legítimo não-gerado
  colocado no diretório é apagado. Escolha de contrato, não defeito. **Baixa,
  depende da política.**
- **Sinais fora do FS:** o exporter confia em `render_schema_files()` como fonte
  da verdade; a integridade dos bytes gerados (não o transporte para disco) está
  fora do escopo desta task e já é coberta por `schemas.py` +
  `test_schema_rendering_and_manifest_hashes_are_deterministic`. Sem achado.

---

### Nota de procedência

O caminho do relatório indicado no prompt
(`.superpowers/sdd/2026-07-26-.../task-4-report.md`) estava correto; a primeira
tentativa de leitura falhou por um caminho relativo. Li o report e o
`task-4-recovery.md` no worktree. O report declara "No open Task 4 concerns" e
observa que um review read-only externo foi solicitado mas não retornou dentro
da janela — este documento é essa revisão, e ela **reabre** o item TOCTOU (C1)
mais três lacunas (I1–I3) não cobertas pela self-review nem pelos testes atuais.

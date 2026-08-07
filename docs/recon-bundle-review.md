# Recon Bundle Review

> GENERATED from the immutable bundle via `scripts/generate_recon_docs.py`. The bundle is parsed as inert data; no command is executed. Source attribution: CyberNeon Recon Bundle (public source; no formal license).


**Bundle:** Recon — CyberNeon Bundle · **Author:** CyberNeon Recon Bundle (public source; no formal license) () · **License:** none-found → reference-only, local reuse authorized with attribution.


**Notes:** 19 · **External/applicable:** 16 · **Internal (disabled):** 3


## Inventory & multi-axis classification

| Note | Difficulty | Updated | Type | Assess. | Bug-bounty | Risk | Approval | Noise | Volume | Scope risk | 3rd-party |
|---|---|---|---|---|---|---|---|---|---|---|---|
| asn & netblock enumeration | intermediario | 2026-07-17 | active | external | restricted | 2 | explicit | high | high | high | likely (ranges may not belong to target) |
| banner scanning | basico | 2026-07-17 | active | external | restricted | 2 | explicit | high | medium | medium | possible |
| consulta de certificado tls | basico | 2026-07-17 | passive | external | applicable | 0 | none | none | low | low | none |
| consulta de dns | basico | 2026-07-17 | mixed | external | applicable | 1 | auto-if-in-scope | low | low | low | none |
| descoberta de hosts numa rede interna | basico | 2026-07-17 | active | internal | disabled | disabled | forbidden-by-default | high | high | internal-only | n/a |
| enumeracao de diretorios | basico | 2026-07-17 | active | external | restricted | 2 | explicit | high | high | medium | none |
| enumeracao ldap | intermediario | 2026-07-17 | active | internal | disabled | disabled | forbidden-by-default | high | high | internal-only | n/a |
| enumeracao de rede em linux | basico | 2026-07-17 | active | internal | disabled | disabled | forbidden-by-default | high | medium | internal-only | n/a |
| github recon & leaked secrets | intermediario | 2026-07-18 | passive | external | applicable | 0 | none | none | low | low | none |
| google dorking | basico | 2026-07-17 | passive | external | applicable | 0 | none | none | low | low | none |
| js analysis & secrets extraction | intermediario | 2026-07-18 | mixed | external | applicable | 1 | auto-if-in-scope | low | medium | low | none |
| ferramentas de osint | basico | 2026-07-17 | passive | external | applicable | 0 | none | none | low | low | none |
| fuzzing de parametros & api discovery | intermediario | 2026-07-17 | active | external | restricted | 2 | explicit | high | high | medium | none |
| port scanning com bash e /dev/tcp | basico | 2026-07-17 | active | external | restricted | 2 | explicit | high | high | medium | possible |
| recon pipeline completo | intermediario | 2026-07-17 | mixed | external | applicable | 1 | auto-if-in-scope | medium | medium | medium | possible |
| subdomain discovery | intermediario | 2026-07-17 | mixed | external | applicable | 1 | auto-if-in-scope | low | medium | medium | possible |
| tcp fin fingerprint | intermediario | 2026-07-17 | active | external | restricted | 2 | explicit | high | medium | medium | possible |
| waf & cdn detection | intermediario | 2026-07-18 | mixed | external | applicable | 1 | auto-if-in-scope | low | low | high | likely (CDN/shared infra) |
| web crawling & js analysis | intermediario | 2026-07-17 | mixed | external | applicable | 1 | auto-if-in-scope | low | medium | medium | possible |

## Per-note detail

### asn & netblock enumeration  ·  `note-asn-netblock`
- **Skill target:** `skills/recon/asn-netblock-analysis`  ·  **Tags:** #hacking #recon #asn #netblock #ip-range
- **Intro:** expandir a superficie de ataque alem dos dominios conhecidos. descobrir ranges de ip, sistemas autonomos, e infraestrutura de rede do alvo. util pra achar shadow it, servidores esquecidos, e ips fora do escopo de dns.
- **Sections (12):** 1. asn discovery, 2. ip range discovery, expandir ranges a partir de ips conhecidos, 3. reverse dns em massa, 4. scan nos ranges descobertos, 5. cloud & cdn (cuidado com escopo), 6. ferramentas all-in-one, 7. workflow completo, 8. favicon hash fingerprinting, 9. SPF/DKIM como fonte de infra, 10. cloud asset discovery, checklist rapido
- **Commands captured (as data):** 11  ·  **Warnings:** 1  ·  **Checklist items:** 6
- **Required tools:** whois, amass, asnmap, mapcidr, dnsx
- **Required API keys:** SHODAN_API_KEY(optional)
- **Excluded sections:** 5. cloud & cdn (cuidado com escopo), scan nos ranges descobertos
- **macOS notes:** xargs-parallel
- **Policy:** ASN/netblock is a HYPOTHESIS source; probing ranges = L2; CDN/cloud ranges DISABLED; favicon-hash is L0 evidence only
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### banner scanning  ·  `note-banner-scanning`
- **Skill target:** `skills/recon/service-fingerprinting`  ·  **Tags:** #hacking #recon #banner-grabbing #fingerprinting
- **Intro:** tecnica de reconhecimento ativo que consiste em conectar nos servicos do alvo pra ler as mensagens de boas-vindas (banners) e identificar versoes de software, sistema operacional e tecnologias em uso.
- **Sections (11):** 1. leitura de banner com netcat e telnet, 2. servicos com tls/ssl, 3. banner grabbing automatizado com nmap, 4. identificacao de tecnologias web, 5. ferramentas especificas de banner, 6. interpretacao de resultados, 7. favicon hash - identificar mesmo servidor across domains, 8. jarm - tls server fingerprint, 9. http header ordering - ordem dos headers identifica web server, 10. service-specific probes - banners por protocolo, checklist rapido
- **Commands captured (as data):** 10  ·  **Warnings:** 10  ·  **Checklist items:** 15
- **Required tools:** nc, nmap, httpx
- **Required API keys:** none
- **Policy:** active banner grabbing across ports needs explicit approval
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### consulta de certificado tls  ·  `note-consulta-certificado-tls`
- **Skill target:** `skills/recon/tls-certificate-recon`  ·  **Tags:** #hacking #recon #tls #subdomain-enumeration #passive-recon
- **Intro:** tecnica passiva de reconhecimento que usa os logs publicos de certificate transparency (ct) pra descobrir subdominios de um alvo. como os certificados tls sao registrados publicamente, qualquer subdominio que tenha um certificado emitido fica visivel sem precisar tocar no alvo.
- **Sections (10):** 1. crt.sh via curl, 2. openssl pra inspecao direta, 3. ferramentas especializadas, subfinder, certspotter, 4. recursos online, 5. Censys, 6. SAN extraction, 7. CT log monitoring, checklist rapido
- **Commands captured (as data):** 7  ·  **Warnings:** 1  ·  **Checklist items:** 12
- **Required tools:** curl, openssl, tlsx, certspotter
- **Required API keys:** censys(optional)
- **Policy:** CT logs / crt.sh / censys are passive; live openssl fetch to in-scope host is L1
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### consulta de dns  ·  `note-consulta-dns`
- **Skill target:** `skills/recon/dns-recon`  ·  **Tags:** #hacking #recon #dns #passive-recon
- **Intro:** tecnicas de reconhecimento via dns pra descobrir subdominios, servidores de email, nameservers e outros registros associados a um dominio alvo. a maioria dessas consultas e passiva e nao gera ruido.
- **Sections (15):** 1. ferramentas nativas do sistema, host, dig, nslookup, 2. ferramentas especializadas, dnsrecon, fierce, amass, dnsx (projectdiscovery), 3. recursos online, 4. dns over https (doh) - queries stealth, 5. dnssec - verificar misconfig, 6. dns cache snooping, 7. nsec walking - dnssec zone enumeration, checklist rapido
- **Commands captured (as data):** 11  ·  **Warnings:** 4  ·  **Checklist items:** 15
- **Required tools:** dig, dnsx, dog, massdns
- **Required API keys:** none
- **Policy:** passive DNS/DoH is L0; active resolution/brute is L1; zone-transfer against 3rd parties excluded
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### descoberta de hosts numa rede interna  ·  `note-descoberta-hosts-rede-interna`
- **Skill target:** `skills/internal-recon/internal-host-discovery`  ·  **Tags:** #hacking #recon #network #host-discovery #internal-network
- **Intro:** tecnicas pra identificar quais maquinas estao ativas dentro de uma rede local. essencial como primeiro passo apos conseguir acesso a uma rede interna durante um pentest ou ctf.
- **Sections (19):** 1. descoberta passiva (zero ruido), netdiscover (modo passivo), p0f (fingerprint passivo), 2. descoberta ativa - camada 2 (arp), arp-scan, arping (um host por vez), nmap arp scan, 3. descoberta ativa - camada 3 (icmp/ping), ping sweep com bash, fping (mais rapido que ping loop), nmap icmp sweep, 4. descoberta avancada (sem icmp), 5. enumeracao windows (netbios/smb), naabu (projectdiscovery), 6. /proc/net/arp - descoberta instantanea em box comprometida, 7. ipv6 discovery, 8. dhcp sniffing - descobrir config de rede inteira, 9. responder modo analyze - mapeamento passivo, checklist rapido
- **Commands captured (as data):** 15  ·  **Warnings:** 3  ·  **Checklist items:** 12
- **Required tools:** nmap, arp-scan, netdiscover, fping
- **Required API keys:** none
- **macOS notes:** proc-net-arp; p0f; arp-scan; responder
- **Policy:** internal network host discovery; requires private-pentest/local-lab profile + explicit auth
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### enumeracao de diretorios  ·  `note-enumeracao-diretorios`
- **Skill target:** `skills/recon/parameter-discovery`  ·  **Tags:** #hacking #recon #directory-enumeration #fuzzing #web
- **Intro:** tecnica de reconhecimento ativo que consiste em fazer brute-force de caminhos (paths) em um servidor web pra descobrir paginas, arquivos e diretorios ocultos que nao sao linkados publicamente.
- **Sections (10):** 1. dirb, 2. gobuster, 3. ffuf (o mais flexivel), 4. feroxbuster (recursivo por padrao), 5. wordlists recomendadas, 6. 403 como sinal, 7. backup file patterns, 8. wordlist de JS, 9. API versioning, checklist rapido
- **Commands captured (as data):** 8  ·  **Warnings:** 2  ·  **Checklist items:** 9
- **Required tools:** ffuf, feroxbuster, gobuster, dirb
- **Required API keys:** none
- **macOS notes:** gnu-timeout
- **Policy:** directory brute-force = L2 high-volume; low-rate limited discovery may be L1 if program allows
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### enumeracao ldap  ·  `note-enumeracao-ldap`
- **Skill target:** `skills/internal-recon/ldap-enumeration`  ·  **Tags:** #hacking #recon #ldap #active-directory
- **Intro:** tecnicas de enumeracao do servico ldap (portas 389/636) pra extrair informacoes de um active directory: usuarios, grupos, politicas de senha, spns e mais. essencial em qualquer pentest de ambiente windows corporativo.
- **Sections (17):** 1. scan inicial com nmap, 2. ldapsearch - consultas manuais, consulta anonima (null bind), consulta autenticada, busca de spns (kerberoasting), laps (senhas de admin local), 3. ldapdomaindump, 4. ldapsearch-ad (consultas avancadas), 5. windapsearch, 6. netexec (nxc) - enumeracao automatizada, 7. bloodhound - mapeamento de caminhos de ataque, 8. as-rep roastable - contas sem preauth, 9. adcs enumeration - certificate services, 10. gmsa password read - service accounts com senha gerenciada, 11. dns zones em ad - descobrir dcs internos, 12. enum4linux-ng - versao modernizada, checklist rapido
- **Commands captured (as data):** 15  ·  **Warnings:** 2  ·  **Checklist items:** 20
- **Required tools:** ldapsearch, nmap, netexec, bloodhound
- **Required API keys:** none
- **macOS notes:** netexec; ad-tooling
- **Policy:** AD/LDAP enumeration; internal only; never enabled by an internal hostname appearing in data
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### enumeracao de rede em linux  ·  `note-enumeracao-linux`
- **Skill target:** `skills/internal-recon/linux-enumeration`  ·  **Tags:** #hacking #recon #linux #networking #nmap
- **Intro:** tecnicas e comandos pra descoberta de hosts e servicos em redes internas a partir de uma maquina linux. cobre desde ping sweep basico ate scans nmap otimizados e filtragem de resultados.
- **Sections (12):** 1. host discovery (identificacao de alvos), ping sweep, arpscan (camada 2), 2. nmap scanning strategies, descoberta massiva, naabu (projectdiscovery), port scan direcionado, scan completo (todas as portas), 3. filtragem de resultados, 4. /proc/net/arp, 5. ss / netstat, checklist rapido
- **Commands captured (as data):** 9  ·  **Warnings:** 0  ·  **Checklist items:** 9
- **Required tools:** nmap, ss, arp
- **Required API keys:** none
- **macOS notes:** proc-net-arp
- **Policy:** internal Linux host/network enumeration; internal profile only
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### github recon & leaked secrets  ·  `note-github-recon`
- **Skill target:** `skills/recon/github-recon`  ·  **Tags:** #hacking #recon #github #git #secrets #osint #passive-recon
- **Intro:** github e uma das maiores fontes de vazamento de credenciais e informacao interna. devs commitem api keys, configs, dockerfiles com endpoints internos, e ate .env em repo publico. dois vetores principais: (1) code search no github por secrets/endpoints do alvo, (2) .git exposto no web server do propr
- **Sections (17):** 1. github code search (passivo), queries manuais, github dorking avancado, via cli (gh), 2. github-subdomains (extrair subdominios do github), 3. travis-ci / gitlab / gists, 4. ferramentas automatizadas de secret scan, trufflehog, gitleaks, gitrob, 5. .git exposto no web server, deteccao, exploracao, 6. github dorks catalog (referencia rapida), 7. workflow completo, 8. validacao de secrets (antes de reportar), checklist rapido
- **Commands captured (as data):** 11  ·  **Warnings:** 1  ·  **Checklist items:** 10
- **Required tools:** gh, trufflehog, gitleaks, github-subdomains
- **Required API keys:** GITHUB_TOKEN
- **Policy:** public code search/secret discovery is L0; exposed .git fetch to in-scope host is L1
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### google dorking  ·  `note-google-dorking`
- **Skill target:** `skills/recon/osint`  ·  **Tags:** #hacking #recon #osint #google-dorking #passive-recon
- **Intro:** tecnica de reconhecimento passivo que usa operadores avancados do google pra encontrar informacoes sensiveis expostas publicamente: arquivos de configuracao, paineis de admin, databases, credenciais e mais.
- **Sections (15):** 1. operadores basicos, 2. dorks uteis pra recon, arquivos sensiveis, paineis de administracao, credenciais expostas, directory listing, erros e informacoes de debug, 3. dorks genericos (google hacking database), 4. ferramentas de automacao, 5. github dorks - credenciais em repos publicos, 6. google cache - paginas deletadas, 7. wayback + dorks - cruzar com archive.org, 8. shodan/censys + google - cruzar ips expostos, 9. github code search api - busca programatica, checklist rapido
- **Commands captured (as data):** 4  ·  **Warnings:** 2  ·  **Checklist items:** 11
- **Required tools:** browser, curl
- **Required API keys:** none
- **Policy:** search-engine dorking is fully passive
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### js analysis & secrets extraction  ·  `note-js-analysis`
- **Skill target:** `skills/recon/javascript-analysis`  ·  **Tags:** #hacking #recon #javascript #secrets #api-discovery #active-recon
- **Intro:** analise de arquivos javascript e onde mora o ouro. endpoints escondidos, chaves de api, configuracoes de firebase, urls internas, feature flags. apps modernos empacotam tudo no frontend e expõem muito mais do que dev imagina.
- **Sections (16):** 1. coleta de arquivos js, via crawl, via browser devtools, via source maps, 2. extracao de secrets, linkfinder (endpoints), secretfinder / trufflehog, regex manual (alto rendimento), 3. ferramentas dedicadas, jsmon (monitoramento continuo), jsfscan (all-in-one), nuclei js templates, 4. analise de webpack bundles, 5. workflow completo, 6. o que procurar (priorizado), checklist rapido
- **Commands captured (as data):** 11  ·  **Warnings:** 0  ·  **Checklist items:** 10
- **Required tools:** katana, gau, subjs, linkfinder, jsluice
- **Required API keys:** none
- **Policy:** collecting JS from in-scope host is L1; local secret extraction is L0
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### ferramentas de osint  ·  `note-osint-tools`
- **Skill target:** `skills/recon/osint`  ·  **Tags:** #hacking #recon #osint #passive-recon #tools
- **Intro:** colecao de ferramentas pra open source intelligence. reconhecimento passivo usando fontes publicas, sem tocar no alvo.
- **Sections (11):** 1. enumeracao de subdominios e dominios, 2. busca de pessoas e usernames, 3. shodan e censys, dorks uteis pro shodan, 4. reconhecimento de infraestrutura, 5. recursos online, 6. GitHub secret dorking, 7. wayback machine, 8. LinkedIn employee enum, 9. DNS history, checklist rapido
- **Commands captured (as data):** 8  ·  **Warnings:** 0  ·  **Checklist items:** 10
- **Required tools:** shodan, theHarvester, amass
- **Required API keys:** SHODAN_API_KEY, censys(optional)
- **Policy:** OSINT aggregation; Shodan/censys via adapters; no active probing
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### fuzzing de parametros & api discovery  ·  `note-param-fuzzing`
- **Skill target:** `skills/recon/parameter-discovery`  ·  **Tags:** #hacking #recon #fuzzing #parametros #api
- **Intro:** descobrir parametros aceitos, endpoints de api escondidos, e metodos http alternativos. onde achar input escondido que as ferramentas de dir fuzzing nao pegam.
- **Sections (15):** 1. parametro discovery (GET/POST), brute-force em urls conhecidas, 2. metodo http discovery, content-type bypass, 3. api endpoint discovery, swagger / openapi, graphql, robots.txt e sitemap, 4. wordlists customizadas, 5. 403 bypass em endpoints, 6. param miner (burp extension), 7. clairvoyance (graphql schema extraction), 8. openapi 3.0 parsing, 9. cache poisoning params, checklist rapido
- **Commands captured (as data):** 12  ·  **Warnings:** 1  ·  **Checklist items:** 10
- **Required tools:** arjun, ffuf, x8, paramspider
- **Required API keys:** none
- **Policy:** parameter/endpoint fuzzing = L2 (high request volume); only when program allows automated testing
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### port scanning com bash e /dev/tcp  ·  `note-port-scanning-bash`
- **Skill target:** `skills/recon/service-fingerprinting`  ·  **Tags:** #hacking #recon #port-scanning #bash #no-tools
- **Intro:** tecnica de scan de portas usando apenas bash puro, sem precisar de nmap ou qualquer outra ferramenta instalada. util quando voce tem uma shell limitada no alvo e precisa mapear a rede interna.
- **Sections (10):** 1. scan basico (todas as portas), 2. scan rapido (portas comuns), 3. scan com timeout, 4. scan de multiplos hosts, 5. scan paralelo (muito mais rapido), 6. alternativas sem /dev/tcp, 7. xargs -P (paralelo limpo), 8. /dev/udp (scan UDP), 9. Python one-liner (fallback), checklist rapido
- **Commands captured (as data):** 9  ·  **Warnings:** 0  ·  **Checklist items:** 9
- **Required tools:** nc, naabu, nmap
- **Required API keys:** none
- **macOS notes:** bash-dev-tcp; bash-dev-udp; gnu-timeout; xargs-parallel
- **Policy:** port scanning is L2; /dev/tcp & /dev/udp need macOS adaptation or naabu/nmap adapter
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### recon pipeline completo  ·  `note-recon-pipeline`
- **Skill target:** `skills/recon/recon-pipeline`  ·  **Tags:** #hacking #recon #pipeline #bug-bounty #automation
- **Intro:** encadeamento de todas as ferramentas de recon numa pipeline unica. do dominio aos findings. util pra bug bounty continuo e pentest de superficie de ataque.
- **Sections (5):** 1. pipeline passivo (zero pacotes no alvo), 2. pipeline ativo (crawl + js analysis), 3. pipeline ASN + netblock, 4. diffing (monitorar mudancas), 5. one-liner completo
- **Commands captured (as data):** 5  ·  **Warnings:** 0  ·  **Checklist items:** 0
- **Required tools:** subfinder, dnsx, httpx, katana, nuclei
- **Required API keys:** SHODAN_API_KEY(optional)
- **Policy:** passive pipeline L0; active pipeline L1; ASN+netblock stage inherits L2/disabled
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### subdomain discovery  ·  `note-subdomain-discovery`
- **Skill target:** `skills/recon/subdomain-discovery`  ·  **Tags:** #hacking #recon #subdominios #dns #passive-recon
- **Intro:** enumeracao de subdominios e crucial pra expandir a superficie de ataque. dominios esquecidos, ambientes de dev/staging, e portais internos expostos sao os alvos mais faceis.
- **Sections (8):** 1. enumeracao passiva (sem tocar no alvo), crt.sh (certificate transparency), motores de busca e agregadores, apis de terceiros, 2. enumeracao ativa (dns bruteforce), resolvers confiaveis, 3. validacao (filtrar vivos), checklist rapido
- **Commands captured (as data):** 13  ·  **Warnings:** 0  ·  **Checklist items:** 10
- **Required tools:** subfinder, amass, dnsx, httpx, puredns
- **Required API keys:** various-passive-sources(optional)
- **macOS notes:** gnu-timeout
- **Policy:** passive sources L0; DNS bruteforce L1 rate-limited; validation httpx L1
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### tcp fin fingerprint  ·  `note-tcp-fin-fingerprint`
- **Skill target:** `skills/recon/service-fingerprinting`  ·  **Tags:** #hacking #recon #fingerprinting #tcp #networking
- **Intro:** tecnica de fingerprinting de sistema operacional baseada no comportamento da pilha tcp/ip. ao enviar pacotes tcp com flags especificas pra portas abertas, voce consegue diferenciar sistemas pela forma como eles respondem (ou nao).
- **Sections (14):** 1. como funciona o tcp fin, 2. tcp fin simples com scapy (python), 3. usando nmap, 4. outras tecnicas de fingerprinting tcp, ttl (time to live), tcp window size, 5. fingerprinting passivo com p0f, 6. JA3/JA4 TLS fingerprinting, 7. JARM (active server fingerprinting), 8. HTTP/2 SETTINGS frame fingerprint, 9. favicon hash, 10. passive OS fingerprint via HTTP headers, 11. HASSH (SSH fingerprinting), checklist rapido
- **Commands captured (as data):** 10  ·  **Warnings:** 2  ·  **Checklist items:** 12
- **Required tools:** nmap, scapy, p0f, jarm
- **Required API keys:** none
- **macOS notes:** scapy; p0f
- **Policy:** TCP FIN/JARM/JA3 active fingerprinting = L2; scapy needs root/Linux-runner; JA3/JARM passive-ish subset L1
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### waf & cdn detection  ·  `note-waf-cdn-detection`
- **Skill target:** `skills/recon/waf-cdn-detection`  ·  **Tags:** #hacking #recon #waf #cdn #bypass #passive-recon
- **Intro:** identificar waf e cdn antes de qualquer recon ativo. scanear portas atraves de cloudflare produz ruido gigante e dados falsos. o alvo real ta atras do proxy. sem saber o que ta na frente, tu perde tempo e queima pelego.
- **Sections (15):** 1. deteccao rapida (passivo), headers http, wafw00f, 2. dns lookup — o cdn check mais confiavel, ranges conhecidos (grep rapido), 3. origin ip discovery (bypass do cdn), subdominios esquecidos, historico dns (passive dns), ssl cert fingerprint, favicon hash (shodan), 4. bypass via host header, 5. whatweb / tech detection, 6. waf bypass durante scans, 7. script: deteccao completa, checklist rapido
- **Commands captured (as data):** 12  ·  **Warnings:** 1  ·  **Checklist items:** 10
- **Required tools:** wafw00f, httpx, dig, whatweb
- **Required API keys:** none
- **Excluded sections:** origin ip discovery (bypass do cdn), bypass via host header
- **Policy:** passive WAF/CDN detection L1; ORIGIN-IP BYPASS sections DISABLED (defeats protection)
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)

### web crawling & js analysis  ·  `note-web-crawling`
- **Skill target:** `skills/recon/web-crawling`  ·  **Tags:** #hacking #recon #crawler #js-analysis #endpoints
- **Intro:** descobrir todos os endpoints, arquivos js, parametros e rotas de api de uma aplicacao web. essencial pra achar endpoints escondidos, apis internas, e segredos vazados em javascript.
- **Sections (11):** 1. url discovery (historico), 2. filtrar urls interessantes, 3. js analysis (garimpar secrets e endpoints), analise manual via browser devtools, 4. tecnologia fingerprinting, 5. workflow automatizado, 6. source maps, 7. mitmproxy2swagger, 8. mobile app analysis, 9. postman/insomnia collections vazadas, checklist rapido
- **Commands captured (as data):** 11  ·  **Warnings:** 1  ·  **Checklist items:** 10
- **Required tools:** katana, gau, waybackurls, httpx, hakrawler
- **Required API keys:** none
- **Policy:** wayback/gau L0; live crawl (katana) L1 with strict scope + rate limit
- **Source:** `references/recon/Recon-bundle.html` → CyberNeon Recon Bundle (public source; no formal license)


# Operator-customizable report templates — design

**Status:** approved (2026-07-26)

**Goal:** Let operators explicitly select global, per-platform Markdown
templates that can reorder report content while preserving the code-owned
reporting safety contract: reproducible evidence is referenced, demonstrated
impact stays separate from plausible impact, and invalid templates fail before
producing output.

**Non-goals:** No per-engagement overrides, conditionals, loops, includes,
arbitrary file reads, HTML rendering, external template engine, code execution,
or automatic submission to bug-bounty platforms.

## Context

`hackbot.reporting.render` currently renders findings through a typed,
code-owned platform registry for `generic`, `hackerone`, `bugcrowd`,
`yeswehack`, `intigriti`, and `immunefi`. The CLI exposes this as:

```text
hackbot finding report --engagement DIR [--platform NAME]
```

The repository already contains empty `templates/<platform>/` directories.
Custom templates must remain an explicit operator action and must not weaken
CLAUDE.md rule 10: demonstrated claims require reproducible evidence, and
demonstrated and plausible impact remain separate.

## Chosen approach

Each customized platform uses two declarative UTF-8 Markdown files:

```text
templates/<platform>/report.md
templates/<platform>/finding.md
```

`report.md` is the outer report skeleton. `finding.md` is rendered once for each
finding, and the resulting blocks replace `{findings}` in `report.md`.

The CLI activates custom templates only when the operator supplies
`--templates-dir DIR`. Without that option, the existing code-owned renderer is
unchanged. This keeps current behavior backward-compatible and prevents
implicit template discovery from the current working directory.

Two alternatives were rejected:

- A single file with repeat markers would require a custom control-flow
  language and a larger parser and security surface.
- A manifest containing only headings and section order would be safer but
  would not provide a genuinely customizable Markdown skeleton.

## Template interface

### Report placeholders

`report.md` accepts only:

- `{engagement_id}`
- `{platform_label}`
- `{finding_count}`
- `{findings}`

`{findings}` must occur exactly once and must be the only non-whitespace content
on its template line.

### Finding placeholders

`finding.md` accepts:

- `{finding_id}`
- `{title}`
- `{severity}`
- `{status}`
- `{vulnerability_type}`
- `{target}`
- `{action_id}`
- `{evidence}`
- `{summary}`
- `{reproduction_steps}`
- `{demonstrated_impact}`
- `{plausible_impact}`

The following safety-critical placeholders must each occur exactly once:

- `{evidence}`
- `{demonstrated_impact}`
- `{plausible_impact}`

Each safety-critical placeholder must also be the only non-whitespace content on
its own template line. The three placeholders therefore cannot be concatenated
or collapsed into one block; operators may freely supply and reorder headings
around their distinct value lines.

Other allowlisted placeholders may be omitted, reordered, or repeated.
`{evidence}` expands to a code-owned reference containing the evidence run ID
and its redacted `evidence/<run_id>/` location. It never reads or embeds evidence
content.

Templates support plain placeholders only. Validation rejects:

- unknown placeholder names;
- missing or repeated mandatory placeholders;
- conversions such as `{title!r}`;
- format specifications such as `{title:>20}`;
- attribute or index access such as `{finding.title}` or `{finding[title]}`;
- malformed braces or incomplete placeholder syntax.

Literal braces in Markdown are written with the standard doubled form `{{` and
`}}`.

No placeholder value is parsed a second time. Braces or Markdown contained in a
finding remain data and cannot introduce new template operations.

## Components and boundaries

### Template loading and validation

Add a focused reporting component responsible for:

1. resolving `DIR/<platform>/report.md` and `finding.md`;
2. requiring both paths to be regular, non-symlink files;
3. enforcing a 64 KiB limit on each file before decoding;
4. decoding strict UTF-8;
5. parsing placeholders with the Python standard library;
6. validating the allowlists and mandatory occurrence counts; and
7. returning an immutable validated template pair.

The platform name is validated against the existing `PLATFORMS` registry before
path resolution. The component has no include or file-expansion feature and
reads only the two fixed filenames beneath the selected platform directory.

### Rendering

The existing severity and finding-ID ordering remains authoritative. The
custom renderer builds a typed string mapping from each `Finding`, renders
`finding.md` once per ordered finding, joins the blocks, and then renders
`report.md`.

When no findings exist, both template files are still validated and
`{findings}` expands to the code-owned text `No findings recorded.` This
preserves the existing empty-report behavior while ensuring that a broken
template cannot remain latent.

The native renderer remains the default and is not implemented in terms of the
operator template mechanism. Custom templates layer over the same typed finding
data but do not replace the native safety fallback: an explicitly selected
custom template either renders successfully or fails.

### CLI

Extend the report command to:

```text
hackbot finding report --engagement DIR [--platform NAME]
                       [--templates-dir DIR]
```

- Without `--templates-dir`, call the existing native renderer.
- With `--templates-dir`, load and validate the exact template pair for the
  selected platform, then render through the validated custom path.
- Do not write any report content until template loading, validation, and full
  rendering succeed.

## Error handling

Template failures are user-input errors. They produce a concise message on
`stderr`, exit code `2`, and empty `stdout`.

Failures include:

- missing template root or platform directory;
- missing one or both required files;
- symlink or non-regular file;
- a file larger than 64 KiB;
- invalid UTF-8;
- malformed or disallowed placeholder syntax;
- missing or duplicated mandatory placeholders; and
- an unsupported platform.

There is no silent fallback after the operator explicitly supplies
`--templates-dir`. This prevents a report from being generated with an
unexpected layout.

## Security properties

- Templates are inert Markdown data, not executable code.
- Only fixed filenames are read; templates cannot include other files.
- Target-controlled finding values cannot select paths or change placeholder
  parsing.
- Raw evidence is never loaded into the renderer.
- Evidence remains a redacted run-ID reference.
- Demonstrated and plausible impact cannot be omitted or collapsed into one
  placeholder.
- Rendering remains local and performs no provider, platform, or network I/O.

## Testing strategy

Implement test-first and observe each new test fail for the intended reason
before adding production behavior.

### Parser and loader tests

- Accept every allowlisted placeholder and arbitrary section ordering.
- Reject unknown names, missing or duplicated mandatory placeholders,
  conversions, format specs, attribute/index access, and malformed braces.
- Reject missing files, a partial pair, non-regular files, symlinks, files over
  64 KiB, and invalid UTF-8.
- Validate both templates even when there are no findings.

### Renderer tests

- Reorder report and finding sections using a custom pair.
- Preserve severity/ID ordering.
- Keep braces in finding values inert.
- Keep evidence, demonstrated impact, and plausible impact distinct.
- Reference the redacted evidence location without embedding raw output.
- Render `No findings recorded.` for an empty collection.

### CLI tests

- Preserve native output when `--templates-dir` is absent.
- Select the custom renderer when it is present.
- Return exit code `2`, write a concise error to `stderr`, and leave `stdout`
  empty for every template validation failure.

### Regression gates

Run the full project gates:

```text
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
bash scripts/smoke_test.sh
```

## Documentation and roadmap

Update:

- `README.md` with the new CLI option and a compact example;
- `docs/findings-and-reporting.md` with template structure, placeholders,
  validation, and failure semantics;
- `docs/next-steps.md` to mark operator templates complete and promote streaming
  output caps to the next roadmap item; and
- the offline smoke test to confirm `finding report --help` exposes
  `--templates-dir`.

## Acceptance criteria

1. Native reports are byte-for-byte unchanged when no template directory is
   supplied.
2. Operators can reorder a platform report through the two documented Markdown
   files and allowlisted placeholders.
3. Evidence, demonstrated impact, and plausible impact are mandatory and
   structurally distinct on separate template lines.
4. Every invalid or incomplete custom template fails before report output, with
   exit code `2`.
5. No raw evidence, template code execution, implicit file discovery, or network
   operation is introduced.
6. All project regression gates pass.

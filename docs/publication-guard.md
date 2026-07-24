# Publication Guard

The local recon bundle `references/recon/Recon-bundle.html` (author **@reeshasx**,
"CyberNeon Recon Bundle") carries **no license**. Per the operator's decision it may
be used for **local, private** purposes with attribution, but **redistribution is
not authorized**. This guard prevents the bundle and its derived artifacts from
being pushed or distributed accidentally.

## Protected artifacts
- `references/recon/Recon-bundle.html` (immutable source)
- `generated/recon-bundle/**` (normalized notes + manifest)
- `docs/recon-bundle-review.md`, `docs/recon-bundle-risk-classification.md`,
  `docs/recon-bundle-macos-compatibility.md`

## Controls
1. **Pre-push hook** — `.githooks/pre-push` blocks any `git push` while these
   tracked artifacts exist, unless the operator sets
   `HACKBOT_ALLOW_PUBLISH_RECON=1` to explicitly acknowledge permission.
   Enabled with a **repo-local** git config (no global/system change):
   ```bash
   git config core.hooksPath .githooks
   ```
2. **Archive exclusion** — `.gitattributes` marks the artifacts `export-ignore`, so
   `git archive` (tarball/zip distribution) omits them.
3. **Package exclusion** — the built wheel contains only `src/hackbot/**`
   (`scripts/build_wheel.py`), so no recon artifact ships in a distributable
   package.

## If you obtain permission
If the author authorizes redistribution, record it in
`docs/licenses-and-attribution.md`, then push with:
```bash
HACKBOT_ALLOW_PUBLISH_RECON=1 git push <remote> <branch>
```
Until then, treat all protected artifacts as local-only.

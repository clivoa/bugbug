# Brewfile — MINIMAL just-in-time base environment for hackbot (bugbug).
#
# Only `uv` is installed now, to establish reproducible Python dependency
# management (venvs + locked installs of the [dev]/[secrets]/[config] extras).
#
# Everything else is DEFERRED to the phase that actually needs it — see the
# "deferred" section printed by scripts/bootstrap-macos.sh --dry-run. Tools already
# present on PATH (git, jq, rg, fd, ...) are NOT duplicated via Homebrew.
#
# No formula here modifies shell init files or requires sudo.

brew "uv"

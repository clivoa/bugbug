# Brewfile — base development environment for hackbot (bugbug).
# Installed by scripts/bootstrap-macos.sh. Recon/offensive tooling is a separate,
# feature-gated step (scripts/install-tools.sh) — NOT installed here by default.
#
# No formula here modifies shell init files or requires sudo.

# --- toolchains ---
brew "uv"            # Python env/deps manager (preferred over pip/venv-by-hand)
brew "pipx"          # isolated Python CLI apps
brew "go"            # ProjectDiscovery tools are built with Go
brew "openjdk@21"    # JRE/JDK 21 for the Burp Suite MCP extension

# --- core utilities (portability: GNU tools + macOS gaps) ---
brew "git"
brew "gh"
brew "jq"
brew "yq"
brew "ripgrep"       # rg — used instead of grep -P on macOS
brew "fd"
brew "coreutils"     # provides gtimeout, gsha256sum, etc. (macOS lacks `timeout`)
brew "gnu-sed"       # gsed — for scripts needing GNU `sed -r`
brew "wget"
brew "openssl@3"
brew "sqlite"

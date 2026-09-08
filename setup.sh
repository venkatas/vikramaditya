#!/bin/bash
# =============================================================================
# Vikramaditya — Tool Installer
# Installs all required tools via Homebrew, Go, and pip
# Usage: ./setup.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_TOOLS_DIR="$SCRIPT_DIR/tools"

log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

# Check for Xcode Command Line Tools
if ! xcode-select -p &>/dev/null; then
    log_warn "Xcode Command Line Tools not found. Prompting installation..."
    xcode-select --install
    log_warn "Please complete the Xcode Command Line Tools installation and run this script again."
    exit 1
fi

echo "============================================="
echo "  Vikramaditya — Tool Installer"
echo "============================================="

# Check for Homebrew
if ! command -v brew &>/dev/null; then
    log_warn "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Ensure brew is available in the current execution context (especially on Apple Silicon)
if [ -f "/opt/homebrew/bin/brew" ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
elif [ -f "/usr/local/bin/brew" ]; then
    eval "$(/usr/local/bin/brew shellenv)"
fi

# Set up a virtual environment to prevent PEP 668 managed environment conflicts on modern macOS
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    log_warn "Creating Python virtual environment at $VENV_DIR to satisfy PEP 668..."
    python3 -m venv "$VENV_DIR"
fi
set +u
source "$VENV_DIR/bin/activate"
set -u
log_ok "Activated virtual environment: $VENV_DIR"

# Install core dependencies from requirements.txt
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo "[*] Installing core dependencies from requirements.txt..."
    if "$VENV_DIR/bin/python" -m pip install --quiet -r "$SCRIPT_DIR/requirements.txt"; then
        log_ok "Core dependencies installed successfully"

    # uro ships as a Python CLI (not a Go tool). requirements.txt installs it into
    # .venv; ensure the venv bin is on PATH. Fallback for non-venv hosts:
    #   python3 -m pip install --user --break-system-packages "uro>=1.0.2"
    if ! command -v uro >/dev/null 2>&1; then
        if [ -x "$VENV_DIR/bin/uro" ]; then
            export PATH="$VENV_DIR/bin:$PATH"
            log_ok "uro available via .venv ($VENV_DIR/bin/uro)"
        else
            log_warn "uro missing after requirements install — try: $VENV_DIR/bin/pip install 'uro>=1.0.2'"
            log_warn "or: python3 -m pip install --user --break-system-packages 'uro>=1.0.2'"
        fi
    else
        log_ok "uro on PATH: $(command -v uro)"
    fi
    # rich pin note: requirements keep rich>=13.9.4,<14 (schemathesis 4.17).
    # semgrep wants rich~=13.5.2 — both resolve on the 13.9.x line. Do NOT install
    # rich 15 into the main .venv or semgrep breaks.

    # markitdown: office/PDF → Markdown helper (optional but recommended)
    if ! "$VENV_DIR/bin/python" -c "import markitdown" 2>/dev/null; then
        log_warn "Installing markitdown[all] into .venv for doc ingest..."
        "$VENV_DIR/bin/pip" install --quiet 'markitdown[all]' || log_warn "markitdown install failed — markitdown_helper.py unavailable"
    else
        log_ok "markitdown available in .venv"
    fi
    else
        log_err "Core dependency installation failed; setup cannot continue with a partial Python environment"
        exit 1
    fi
    if "$VENV_DIR/bin/python" -m pip check; then
        log_ok "Python dependency consistency check passed"
    else
        log_err "Python dependency consistency check failed after requirements installation"
        exit 1
    fi
fi

# Prowler 4.5 and PrincipalMapper are required for AWS whitebox coverage but
# cannot share the main venv. Prowler pins cryptography 43 and pydantic 1 while
# the main scanner requires newer cryptography and pydantic. Install and verify
# both tools in isolated environments instead of leaving requirements.txt
# impossible to resolve.
VIKRAMADITYA_ISOLATED_ROOT="${VIKRAMADITYA_ISOLATED_ROOT:-$HOME/.venvs}"
ISOLATED_PYTHON="$(command -v python3.11 2>/dev/null || command -v python3)"

install_isolated_python_tool() {
    local label="$1"
    local venv_dir="$2"
    local requirements_file="$3"
    local binary_name="$4"

    if [ ! -f "$requirements_file" ]; then
        log_err "$label requirements file missing: $requirements_file"
        return 1
    fi
    if [ ! -x "$venv_dir/bin/python" ]; then
        log_warn "Creating isolated $label environment at $venv_dir..."
        if ! "$ISOLATED_PYTHON" -m venv "$venv_dir"; then
            log_err "$label isolated environment creation failed"
            return 1
        fi
    fi
    if ! "$venv_dir/bin/python" -m pip install --quiet -r "$requirements_file"; then
        log_err "$label dependency installation failed"
        return 1
    fi
    if ! "$venv_dir/bin/python" -m pip check; then
        log_err "$label dependency consistency check failed"
        return 1
    fi
    if [ ! -x "$venv_dir/bin/$binary_name" ]; then
        log_err "$label command missing after installation: $venv_dir/bin/$binary_name"
        return 1
    fi
    if ! "$venv_dir/bin/$binary_name" --help >/dev/null 2>&1; then
        log_err "$label command failed its readiness probe"
        return 1
    fi
    log_ok "$label isolated environment is ready: $venv_dir/bin/$binary_name"
}

if ! install_isolated_python_tool \
    "Prowler" \
    "$VIKRAMADITYA_ISOLATED_ROOT/prowler" \
    "$SCRIPT_DIR/requirements-prowler.txt" \
    "prowler"; then
    exit 1
fi

if ! install_isolated_python_tool \
    "PrincipalMapper" \
    "$VIKRAMADITYA_ISOLATED_ROOT/pmapper" \
    "$SCRIPT_DIR/requirements-pmapper.txt" \
    "pmapper"; then
    exit 1
fi

# Propagate Go Path to running session
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

# Check for Go (needed for some tools)
if ! command -v go &>/dev/null; then
    log_warn "Go not found. Installing via Homebrew..."
    brew install go
fi

# Tools to install via Homebrew
BREW_TOOLS=(
    "nmap"
    "subfinder"
    "httpx"
    "nuclei"
    "ffuf"
    "amass"
    "sqlmap"
    "trufflehog"
    "gitleaks"
    "whatweb"
    "feroxbuster"
    "massdns"
)

echo ""
echo "[*] Installing tools via Homebrew..."
for tool in "${BREW_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool already installed ($(command -v "$tool"))"
    else
        echo "    Installing $tool..."
        if brew install "$tool" 2>/dev/null; then
            log_ok "$tool installed successfully"
        else
            log_err "$tool failed to install via brew, trying alternative..."
        fi
    fi
done

# Tools to install via Go
echo ""
echo "[*] Installing tools via Go..."

GO_TOOLS=(
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/LukaSikic/subzy@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
    "github.com/KathanP19/Gxss@latest"
    # v10.7.0 — recon binaries recon.sh already calls but setup.sh never installed
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest"
    "github.com/BishopFox/jsluice/cmd/jsluice@latest"
    # v10.7.0 — calibrated 401/403 bypass engine (payloads copied below)
    "github.com/devploit/nomore403@latest"
    "github.com/praetorian-inc/hadrian/cmd/hadrian@latest"
)

GO_TOOL_NAMES=(
    "dnsx"
    "katana"
    "naabu"
    "cdncheck"
    "interactsh-client"
    "gau"
    "dalfox"
    "subzy"
    "waybackurls"
    "anew"
    "qsreplace"
    "assetfinder"
    "gf"
    "asnmap"
    "mapcidr"
    "alterx"
    "urlfinder"
    "Gxss"
    "tlsx"
    "uncover"
    "shuffledns"
    "fingerprintx"
    "jsluice"
    "nomore403"
    "hadrian"
)

for i in "${!GO_TOOLS[@]}"; do
    tool_name="${GO_TOOL_NAMES[$i]}"
    tool_path="${GO_TOOLS[$i]}"
    if command -v "$tool_name" &>/dev/null; then
        log_ok "$tool_name already installed"
    else
        echo "    Installing $tool_name..."
        if go install "$tool_path" 2>/dev/null; then
            log_ok "$tool_name installed successfully"
        else
            log_err "$tool_name failed to install"
        fi
    fi
done

# gowitness v3 is required for the `gowitness scan single ...` syntax used by recon.
# The latest Go module currently requires a newer Go toolchain than some macOS setups
# ship with, so prefer the official prebuilt binary on Apple Silicon.
echo ""
echo "[*] Installing gowitness..."
if command -v gowitness &>/dev/null; then
    log_ok "gowitness already installed"
else
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    GOWITNESS_VERSION="3.1.1"
    GOWITNESS_URL=""

    case "$OS/$ARCH" in
        darwin/arm64) GOWITNESS_URL="https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/gowitness-${GOWITNESS_VERSION}-darwin-arm64" ;;
        darwin/x86_64) GOWITNESS_URL="https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/gowitness-${GOWITNESS_VERSION}-darwin-amd64" ;;
        linux/arm64|linux/aarch64) GOWITNESS_URL="https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/gowitness-${GOWITNESS_VERSION}-linux-arm64" ;;
        linux/x86_64) GOWITNESS_URL="https://github.com/sensepost/gowitness/releases/download/${GOWITNESS_VERSION}/gowitness-${GOWITNESS_VERSION}-linux-amd64" ;;
    esac

    mkdir -p "$HOME/go/bin"
    if [ -n "$GOWITNESS_URL" ] && curl -fsSL "$GOWITNESS_URL" -o "$HOME/go/bin/gowitness"; then
        chmod +x "$HOME/go/bin/gowitness"
        log_ok "gowitness installed successfully"
    else
        log_err "gowitness failed to install automatically — download a prebuilt binary from the official releases page"
    fi
fi

# Browser agent deps (optional — needed for --browser-scan phase)
echo ""
echo "[*] Installing browser agent dependencies (optional)..."
if python3 -c "import browser_use" &>/dev/null 2>&1; then
    log_ok "browser-use already installed"
else
    if pip3 install --quiet "browser-use>=0.1.40" "playwright>=1.44.0" "langchain-anthropic>=0.1.0" 2>/dev/null; then
        log_ok "browser-use + playwright + langchain-anthropic installed"
        playwright install chromium --with-deps 2>/dev/null || log_warn "playwright chromium install failed — run: playwright install chromium"
    else
        log_warn "browser-use install failed — --browser-scan phase will be skipped (non-fatal)"
    fi
fi

# Tools to install via pip
echo ""
echo "[*] Installing Python tools..."
PIP_TOOLS=("arjun" "waymore" "xnLinkFinder")
for pkg in "${PIP_TOOLS[@]}"; do
    name="${pkg%%[*}"   # strip extras like [cli]
    if pip3 show "$name" &>/dev/null; then
        log_ok "$name already installed"
    else
        echo "    Installing $pkg..."
        if pip3 install --quiet "$pkg" 2>/dev/null; then
            log_ok "$pkg installed successfully"
        else
            log_err "$pkg failed to install"
        fi
    fi
done


# Tier-A recon enrichment notes (uncover / tlsx / waymore / xnLinkFinder)
# - uncover: OPT-IN via UNCOVER=1 in recon.sh. Configure API keys in
#   ~/.config/uncover/provider-config.yaml (or SHODAN_API_KEY / FOFA_EMAIL+FOFA_KEY /
#   CENSYS_API_ID+CENSYS_API_SECRET). shodan-idb needs no key.
# - tlsx: installed above; Phase 3.5 SAN harvest always runs when present.
# - waymore: pip tool; archive URL pull in full recon (skipped in --quick).
# - xnLinkFinder: pip tool; richer JS/SPA endpoint mining after LinkFinder.
echo ""
echo "[*] Tier-A recon enrichment tools (uncover/tlsx/waymore/xnLinkFinder) — see docs/recon-enrichment.md"
if command -v uncover >/dev/null 2>&1; then
    log_ok "uncover on PATH: $(command -v uncover)"
else
    log_warn "uncover not installed — optional OPT-IN (UNCOVER=1); go install github.com/projectdiscovery/uncover/cmd/uncover@latest"
fi
if command -v xnLinkFinder >/dev/null 2>&1 || command -v xnlinkfinder >/dev/null 2>&1; then
    log_ok "xnLinkFinder on PATH"
else
    log_warn "xnLinkFinder not installed — pip3 install xnLinkFinder (JS/SPA endpoint mining)"
fi
if command -v waymore >/dev/null 2>&1; then
    log_ok "waymore on PATH: $(command -v waymore)"
else
    log_warn "waymore not installed — pip3 install waymore"
fi
if command -v tlsx >/dev/null 2>&1; then
    log_ok "tlsx on PATH: $(command -v tlsx)"
else
    log_warn "tlsx not installed — go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
fi

# garak (NVIDIA LLM vulnerability scanner) — the breadth engine of llm_hunt.py.
# Installed in an ISOLATED venv: it pulls heavy ML deps that would bloat/conflict
# with the main venv. llm_hunt._garak_bin() discovers ~/.venvs/garak/bin/garak.
echo ""
echo "[*] Installing garak (LLM red-team) in an isolated venv..."
if [ -x "$HOME/.venvs/garak/bin/garak" ]; then
    log_ok "garak already installed ($HOME/.venvs/garak/bin/garak)"
else
    if python3.11 -m venv "$HOME/.venvs/garak" 2>/dev/null || python3 -m venv "$HOME/.venvs/garak" 2>/dev/null; then
        if "$HOME/.venvs/garak/bin/pip" install --quiet garak 2>/dev/null; then
            log_ok "garak installed to $HOME/.venvs/garak/bin/garak"
        else
            log_warn "garak pip install failed — llm_hunt.py will skip the garak engine"
        fi
    else
        log_warn "garak venv creation failed (need python3.11) — llm_hunt.py garak engine unavailable"
    fi
fi

# Apple Silicon MLX — faster than Ollama on M-series chips
echo ""
if [[ "$(uname -m)" == "arm64" ]]; then
    echo "[*] Apple Silicon detected — installing MLX for faster local inference..."
    if python3 -c "import mlx_lm" &>/dev/null 2>&1; then
        log_ok "mlx-lm already installed"
    else
        if pip3 install --quiet mlx-lm 2>/dev/null; then
            log_ok "mlx-lm installed successfully (set BRAIN_PROVIDER=mlx to use)"
        else
            log_err "mlx-lm failed to install (requires macOS 13.3+ with Apple Silicon)"
        fi
    fi
else
    echo "[*] Intel/Linux — skipping MLX (Apple Silicon only)"
fi

# Repo-local helper tools (Python scripts cloned to tools/)
echo ""
echo "[*] Installing repo-local helper tools..."
mkdir -p "$REPO_TOOLS_DIR"

if [ -f "$REPO_TOOLS_DIR/drupalgeddon2.py" ]; then
    log_ok "drupalgeddon2.py already present ($REPO_TOOLS_DIR/drupalgeddon2.py)"
else
    if curl -sL "https://raw.githubusercontent.com/pimps/CVE-2018-7600/master/drupa7-CVE-2018-7600.py" -o "$REPO_TOOLS_DIR/drupalgeddon2.py"; then
        chmod +x "$REPO_TOOLS_DIR/drupalgeddon2.py"
        log_ok "drupalgeddon2.py installed to $REPO_TOOLS_DIR/drupalgeddon2.py"
    else
        log_err "drupalgeddon2.py failed to download"
    fi
fi

# LinkFinder — extract endpoints from JavaScript files
if [ -d "$REPO_TOOLS_DIR/LinkFinder" ]; then
    log_ok "LinkFinder already present"
else
    echo "    Cloning LinkFinder..."
    if git clone --quiet https://github.com/GerbenJavado/LinkFinder.git "$REPO_TOOLS_DIR/LinkFinder" 2>/dev/null; then
        pip3 install --quiet -r "$REPO_TOOLS_DIR/LinkFinder/requirements.txt" 2>/dev/null || true
        log_ok "LinkFinder installed to $REPO_TOOLS_DIR/LinkFinder/"
    else
        log_err "LinkFinder failed to clone"
    fi
fi

# SecretFinder — find secrets/credentials in JavaScript files
if [ -d "$REPO_TOOLS_DIR/SecretFinder" ]; then
    log_ok "SecretFinder already present"
else
    echo "    Cloning SecretFinder..."
    if git clone --quiet https://github.com/m4ll0k/SecretFinder.git "$REPO_TOOLS_DIR/SecretFinder" 2>/dev/null; then
        pip3 install --quiet -r "$REPO_TOOLS_DIR/SecretFinder/requirements.txt" 2>/dev/null || true
        log_ok "SecretFinder installed to $REPO_TOOLS_DIR/SecretFinder/"
    else
        log_err "SecretFinder failed to clone"
    fi
fi

# XSStrike — advanced XSS scanner with WAF bypass
if [ -d "$REPO_TOOLS_DIR/XSStrike" ]; then
    log_ok "XSStrike already present"
else
    echo "    Cloning XSStrike..."
    if git clone --quiet https://github.com/s0md3v/XSStrike.git "$REPO_TOOLS_DIR/XSStrike" 2>/dev/null; then
        pip3 install --quiet -r "$REPO_TOOLS_DIR/XSStrike/requirements.txt" 2>/dev/null || true
        log_ok "XSStrike installed to $REPO_TOOLS_DIR/XSStrike/"
    else
        log_err "XSStrike failed to clone"
    fi
fi

# graphql-cop (MIT) — GraphQL DoS/CSRF/info-leak checks (graphql_audit.py run_graphql_cop).
# NOT on PyPI (git-clone only). Deps are installed into the active venv WITHOUT its stale
# requests==2.25.1 pin (which would downgrade a shared dep); graphql-cop works with any
# recent requests.
if [ -f "$REPO_TOOLS_DIR/graphql-cop/graphql-cop.py" ]; then
    log_ok "graphql-cop already present"
else
    echo "    Cloning graphql-cop..."
    if git clone --quiet https://github.com/dolevf/graphql-cop.git "$REPO_TOOLS_DIR/graphql-cop" 2>/dev/null; then
        pip3 install --quiet simplejson termcolor PySocks 2>/dev/null || true
        log_ok "graphql-cop installed to $REPO_TOOLS_DIR/graphql-cop/"
    else
        log_err "graphql-cop failed to clone"
    fi
fi

# nomore403 payloads (headers/ips/httpmethods/midpaths/endpaths/...) — REQUIRED by
# the header/path bypass techniques. `go install` drops only the binary, so copy the
# payloads out of the Go module cache to a stable path nomore403_audit.py looks in
# (tools/nomore403/payloads). Without them nomore403 silently skips its best techniques.
echo ""
echo "[*] Installing nomore403 payloads..."
NM_PAYLOADS_DST="$REPO_TOOLS_DIR/nomore403/payloads"
if [ -d "$NM_PAYLOADS_DST" ] && [ -n "$(ls -A "$NM_PAYLOADS_DST" 2>/dev/null)" ]; then
    log_ok "nomore403 payloads already present ($NM_PAYLOADS_DST)"
else
    # Newest-by-mtime = the version go just installed (portable: `ls -td` avoids
    # the BSD-vs-GNU `sort -V` trap and lexicographic v1.10 < v1.5 misordering).
    # `|| true` — a no-match glob makes `ls -td` exit non-zero; under `set -euo
    # pipefail` the bare assignment would abort the whole installer before the
    # empty-guard below (offline / pruned GOMODCACHE / renamed upstream dir).
    NM_SRC="$(ls -td "$(go env GOMODCACHE 2>/dev/null)"/github.com/devploit/nomore403@*/payloads 2>/dev/null | head -1)" || true
    if [ -n "$NM_SRC" ] && [ -d "$NM_SRC" ]; then
        mkdir -p "$NM_PAYLOADS_DST"
        if cp -Rf "$NM_SRC"/. "$NM_PAYLOADS_DST"/ 2>/dev/null; then
            chmod -R u+rw "$NM_PAYLOADS_DST" 2>/dev/null || true
            log_ok "nomore403 payloads copied to $NM_PAYLOADS_DST"
        else
            log_err "nomore403 payloads copy failed from $NM_SRC"
        fi
    else
        log_warn "nomore403 payloads not in Go module cache — header/path bypass techniques limited"
        log_warn "  fix: git clone https://github.com/devploit/nomore403 && cp -r nomore403/payloads $NM_PAYLOADS_DST"
    fi
fi

# Install gf patterns (tomnomnom's pattern pack)
GF_PATTERNS_DIR="$HOME/.gf"
_GF_PATTERN_COUNT=$(find "$GF_PATTERNS_DIR" -maxdepth 1 -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
if [ "${_GF_PATTERN_COUNT:-0}" -gt 5 ]; then
    log_ok "gf patterns already installed ($GF_PATTERNS_DIR — ${_GF_PATTERN_COUNT} patterns)"
else
    echo "    Installing gf patterns..."
    mkdir -p "$GF_PATTERNS_DIR"
    # 1ndianl33t community patterns — primary source (reliable, no GOPATH dependency)
    TMP_GF=$(mktemp -d 2>/dev/null || mktemp -d -t 'gf-patterns')
    if git clone --quiet https://github.com/1ndianl33t/Gf-Patterns.git "$TMP_GF" 2>/dev/null; then
        cp "$TMP_GF"/*.json "$GF_PATTERNS_DIR/" 2>/dev/null || true
        rm -rf "$TMP_GF"
    else
        log_warn "1ndianl33t/Gf-Patterns clone failed — trying tomnomnom examples..."
    fi
    # tomnomnom's own patterns — fallback via go install + copy from module cache
    GOPATH_DIR="${GOPATH:-$HOME/go}"
    for gf_src in "$GOPATH_DIR"/pkg/mod/github.com/tomnomnom/gf*/examples/; do
        [ -d "$gf_src" ] && cp -r "$gf_src". "$GF_PATTERNS_DIR/" 2>/dev/null || true
    done
    _INSTALLED=$(find "$GF_PATTERNS_DIR" -maxdepth 1 -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
    if [ "${_INSTALLED:-0}" -gt 0 ]; then
        log_ok "gf patterns installed to $GF_PATTERNS_DIR/ (${_INSTALLED} patterns)"
    else
        log_warn "gf patterns: 0 patterns installed — run manually: git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-p && cp /tmp/gf-p/*.json ~/.gf/"
    fi
fi

# subfinder API key config (optional — improves subdomain coverage significantly)
echo ""
echo "[*] Setting up subfinder API key config..."
SUBFINDER_CONFIG_DIR="$HOME/.config/subfinder"
SUBFINDER_CONFIG="$SUBFINDER_CONFIG_DIR/provider-config.yaml"
mkdir -p "$SUBFINDER_CONFIG_DIR"
if [ -f "$SUBFINDER_CONFIG" ]; then
    log_ok "subfinder config already exists: $SUBFINDER_CONFIG"
else
    cat > "$SUBFINDER_CONFIG" << 'SUBFINDER_EOF'
# subfinder provider-config.yaml
# Fill in your API keys below for better subdomain coverage.
# Free tiers available for all providers.
#
# chaos (ProjectDiscovery) — https://chaos.projectdiscovery.io
# chaos:
#   - YOUR_CHAOS_API_KEY
#
# virustotal — https://www.virustotal.com/gui/my-apikey
# virustotal:
#   - YOUR_VIRUSTOTAL_API_KEY
#
# securitytrails — https://securitytrails.com/app/account/credentials
# securitytrails:
#   - YOUR_SECURITYTRAILS_API_KEY
#
# censys — https://search.censys.io/account/api
# censys:
#   - YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET
#
# shodan — https://account.shodan.io
# shodan:
#   - YOUR_SHODAN_API_KEY
#
# github — https://github.com/settings/tokens (no scopes needed)
# github:
#   - YOUR_GITHUB_TOKEN
SUBFINDER_EOF
    log_ok "subfinder config scaffold created: $SUBFINDER_CONFIG"
    log_warn "Edit $SUBFINDER_CONFIG to add API keys for better coverage"
fi

# Seed a DNS resolvers list for shuffledns (recon.sh Phase 1 mass-resolve /
# wildcard filter). recon.sh looks first at ~/.config/shuffledns/resolvers.txt;
# without it, the pre-httpx dead-name/wildcard filter silently no-ops.
echo ""
echo "[*] Seeding DNS resolvers for shuffledns..."
SHUFFLEDNS_RESOLVERS="$HOME/.config/shuffledns/resolvers.txt"
if [ -s "$SHUFFLEDNS_RESOLVERS" ]; then
    log_ok "resolvers.txt already present: $SHUFFLEDNS_RESOLVERS ($(wc -l < "$SHUFFLEDNS_RESOLVERS" | tr -d ' ') resolvers)"
else
    mkdir -p "$(dirname "$SHUFFLEDNS_RESOLVERS")"
    # Trusted, frequently-refreshed public resolver list.
    if curl -fsSL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$SHUFFLEDNS_RESOLVERS" 2>/dev/null \
        && [ -s "$SHUFFLEDNS_RESOLVERS" ]; then
        log_ok "resolvers.txt seeded to $SHUFFLEDNS_RESOLVERS ($(wc -l < "$SHUFFLEDNS_RESOLVERS" | tr -d ' ') resolvers)"
    else
        # Fallback: a small set of reliable public resolvers so shuffledns still fires.
        printf '%s\n' 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220 > "$SHUFFLEDNS_RESOLVERS"
        log_warn "resolvers.txt fetch failed — wrote 8 fallback public resolvers to $SHUFFLEDNS_RESOLVERS"
    fi
fi

# Update nuclei templates
echo ""
echo "[*] Updating nuclei templates..."
if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null || true
    log_ok "Nuclei templates updated"
fi

# Ensure nuclei >= 3.8.0 — GHSA-29rg-wmcw-hpf4 (community-template file-read) fix,
# and the -dast fuzzing engine (hunt.py run_nuclei_dast). Numeric compare avoids
# the lexicographic 3.10 < 3.8 trap.
if command -v nuclei &>/dev/null; then
    # `|| true` — a present-but-broken nuclei emitting no parseable semver makes
    # grep exit non-zero; under `set -euo pipefail` that would abort setup.sh
    # before the ${NUCLEI_VER:-0.0.0} fallback can apply.
    NUCLEI_VER="$(nuclei -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)" || true
    NUCLEI_NUM="$(echo "${NUCLEI_VER:-0.0.0}" | awk -F. '{printf "%d%03d%03d", $1,$2,$3}')"
    # 10# forces base-10 so a leading-zero build (e.g. 0.8.0 -> 0008000) can't be
    # mis-parsed as octal by the [ -lt ] test.
    if [ "$((10#${NUCLEI_NUM:-0}))" -lt 3008000 ]; then
        log_warn "nuclei ${NUCLEI_VER:-unknown} < 3.8.0 (template file-read advisory) — upgrading..."
        if brew upgrade nuclei 2>/dev/null || go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null; then
            log_ok "nuclei upgraded"
        else
            log_warn "nuclei upgrade failed — run manually: brew upgrade nuclei"
        fi
    else
        log_ok "nuclei ${NUCLEI_VER} (>= 3.8.0)"
    fi
fi

# Ensure Go bin is in PATH
GOPATH="${GOPATH:-$HOME/go}"
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    log_warn "Add Go bin to your PATH:"
    echo "    export PATH=\$PATH:$GOPATH/bin"
    echo "    # Add to ~/.zshrc for persistence"
fi


# ── Optional evidence / SBOM tools (opt-in; missing does NOT fail setup) ──────
# Gitleaks is already in BREW_TOOLS above. Syft/Grype/bagit power:
#   gitleaks_report.py / sbom_syft.py / evidence_bag.py
# See docs/gitleaks-syft-bagit.md
echo ""
echo "[*] Optional evidence/SBOM tools (not required for core VAPT)..."
for opt_tool in syft grype; do
    if command -v "$opt_tool" &>/dev/null; then
        log_ok "$opt_tool already installed ($(command -v "$opt_tool"))"
    else
        log_warn "$opt_tool not installed — optional: brew install $opt_tool"
    fi
done
if "$VENV_DIR/bin/python" -c "import bagit" 2>/dev/null; then
    log_ok "bagit (Python) available in venv"
else
    log_warn "bagit not in venv — optional: $VENV_DIR/bin/pip install 'bagit>=1.8.1' (stdlib BagIt writer still works)"
fi

# Verification
echo ""
echo "============================================="
echo "[*] Installation Verification"
echo "============================================="

ALL_TOOLS=(subfinder httpx nuclei ffuf feroxbuster nmap amass sqlmap trufflehog gitleaks whatweb dnsx katana naabu cdncheck interactsh-client gau dalfox subzy gowitness waybackurls anew qsreplace assetfinder arjun gf asnmap mapcidr alterx uro Gxss tlsx shuffledns fingerprintx jsluice massdns nomore403)
INSTALLED=0
MISSING=0

for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool: $(which "$tool")"
        ((++INSTALLED))
    else
        log_err "$tool: NOT FOUND"
        ((++MISSING))
    fi
done

if [ -f "$REPO_TOOLS_DIR/drupalgeddon2.py" ]; then
    log_ok "drupalgeddon2.py: $REPO_TOOLS_DIR/drupalgeddon2.py"
    ((++INSTALLED))
else
    log_err "drupalgeddon2.py: NOT FOUND"
    ((++MISSING))
fi

for local_tool in "LinkFinder/linkfinder.py" "SecretFinder/SecretFinder.py" "XSStrike/xsstrike.py"; do
    tool_name="${local_tool%%/*}"
    if [ -d "$REPO_TOOLS_DIR/$tool_name" ]; then
        log_ok "$tool_name: $REPO_TOOLS_DIR/$tool_name/"
        ((++INSTALLED))
    else
        log_err "$tool_name: NOT FOUND in $REPO_TOOLS_DIR/"
        ((++MISSING))
    fi
done

# Optional: Endava CATS for OpenAPI negative fuzz (cats_audit.py).
# Not required for core VAPT; install separately when needed
# (brew tap endava/tap && brew install cats, or releases binary/JAR).
# See docs/cats.md
if command -v cats >/dev/null 2>&1; then
    log_ok "Endava CATS on PATH: $(command -v cats)"
else
    log_warn "Endava CATS (cats) not installed — optional for --cats / cats_audit.py"
fi

# Optional: MITRE SAF CLI for SARIF→HDF→ASFF export (saf_export.py).
# Not required for core VAPT; install separately when you need HDF/ASFF
# (NPM package @mitre/saf, or Homebrew mitre/saf/saf-cli). See docs/saf-export.md
if command -v saf >/dev/null 2>&1; then
    log_ok "MITRE SAF CLI on PATH: $(command -v saf)"
else
    log_warn "MITRE SAF CLI (saf) not installed — optional for --saf-hdf/--saf-asff"
fi

READINESS_FAILED=0
if "$VENV_DIR/bin/python" "$SCRIPT_DIR/environment_readiness.py"; then
    log_ok "Environment readiness checks passed"
else
    log_err "Environment readiness checks failed"
    READINESS_FAILED=1
fi

echo ""
echo "============================================="
echo "  Installed: $INSTALLED / $((${#ALL_TOOLS[@]} + 4)) tools"
[ "$MISSING" -gt 0 ] && echo "  Missing: $MISSING (check errors above)"
echo "============================================="

if [ "$MISSING" -gt 0 ] || [ "$READINESS_FAILED" -ne 0 ]; then
    log_err "Installation is incomplete; required tools or dependencies are not ready"
    exit 1
fi

log_ok "Installation complete and ready"

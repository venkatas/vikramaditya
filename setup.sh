#!/bin/bash
# =============================================================================
# OBSIDIAN — Tool Installer
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

echo "============================================="
echo "  OBSIDIAN — Tool Installer"
echo "============================================="

# Check for Homebrew
if ! command -v brew &>/dev/null; then
    log_warn "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

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

# Tools to install via pip
echo ""
echo "[*] Installing Python tools..."
PIP_TOOLS=("arjun" "httpx[cli]")
for pkg in "${PIP_TOOLS[@]}"; do
    name="${pkg%%[*}"   # strip extras like [cli]
    if command -v "$name" &>/dev/null || python3 -c "import ${name//-/_}" &>/dev/null 2>&1; then
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

# Install gf patterns (tomnomnom's pattern pack)
GF_PATTERNS_DIR="$HOME/.gf"
if [ -d "$GF_PATTERNS_DIR" ] && [ "$(ls -A "$GF_PATTERNS_DIR" 2>/dev/null | wc -l)" -gt 2 ]; then
    log_ok "gf patterns already installed ($GF_PATTERNS_DIR)"
else
    echo "    Installing gf patterns..."
    mkdir -p "$GF_PATTERNS_DIR"
    # tomnomnom's own patterns
    GOPATH_BIN="${GOPATH:-$HOME/go}"
    [ -d "$GOPATH_BIN/pkg/mod/github.com/tomnomnom/gf"* ] && \
        cp -r "$GOPATH_BIN/pkg/mod/github.com/tomnomnom/gf"*/examples/. "$GF_PATTERNS_DIR/" 2>/dev/null || true
    # 1ndianl33t community patterns (xss, sqli, ssrf, redirect, lfi, idor, rce, debug_logic, img-traversal, interestingparams, jsvar, cors)
    if git clone --quiet https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null; then
        cp /tmp/gf-patterns/*.json "$GF_PATTERNS_DIR/" 2>/dev/null || true
        rm -rf /tmp/gf-patterns
        log_ok "gf patterns installed to $GF_PATTERNS_DIR/"
    else
        log_warn "gf community patterns failed — add manually: https://github.com/1ndianl33t/Gf-Patterns"
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

# Update nuclei templates
echo ""
echo "[*] Updating nuclei templates..."
if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null || true
    log_ok "Nuclei templates updated"
fi

# Ensure Go bin is in PATH
GOPATH="${GOPATH:-$HOME/go}"
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    log_warn "Add Go bin to your PATH:"
    echo "    export PATH=\$PATH:$GOPATH/bin"
    echo "    # Add to ~/.zshrc for persistence"
fi

# Verification
echo ""
echo "============================================="
echo "[*] Installation Verification"
echo "============================================="

ALL_TOOLS=(subfinder httpx nuclei ffuf nmap amass sqlmap trufflehog gitleaks whatweb dnsx katana naabu cdncheck interactsh-client gau dalfox subzy gowitness waybackurls anew qsreplace assetfinder arjun gf)
INSTALLED=0
MISSING=0

for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool: $(which "$tool")"
        ((INSTALLED++))
    else
        log_err "$tool: NOT FOUND"
        ((MISSING++))
    fi
done

if [ -f "$REPO_TOOLS_DIR/drupalgeddon2.py" ]; then
    log_ok "drupalgeddon2.py: $REPO_TOOLS_DIR/drupalgeddon2.py"
    ((INSTALLED++))
else
    log_err "drupalgeddon2.py: NOT FOUND"
    ((MISSING++))
fi

for local_tool in "LinkFinder/linkfinder.py" "SecretFinder/SecretFinder.py" "XSStrike/xsstrike.py"; do
    tool_name="${local_tool%%/*}"
    if [ -d "$REPO_TOOLS_DIR/$tool_name" ]; then
        log_ok "$tool_name: $REPO_TOOLS_DIR/$tool_name/"
        ((INSTALLED++))
    else
        log_err "$tool_name: NOT FOUND in $REPO_TOOLS_DIR/"
        ((MISSING++))
    fi
done

echo ""
echo "============================================="
echo "  Installed: $INSTALLED / $((${#ALL_TOOLS[@]} + 1)) tools"
[ "$MISSING" -gt 0 ] && echo "  Missing: $MISSING (check errors above)"
echo "============================================="

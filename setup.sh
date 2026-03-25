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

# Repo-local helper tools
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

ALL_TOOLS=(subfinder httpx nuclei ffuf nmap amass sqlmap trufflehog gitleaks whatweb dnsx katana naabu cdncheck interactsh-client gau dalfox subzy gowitness waybackurls anew qsreplace assetfinder arjun)
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

echo ""
echo "============================================="
echo "  Installed: $INSTALLED / $((${#ALL_TOOLS[@]} + 1)) tools"
[ "$MISSING" -gt 0 ] && echo "  Missing: $MISSING (check errors above)"
echo "============================================="

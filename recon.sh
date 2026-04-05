#!/bin/bash
# =============================================================================
# Enhanced Recon Engine v2 — Batch-Aware with Tech CVE Prioritization
#
# Usage: ./recon_engine.sh <target-domain> [--quick]
#
# What's new vs v1:
#   • Subdomains processed in batches of 10 — never overwhelms tools
#   • httpx tech-detect runs per batch; results fed to tech_priority.py
#   • Outputs a CVE-prioritized host list for the scanner
#   • amass timeout raised to 10 minutes (600s)
#   • Added: katana crawl, dnsx resolution, assetfinder, waybackurls
#   • Added: whatweb fingerprinting on high-priority hosts
#   • Added: subzy subdomain takeover pre-check
#   • Added: trufflehog / gitleaks pass on JS files
# =============================================================================

set -uo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[$(ts)] [+]${NC} $1"; }
log_err()   { echo -e "${RED}[$(ts)] [-]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[$(ts)] [!]${NC} $1"; }
log_info()  { echo -e "${CYAN}[$(ts)] [*]${NC} $1"; }
log_step()  { echo -e "    ${CYAN}[$(ts)] [>]${NC} $1"; }
log_done()  { echo -e "    ${GREEN}[$(ts)] [✓]${NC} $1"; }
log_crit()  { echo -e "    ${MAGENTA}${BOLD}[$(ts)] [CRITICAL]${NC} $1"; }
ts()        { date '+%Y-%m-%d %H:%M:%S'; }

# ── Config ────────────────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 <target-domain> [--quick] [--resume]" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    usage
    exit 1
fi

QUICK_MODE=""
RESUME_MODE=""
for arg in "${@:2}"; do
    case "$arg" in
        --quick)  QUICK_MODE="--quick" ;;
        --resume) RESUME_MODE="1" ;;
    esac
done
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$SCRIPT_DIR"
RECON_DIR="${RECON_OUT_DIR:-$BASE_DIR/recon/$TARGET}"
SESSION_ID="${RECON_SESSION_ID:-}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Prefer ProjectDiscovery httpx (~/go/bin) over Python httpx (/opt/homebrew/bin)
export PATH="$HOME/go/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

# macOS compatibility: 'timeout' is a Linux coreutils command.
# On macOS use gtimeout (brew install coreutils) or fall back to a no-op wrapper.
if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        timeout() { gtimeout "$@"; }
        export -f timeout
    else
        # No timeout available — define a passthrough so commands still run
        timeout() { shift; "$@"; }
        export -f timeout
    fi
fi

BATCH_SIZE="${BATCH_SIZE:-5}"
THREADS="${THREADS_OVERRIDE:-50}"
RATE_LIMIT="${RATE_LIMIT_OVERRIDE:-150}"
SCOPE_LOCK="${SCOPE_LOCK:-0}"
MAX_URLS="${MAX_URLS:-100}"

# ── Detect target type (passed from hunt.py or auto-detected) ─────────────────
_detect_target_type() {
    local t="$1"
    if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then echo "cidr"
    elif [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];        then echo "ip"
    else echo "domain"; fi
}
TARGET_TYPE="${TARGET_TYPE:-$(_detect_target_type "$TARGET")}"

# For IP/CIDR: always scope-lock (no subdomain enum needed)
if [ "$TARGET_TYPE" = "ip" ] || [ "$TARGET_TYPE" = "cidr" ]; then
    SCOPE_LOCK=1
fi
AMASS_TIMEOUT=600      # 10 minutes (was 5 min)
CURL_TIMEOUT=10        # per request
HTTP_PROBE_TIMEOUT=5   # reduced: 5s per-host timeout (was 10) — avoids macOS TCP hang

mkdir -p "$RECON_DIR"/{subdomains,live,ports,urls,js,dirs,params,priority,exposure,screenshots,api_specs,cors,secrets,vhosts}

# ── Safety net: merge partial subdomain results on early exit ────────────────
# If the watchdog or timeout kills this script mid-Phase-1, the merge step at
# the end of Phase 1 never runs and all.txt is empty → 0 live hosts.
# This trap ensures any partial results are merged before exit.
_emergency_merge_subs() {
    if [ ! -s "$RECON_DIR/subdomains/all.txt" ] && \
       ls "$RECON_DIR/subdomains/"*.txt &>/dev/null; then
        cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/^\*\.//' \
            | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" \
            | sort -u > "$RECON_DIR/subdomains/all.txt" 2>/dev/null || true
        _count=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
        if [ "${_count:-0}" -gt 0 ]; then
            echo -e "${YELLOW}[$(ts)] [!]${NC} Emergency merge: ${_count} subdomains saved to all.txt"
        fi
    fi
}
trap _emergency_merge_subs EXIT

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  Recon Engine v2 — $TARGET${NC}"
echo -e "  Output  : $RECON_DIR/"
[ -n "$SESSION_ID" ] && echo -e "  Session : $SESSION_ID"
echo -e "  Mode    : $([ "$QUICK_MODE" = "--quick" ] && echo "Quick" || echo "Full")$([ -n "$RESUME_MODE" ] && echo " + RESUME (skip completed phases)" || true)"
echo -e "  Batch   : $BATCH_SIZE subdomains per httpx probe"
echo -e "  Threads : $THREADS | Rate: $RATE_LIMIT rps"
echo -e "  Started : $(date)"
echo -e "${BOLD}============================================================${NC}"
echo ""

# ── Helpers ───────────────────────────────────────────────────────────────────
file_lines() {
    local path="${1:-}"
    [ -n "$path" ] && [ -f "$path" ] || { echo 0; return; }
    wc -l < "$path" 2>/dev/null | tr -d ' ' || echo 0
}
tool_ok()    { command -v "$1" &>/dev/null; }
# In resume mode: returns 0 (true) if the given file exists and is non-empty → skip phase
phase_done() {
    local f="$1"
    [ -n "$RESUME_MODE" ] && [ -s "$f" ] && \
        log_warn "RESUME: skipping — $(basename "$f") already has $(file_lines "$f") lines" && \
        return 0
    return 1
}

refresh_priority() {
    local context="${1:-latest recon artifacts}"
    local priority_script="$SCRIPT_DIR/tech_priority.py"

    if [ ! -f "$priority_script" ] || [ ! -s "$RECON_DIR/live/httpx_full.txt" ]; then
        return 1
    fi

    log_step "Scoring technologies against CVE database ($context)..."
    python3 "$priority_script" \
        "$RECON_DIR/live/httpx_full.txt" \
        "$RECON_DIR/priority/prioritized_hosts.txt" 2>/dev/null || true


    log_done "Priority files: $RECON_DIR/priority/"
    [ -s "$RECON_DIR/priority/critical_hosts.txt" ] && \
        log_crit "$(file_lines "$RECON_DIR/priority/critical_hosts.txt") CRITICAL CVE-risk hosts"
    [ -s "$RECON_DIR/priority/high_hosts.txt" ] && \
        log_warn "$(file_lines "$RECON_DIR/priority/high_hosts.txt") HIGH CVE-risk hosts"
    [ -f "$RECON_DIR/priority/attack_surface.md" ] && \
        log_done "Attack surface report: $RECON_DIR/priority/attack_surface.md"
    return 0
}

ASYNC_PIDS=()
ASYNC_NAMES=()
ASYNC_LOGS=()

start_async_phase() {
    local name="$1"
    local log_file="$2"
    shift 2
    mkdir -p "$(dirname "$log_file")"
    : > "$log_file"
    log_step "Backgrounding $name"
    (
        "$@"
    ) >"$log_file" 2>&1 &
    ASYNC_PIDS+=("$!")
    ASYNC_NAMES+=("$name")
    ASYNC_LOGS+=("$log_file")
}

wait_async_phases() {
    local idx pid name log_file rc
    for idx in "${!ASYNC_PIDS[@]}"; do
        pid="${ASYNC_PIDS[$idx]}"
        name="${ASYNC_NAMES[$idx]}"
        log_file="${ASYNC_LOGS[$idx]}"
        wait "$pid"
        rc=$?
        [ -s "$log_file" ] && cat "$log_file"
        if [ "$rc" -eq 0 ]; then
            log_done "$name finished"
        else
            log_warn "$name exited with rc=$rc"
        fi
    done
    ASYNC_PIDS=()
    ASYNC_NAMES=()
    ASYNC_LOGS=()
}

run_phase5_port_scanning() {
    echo ""
    log_info "Phase 5: Port Scanning"
    if phase_done "$RECON_DIR/ports/nmap_results.txt"; then
        return 0
    fi

    if tool_ok nmap; then
        if tool_ok naabu; then
            log_step "naabu top-1000 on $TARGET..."
            naabu -host "$TARGET" -top-ports 1000 -silent \
                -o "$RECON_DIR/ports/naabu_results.txt" 2>/dev/null || true
            awk -F: 'NF>1 {print $2"/open"}' "$RECON_DIR/ports/naabu_results.txt" \
                | sort -u > "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || true

            if [ -s "$RECON_DIR/ports/open_ports.txt" ]; then
                PORT_CSV="$(cut -d/ -f1 "$RECON_DIR/ports/open_ports.txt" | paste -sd, -)"
                log_step "nmap service fingerprinting on naabu-discovered ports: ${PORT_CSV:-none}"
                nmap -sV -p "$PORT_CSV" -T4 --open "$TARGET" \
                    -oN "$RECON_DIR/ports/nmap_results.txt" \
                    -oG "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null || true
            else
                log_warn "naabu found no open ports — falling back to nmap top-1000"
                nmap -sV --top-ports 1000 -T4 --open "$TARGET" \
                    -oN "$RECON_DIR/ports/nmap_results.txt" \
                    -oG "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null || true
            fi
        else
            log_step "nmap top-1000 on $TARGET..."
            nmap -sV --top-ports 1000 -T4 --open "$TARGET" \
                -oN "$RECON_DIR/ports/nmap_results.txt" \
                -oG "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null || true
        fi

        grep "open" "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null \
            | sed -nE 's/.*[^0-9]([0-9]+)\/open.*/\1\/open/p' \
            | sort -u > "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || true
        log_done "Open ports: $(file_lines "$RECON_DIR/ports/open_ports.txt")"

        if [ -s "$RECON_DIR/priority/critical_hosts.txt" ]; then
            log_step "nmap non-standard ports on CRITICAL hosts..."
            while IFS= read -r host; do
                HOSTNAME=$(echo "$host" | sed 's|https\?://||;s|[/:].*||')
                nmap -sV -p 8080,8443,8888,9090,9200,5601,6379,27017,3306,5432,2375,2376 \
                    --open -T4 "$HOSTNAME" \
                    -oN "$RECON_DIR/ports/nmap_critical_${HOSTNAME}.txt" 2>/dev/null || true
            done < <(head -5 "$RECON_DIR/priority/critical_hosts.txt")
        fi
    else
        log_warn "nmap not installed — skipping"
    fi
}

run_phase11_takeover_check() {
    local takeover_done_file="$RECON_DIR/live/takeover_check.done"
    local ran_check=0

    echo ""
    log_info "Phase 11: Subdomain Takeover Pre-Check"
    if phase_done "$takeover_done_file"; then
        return 0
    fi

    if tool_ok subzy && [ -s "$RECON_DIR/subdomains/all.txt" ]; then
        ran_check=1
        log_step "subzy takeover check..."
        subzy run --hosts "$RECON_DIR/subdomains/all.txt" \
            --output "$RECON_DIR/live/subzy_takeovers.txt" \
            --concurrency "$THREADS" \
            --timeout 10 2>/dev/null || true
        [ -s "$RECON_DIR/live/subzy_takeovers.txt" ] && \
            log_warn "Potential takeovers: $(file_lines "$RECON_DIR/live/subzy_takeovers.txt")"
    elif tool_ok nuclei && [ -s "$RECON_DIR/live/urls.txt" ]; then
        ran_check=1
        log_step "nuclei takeover templates..."
        nuclei -l "$RECON_DIR/live/urls.txt" \
            -tags takeover -silent \
            -rate-limit "$RATE_LIMIT" \
            -o "$RECON_DIR/live/nuclei_takeovers.txt" 2>/dev/null || true
        [ -s "$RECON_DIR/live/nuclei_takeovers.txt" ] && \
            log_warn "Takeover candidates: $(file_lines "$RECON_DIR/live/nuclei_takeovers.txt")"
    else
        log_warn "subzy / nuclei not installed — skipping takeover check"
    fi

    [ "$ran_check" -eq 1 ] && date '+%Y-%m-%d %H:%M:%S' > "$takeover_done_file"
}

# ============================================================
# Phase 1: Subdomain Enumeration
# ============================================================
log_info "Phase 1: Subdomain Enumeration"
if phase_done "$RECON_DIR/subdomains/all.txt"; then true; else

# ── Scope-lock: skip all enum tools, test only the exact given target ─────────
if [ "$SCOPE_LOCK" = "1" ]; then
    if [ "$TARGET_TYPE" = "cidr" ]; then
        log_info "CIDR target — running ping sweep to discover live hosts"
        if tool_ok nmap; then
            nmap -sn "$TARGET" -oG - 2>/dev/null \
                | awk '/Up$/{print $2}' \
                > "$RECON_DIR/subdomains/all.txt" || true
            LIVE_CIDR=$(file_lines "$RECON_DIR/subdomains/all.txt")
            [ "$LIVE_CIDR" -eq 0 ] && echo "$TARGET" > "$RECON_DIR/subdomains/all.txt"
            log_ok "CIDR sweep: $(file_lines "$RECON_DIR/subdomains/all.txt") live host(s)"
        else
            log_warn "nmap not found — writing CIDR as single target"
            echo "$TARGET" > "$RECON_DIR/subdomains/all.txt"
        fi
    else
        log_warn "SCOPE_LOCK active — skipping subdomain enumeration"
        log_step "Scope restricted to: $TARGET only"
        echo "$TARGET" > "$RECON_DIR/subdomains/all.txt"
        log_ok "Scope-locked: 1 target ($TARGET)"
    fi

else  # normal subdomain enum

# subfinder — passive, fast
# Uses CHAOS_API_KEY env var if set (ProjectDiscovery chaos dataset — massive coverage boost)
# Optional: set VirusTotal/SecurityTrails/Censys/Shodan keys in ~/.config/subfinder/provider-config.yaml
if tool_ok subfinder; then
    log_step "subfinder..."
    SUBFINDER_CHAOS_FLAG=""
    if [ -n "${CHAOS_API_KEY:-}" ]; then
        # chaos provider uses the key via provider-config.yaml, but we can also
        # inject it inline so no config file is needed
        SUBFINDER_CHAOS_FLAG="-provider chaos"
        # Write a temp provider config with the chaos key if config doesn't have it
        _chaos_config="$HOME/.config/subfinder/provider-config.yaml"
        if ! grep -q "^chaos:" "$_chaos_config" 2>/dev/null; then
            mkdir -p "$(dirname "$_chaos_config")"
            printf "chaos:\n  - %s\n" "$CHAOS_API_KEY" >> "$_chaos_config"
            log_step "CHAOS_API_KEY injected into subfinder config"
        fi
    fi
    subfinder -d "$TARGET" -silent -all $SUBFINDER_CHAOS_FLAG \
        -o "$RECON_DIR/subdomains/subfinder.txt" 2>/dev/null || true
    log_done "subfinder: $(file_lines "$RECON_DIR/subdomains/subfinder.txt") subdomains"
else
    log_warn "subfinder not installed"
fi

# assetfinder — fast passive (90s timeout — hangs indefinitely on slow DNS without it)
if tool_ok assetfinder; then
    log_step "assetfinder..."
    timeout 90 assetfinder --subs-only "$TARGET" \
        > "$RECON_DIR/subdomains/assetfinder.txt" 2>/dev/null || true
    log_done "assetfinder: $(file_lines "$RECON_DIR/subdomains/assetfinder.txt") subdomains"
else
    log_warn "assetfinder not installed"
fi

# amass — deeper passive (10 min timeout)
if tool_ok amass && [ "$QUICK_MODE" != "--quick" ]; then
    log_step "amass passive (timeout: ${AMASS_TIMEOUT}s = 10 min)..."
    timeout "$AMASS_TIMEOUT" amass enum -passive -d "$TARGET" \
        -o "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || true
    [ ! -f "$RECON_DIR/subdomains/amass.txt" ] && touch "$RECON_DIR/subdomains/amass.txt"
    log_done "amass: $(file_lines "$RECON_DIR/subdomains/amass.txt") subdomains"
else
    [ "$QUICK_MODE" = "--quick" ] && log_warn "amass skipped (quick mode)"
fi

# crt.sh — certificate transparency
log_step "crt.sh..."
curl -s --max-time 30 "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for e in data:
        for n in e.get('name_value','').split('\n'):
            n = n.strip().lower().lstrip('*.')
            if n and '.' in n:
                names.add(n)
    [print(n) for n in sorted(names)]
except: pass
" > "$RECON_DIR/subdomains/crtsh.txt" 2>/dev/null || true
log_done "crt.sh: $(file_lines "$RECON_DIR/subdomains/crtsh.txt") subdomains"

# Wayback Machine subdomains
log_step "Wayback Machine subdomains..."
curl -s --max-time 30 \
    "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" \
    2>/dev/null \
    | sed -nE "s|.*://([a-zA-Z0-9._-]+\.$TARGET).*|\1|p" \
    | sort -u > "$RECON_DIR/subdomains/wayback_subs.txt" 2>/dev/null || true
log_done "wayback subs: $(file_lines "$RECON_DIR/subdomains/wayback_subs.txt") subdomains"

# AlienVault OTX
log_step "AlienVault OTX..."
curl -s --max-time 20 \
    "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" \
    2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for r in data.get('passive_dns', []):
        h = r.get('hostname','').lower()
        if h and '.' in h:
            print(h)
except: pass
" | sort -u > "$RECON_DIR/subdomains/otx.txt" 2>/dev/null || true
log_done "OTX: $(file_lines "$RECON_DIR/subdomains/otx.txt") subdomains"

# HackerTarget
log_step "HackerTarget API..."
curl -s --max-time 20 \
    "https://api.hackertarget.com/hostsearch/?q=$TARGET" \
    2>/dev/null | cut -d',' -f1 | grep -v "^error\|^API" \
    > "$RECON_DIR/subdomains/hackertarget.txt" 2>/dev/null || true
log_done "hackertarget: $(file_lines "$RECON_DIR/subdomains/hackertarget.txt") subdomains"

# asnmap — enumerate IP ranges for the target org (ASN → CIDR → IPs)
if tool_ok asnmap && [ "$QUICK_MODE" != "--quick" ]; then
    log_step "asnmap (ASN → IP range enumeration)..."
    mkdir -p "$RECON_DIR/asn"
    asnmap -d "$TARGET" -silent -json \
        > "$RECON_DIR/asn/asnmap.json" 2>/dev/null || true
    # Extract CIDRs and expand to IPs if mapcidr is available
    if tool_ok mapcidr && [ -s "$RECON_DIR/asn/asnmap.json" ]; then
        python3 -c "
import json, sys
try:
    for line in open('$RECON_DIR/asn/asnmap.json'):
        obj = json.loads(line.strip())
        for cidr in obj.get('cidr', []):
            print(cidr)
except: pass
" 2>/dev/null | mapcidr -silent > "$RECON_DIR/asn/ip_ranges.txt" 2>/dev/null || true
        log_done "asnmap: $(file_lines "$RECON_DIR/asn/ip_ranges.txt") IPs in org range"
    else
        log_done "asnmap: $RECON_DIR/asn/asnmap.json (mapcidr not available for expansion)"
    fi
fi

# ── Merge & deduplicate ───────────────────────────────────────────────────────
cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/^\*\.//' \
    | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" \
    | sort -u > "$RECON_DIR/subdomains/all.txt"

TOTAL_SUBS=$(file_lines "$RECON_DIR/subdomains/all.txt")
log_ok "Total unique subdomains (pre-permutation): $TOTAL_SUBS"

# alterx — permutation-based subdomain generation (BugBounty-Recon-Methodology)
# Generates variations like: dev-api, api-dev, api2, api-internal etc.
# Often finds assets that passive sources miss entirely.
if tool_ok alterx && [ "$QUICK_MODE" != "--quick" ] && [ "$TOTAL_SUBS" -gt 0 ]; then
    log_step "alterx (subdomain permutation generation)..."
    alterx -l "$RECON_DIR/subdomains/all.txt" -silent \
        > "$RECON_DIR/subdomains/alterx.txt" 2>/dev/null || true
    ALTERX_COUNT=$(file_lines "$RECON_DIR/subdomains/alterx.txt")
    log_done "alterx: $ALTERX_COUNT permutations generated"
    # Merge permutations back into all.txt and re-resolve in Phase 2
    if [ "$ALTERX_COUNT" -gt 0 ]; then
        cat "$RECON_DIR/subdomains/all.txt" "$RECON_DIR/subdomains/alterx.txt" \
            | sort -u > "$RECON_DIR/subdomains/all_with_permutations.txt"
        cp "$RECON_DIR/subdomains/all_with_permutations.txt" "$RECON_DIR/subdomains/all.txt"
        TOTAL_SUBS=$(file_lines "$RECON_DIR/subdomains/all.txt")
        log_ok "Total unique subdomains (with permutations): $TOTAL_SUBS"
    fi
fi

fi  # end SCOPE_LOCK else block
fi  # end Phase 1 resume skip

# ============================================================
# Phase 2: DNS Resolution — filter to only resolvable hosts
# ============================================================
echo ""
log_info "Phase 2: DNS Resolution"
if phase_done "$RECON_DIR/subdomains/resolved.txt"; then true; else

if tool_ok dnsx; then
    log_step "Resolving subdomains with dnsx..."
    dnsx -l "$RECON_DIR/subdomains/all.txt" \
        -silent \
        -threads "$THREADS" \
        -o "$RECON_DIR/subdomains/resolved.txt" 2>/dev/null || true
    log_done "Resolved: $(file_lines "$RECON_DIR/subdomains/resolved.txt") hosts"
else
    log_warn "dnsx not installed — using all subdomains as-is"
    cp "$RECON_DIR/subdomains/all.txt" "$RECON_DIR/subdomains/resolved.txt"
fi

fi  # end Phase 2 resume skip

RESOLVED_FILE="$RECON_DIR/subdomains/resolved.txt"
RESOLVED_COUNT=$(file_lines "$RESOLVED_FILE")

# ── Large-target adaptive tuning ─────────────────────────────────────────────
# For targets with many resolved subdomains, probing all of them serially with
# BATCH_SIZE=5 causes thousands of httpx invocations and always hits the recon
# timeout before httpx_full.txt is populated.  Scale up automatically.
LARGE_TARGET=0
HTTPX_TARGET_FILE="$RESOLVED_FILE"   # default: probe everything

if [ "$RESOLVED_COUNT" -gt 5000 ]; then
    LARGE_TARGET=1
    BATCH_SIZE=100
    log_warn "Large target: $RESOLVED_COUNT resolved hosts — switching to BATCH_SIZE=100"
    log_step "Building priority-filtered probe list (keyword + cap 1500)..."
    PRIORITY_PROBE="$RECON_DIR/subdomains/priority_probe.txt"
    # Step 1: keyword-priority hosts first
    grep -iE "(admin|api|portal|login|vpn|mail|dev|staging|test|beta|upload|backup|legacy|ftp|app|dashboard|internal|intranet|monitor|jenkins|grafana|kibana|jira|proxy|gateway|auth|oauth|token|swagger|openapi|console|manage|corp|secure|access|secret|config|db|database|git|ci|cd|build|deploy|infra|cloud|prod|uat|qa|preprod)" \
        "$RESOLVED_FILE" 2>/dev/null | head -1000 > "$PRIORITY_PROBE" || true
    # Step 2: fill up to 1500 with remaining hosts not already selected
    grep -vxFf "$PRIORITY_PROBE" "$RESOLVED_FILE" 2>/dev/null | head -500 >> "$PRIORITY_PROBE" || true
    awk '!seen[$0]++' "$PRIORITY_PROBE" > "${PRIORITY_PROBE}.dedup" && mv "${PRIORITY_PROBE}.dedup" "$PRIORITY_PROBE"
    PRIORITY_COUNT=$(file_lines "$PRIORITY_PROBE")
    log_step "Priority probe list: $PRIORITY_COUNT hosts (from $RESOLVED_COUNT resolved)"
    HTTPX_TARGET_FILE="$PRIORITY_PROBE"
    RESOLVED_COUNT="$PRIORITY_COUNT"

elif [ "$RESOLVED_COUNT" -gt 1000 ]; then
    LARGE_TARGET=1
    BATCH_SIZE=50
    log_warn "Medium-large target: $RESOLVED_COUNT resolved hosts — switching to BATCH_SIZE=50"
fi

# ============================================================
# Phase 3: HTTP Probing in Batches of BATCH_SIZE
# ============================================================
echo ""
log_info "Phase 3: HTTP Probing in batches of $BATCH_SIZE (total: $RESOLVED_COUNT subdomains)"
if phase_done "$RECON_DIR/live/httpx_full.txt"; then true; else

if ! tool_ok httpx; then
    log_warn "httpx not installed — skipping HTTP probing"
else
    # Clear previous output
    : > "$RECON_DIR/live/httpx_full.txt"
    : > "$RECON_DIR/live/httpx_all_tech.txt"

    BATCH_NUM=0
    TOTAL_BATCHES=$(( (RESOLVED_COUNT + BATCH_SIZE - 1) / BATCH_SIZE ))

    # Split resolved file into batches and process each
    BATCH_NUM=0
    split -l "$BATCH_SIZE" "$HTTPX_TARGET_FILE" "$RECON_DIR/subdomains/batch_"

    # Max seconds a single batch is allowed to run before we skip it
    # × 2 multiplier + 60s buffer accommodates slow gov.in-class servers
    BATCH_WATCHDOG=$(( HTTP_PROBE_TIMEOUT * BATCH_SIZE * 2 + 60 ))

    for BATCH_FILE in "$RECON_DIR/subdomains/batch_"*; do
        [ -f "$BATCH_FILE" ] || continue
        BATCH_NUM=$((BATCH_NUM + 1))
        BATCH_NAME=$(basename "$BATCH_FILE")

        BATCH_HOSTS=$(file_lines "$BATCH_FILE")
        LIVE_SO_FAR=$(file_lines "$RECON_DIR/live/httpx_full.txt")
        BATCH_START=$(date +%s)
        log_step "Batch $BATCH_NUM/$TOTAL_BATCHES — probing $BATCH_HOSTS hosts... (live so far: $LIVE_SO_FAR | $(date '+%H:%M:%S'))"

        # httpx: tech-detect skipped on first fast pass; added via separate run below
        # -no-fallback prevents HTTPS→HTTP retry loops that cause hangs
        # timeout(1) is a hard OS-level watchdog — kills httpx if it exceeds BATCH_WATCHDOG
        timeout "$BATCH_WATCHDOG" \
        httpx -l "$BATCH_FILE" \
            -silent \
            -status-code \
            -title \
            -tech-detect \
            -content-length \
            -ip \
            -no-fallback \
            -no-color \
            -threads "$THREADS" \
            -rate-limit "$RATE_LIMIT" \
            -timeout "$HTTP_PROBE_TIMEOUT" \
            2>/dev/null >> "$RECON_DIR/live/httpx_full.txt" || true

        BATCH_END=$(date +%s)
        BATCH_ELAPSED=$(( BATCH_END - BATCH_START ))
        NEW_LIVE=$(file_lines "$RECON_DIR/live/httpx_full.txt")
        BATCH_FOUND=$(( NEW_LIVE - LIVE_SO_FAR ))
        log_step "  → Batch $BATCH_NUM done in ${BATCH_ELAPSED}s | found $BATCH_FOUND live hosts this batch | total live: $NEW_LIVE"

        rm -f "$BATCH_FILE"
    done

    LIVE_COUNT=$(file_lines "$RECON_DIR/live/httpx_full.txt")

    if [ "$LIVE_COUNT" -eq 0 ] && [ "$RESOLVED_COUNT" -gt 0 ] && { [ "${SCOPE_LOCK:-0}" = "1" ] || [ "$RESOLVED_COUNT" -le 50 ]; }; then
        SCHEME_RETRY_FILE="$RECON_DIR/live/.scheme_retry.txt"
        awk '{print "https://" $0 ORS "http://" $0}' "$HTTPX_TARGET_FILE" \
            | awk '!seen[$0]++' > "$SCHEME_RETRY_FILE" 2>/dev/null || true
        if [ -s "$SCHEME_RETRY_FILE" ]; then
            RETRY_COUNT=$(file_lines "$SCHEME_RETRY_FILE")
            log_step "No live hosts on bare-host probe — retrying explicit http:// and https:// URLs ($RETRY_COUNT targets)..."
            timeout "$BATCH_WATCHDOG" \
            httpx -l "$SCHEME_RETRY_FILE" \
                -silent \
                -status-code \
                -title \
                -tech-detect \
                -content-length \
                -no-fallback \
                -no-color \
                -threads "$THREADS" \
                -rate-limit "$RATE_LIMIT" \
                -timeout "$HTTP_PROBE_TIMEOUT" \
                2>/dev/null >> "$RECON_DIR/live/httpx_full.txt" || true
            sort -u "$RECON_DIR/live/httpx_full.txt" -o "$RECON_DIR/live/httpx_full.txt" 2>/dev/null || true
            LIVE_COUNT=$(file_lines "$RECON_DIR/live/httpx_full.txt")
        fi
        rm -f "$SCHEME_RETRY_FILE"
    fi

    log_ok "HTTP probing complete — $LIVE_COUNT live hosts found"

    # Extract clean URL list
    awk '{print $1}' "$RECON_DIR/live/httpx_full.txt" \
        | sort -u > "$RECON_DIR/live/urls.txt" 2>/dev/null || true

    # Separate by status
    grep '\[200\]'   "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_200.txt"  2>/dev/null || true
    grep '\[30[123]\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || true
    grep '\[403\]'   "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_403.txt"  2>/dev/null || true
    grep '\[401\]'   "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_401.txt"  2>/dev/null || true
    grep '\[429\]'   "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_429.txt"  2>/dev/null || true

    # Extract unique IPs from httpx output (needed for vhost discovery Phase 7.5)
    # httpx -ip outputs IP as last bracketed field: https://host [200] [...] [1.2.3.4]
    grep -oE '\[([0-9]{1,3}\.){3}[0-9]{1,3}\]' "$RECON_DIR/live/httpx_full.txt" \
        | tr -d '[]' | sort -u > "$RECON_DIR/live/ips.txt" 2>/dev/null || true

    log_done "200 OK:         $(file_lines "$RECON_DIR/live/status_200.txt")"
    log_done "3xx Redirect:   $(file_lines "$RECON_DIR/live/status_3xx.txt")"
    log_done "403 Forbidden:  $(file_lines "$RECON_DIR/live/status_403.txt")"
    log_done "401 Auth Req:   $(file_lines "$RECON_DIR/live/status_401.txt")"
    log_done "429 Rate Limit: $(file_lines "$RECON_DIR/live/status_429.txt")"

    RATE_429_COUNT=$(file_lines "$RECON_DIR/live/status_429.txt")
    if [ "$LIVE_COUNT" -gt 0 ] && [ "$RATE_429_COUNT" -gt 0 ]; then
        RATE_429_PCT=$(( RATE_429_COUNT * 100 / LIVE_COUNT ))
        if [ "$RATE_429_PCT" -ge 40 ]; then
            RATE_LIMIT=40
            THREADS=12
            log_warn "Adaptive throttling: 429 rate ${RATE_429_PCT}% — reducing to $RATE_LIMIT rps / $THREADS threads for later phases"
        elif [ "$RATE_429_PCT" -ge 20 ]; then
            RATE_LIMIT=75
            THREADS=20
            log_warn "Adaptive throttling: 429 rate ${RATE_429_PCT}% — reducing to $RATE_LIMIT rps / $THREADS threads for later phases"
        fi
    fi
fi
fi  # end Phase 3 resume skip

# ============================================================
# Phase 4: Tech CVE Prioritization
# ============================================================
echo ""
log_info "Phase 4: Technology CVE Prioritization"
if phase_done "$RECON_DIR/priority/prioritized_hosts.txt"; then true; else

if refresh_priority "initial httpx fingerprint pass"; then
    :
else
    log_warn "tech_priority.py not found or no live hosts — skipping CVE scoring"
    # Fall back: treat all live hosts with equal priority
    if [ -s "$RECON_DIR/live/urls.txt" ]; then
        cp "$RECON_DIR/live/urls.txt" "$RECON_DIR/priority/prioritized_hosts.txt" || true
    else
        : > "$RECON_DIR/priority/prioritized_hosts.txt"
    fi
    : > "$RECON_DIR/priority/critical_hosts.txt"
    : > "$RECON_DIR/priority/high_hosts.txt"
fi

fi  # end Phase 4 resume skip

# ── Visual recon on priority web assets (XPFarm-style quick visibility) ─────
if [ "$QUICK_MODE" != "--quick" ] && tool_ok gowitness && [ -s "$RECON_DIR/live/urls.txt" ]; then
    if phase_done "$RECON_DIR/screenshots/.done"; then true; else
        SCREEN_TARGETS="$RECON_DIR/screenshots/targets.txt"
        {
            [ -s "$RECON_DIR/priority/critical_hosts.txt" ] && head -5 "$RECON_DIR/priority/critical_hosts.txt"
            [ -s "$RECON_DIR/priority/high_hosts.txt" ] && head -5 "$RECON_DIR/priority/high_hosts.txt"
            head -5 "$RECON_DIR/live/urls.txt"
        } | sed '/^$/d' | sort -u > "$SCREEN_TARGETS"

        if [ -s "$SCREEN_TARGETS" ]; then
            log_step "gowitness screenshots on $(file_lines "$SCREEN_TARGETS") priority hosts..."
            (
                cd "$RECON_DIR/screenshots" || exit 1
                while IFS= read -r url; do
                    gowitness scan single -u "$url" --screenshot-fullpage >/dev/null 2>&1 || true
                done < "$SCREEN_TARGETS"
            )
            find "$RECON_DIR/screenshots" -type f \( -name '*.png' -o -name '*.jpg' -o -name '*.jpeg' \) \
                | sort > "$RECON_DIR/screenshots/index.txt" 2>/dev/null || true
            date '+%Y-%m-%d %H:%M:%S' > "$RECON_DIR/screenshots/.done"
            log_done "Screenshots captured: $(file_lines "$RECON_DIR/screenshots/index.txt")"
        fi
    fi
elif [ "$QUICK_MODE" != "--quick" ]; then
    log_warn "gowitness not installed — skipping screenshot recon"
fi

# ── Deep fingerprint on CRITICAL/HIGH hosts ───────────────────────────────────
if tool_ok whatweb && [ -s "$RECON_DIR/priority/critical_hosts.txt" ]; then
    log_step "whatweb deep fingerprint on CRITICAL hosts..."
    while IFS= read -r host; do
        whatweb --log-brief="$RECON_DIR/priority/whatweb_${host//[:\/]/_}.txt" \
            --no-errors -a 3 "$host" 2>/dev/null || true
    done < <(head -20 "$RECON_DIR/priority/critical_hosts.txt")
    log_done "whatweb fingerprinting done"
fi

ASYNC_LOG_DIR="$RECON_DIR/.async"
start_async_phase "Phase 5: Port Scanning" "$ASYNC_LOG_DIR/phase5_port_scanning.log" run_phase5_port_scanning
start_async_phase "Phase 11: Subdomain Takeover Pre-Check" "$ASYNC_LOG_DIR/phase11_takeover_check.log" run_phase11_takeover_check

# ============================================================
# Phase 6: URL Collection
# ============================================================
echo ""
log_info "Phase 6: URL Collection"
if phase_done "$RECON_DIR/urls/gau.txt"; then true; else

# gau — historical URLs from multiple sources
if tool_ok gau; then
    log_step "gau (historical URLs)..."
    echo "$TARGET" | gau --threads 5 \
        --o "$RECON_DIR/urls/gau.txt" 2>/dev/null || \
    echo "$TARGET" | gau > "$RECON_DIR/urls/gau.txt" 2>/dev/null || true
    log_done "gau: $(file_lines "$RECON_DIR/urls/gau.txt") URLs"
else
    log_warn "gau not installed — using Wayback fallback"
    curl -s --max-time 30 \
        "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&limit=10000" \
        > "$RECON_DIR/urls/wayback.txt" 2>/dev/null || true
    log_done "wayback: $(file_lines "$RECON_DIR/urls/wayback.txt") URLs"
fi

# waybackurls — extra coverage
if tool_ok waybackurls; then
    log_step "waybackurls..."
    echo "$TARGET" | waybackurls \
        > "$RECON_DIR/urls/waybackurls.txt" 2>/dev/null || true
    log_done "waybackurls: $(file_lines "$RECON_DIR/urls/waybackurls.txt") URLs"
fi

# waymore — richer archive coverage than gau+waybackurls combined
# Pulls from Wayback, URLScan, CommonCrawl, VirusTotal, AlienVault
if tool_ok waymore && [ "$QUICK_MODE" != "--quick" ]; then
    log_step "waymore (multi-source archive URLs)..."
    waymore -i "$TARGET" -mode U -oU "$RECON_DIR/urls/waymore.txt" \
        2>/dev/null || true
    log_done "waymore: $(file_lines "$RECON_DIR/urls/waymore.txt") URLs"
fi

# katana — active crawl on live hosts (prioritised first)
if tool_ok katana && [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "katana crawl on high-priority + sample live hosts..."

    # Crawl CRITICAL first, then sample others
    {
        [ -s "$RECON_DIR/priority/critical_hosts.txt" ] && cat "$RECON_DIR/priority/critical_hosts.txt"
        [ -s "$RECON_DIR/priority/high_hosts.txt" ] && head -10 "$RECON_DIR/priority/high_hosts.txt"
        head -20 "$RECON_DIR/live/urls.txt"
    } | sort -u | head -50 > "$RECON_DIR/urls/katana_targets.txt"

    katana -list "$RECON_DIR/urls/katana_targets.txt" \
        -d 5 -silent -jc \
        -o "$RECON_DIR/urls/katana.txt" 2>/dev/null || true
    log_done "katana: $(file_lines "$RECON_DIR/urls/katana.txt") URLs"
fi

# Merge all URLs
cat "$RECON_DIR/urls/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/urls/all.txt" || true
TOTAL_URLS_RAW=$(file_lines "$RECON_DIR/urls/all.txt")
log_ok "Total unique URLs (raw): $TOTAL_URLS_RAW"

# ── MAX_URLS cap: keep the most valuable URLs first ───────────────────────────
# Priority order: parameterised > JS > API > sensitive > remaining.
# This ensures the 100-URL default retains the highest-signal URLs for vuln
# scanning rather than randomly discarding based on sort order.
if [ "${MAX_URLS:-0}" -gt 0 ] && [ "$TOTAL_URLS_RAW" -gt "$MAX_URLS" ]; then
    log_warn "MAX_URLS=$MAX_URLS: selecting top $MAX_URLS priority URLs from $TOTAL_URLS_RAW total"
    ALL_URL_FILE="$RECON_DIR/urls/all.txt"
    TMP_CAPPED="$RECON_DIR/urls/.all_capped.txt"
    : > "$TMP_CAPPED"
    # Tier 1: parameterised URLs (highest signal for SQLi/XSS/SSRF/LFI)
    grep '?' "$ALL_URL_FILE" | head -$(( MAX_URLS / 2 )) >> "$TMP_CAPPED" 2>/dev/null || true
    # Tier 2: JS files
    grep -iE '\.js(\?|$)' "$ALL_URL_FILE" | head -$(( MAX_URLS / 5 )) >> "$TMP_CAPPED" 2>/dev/null || true
    # Tier 3: API endpoints
    grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/)' "$ALL_URL_FILE" | head -$(( MAX_URLS / 5 )) >> "$TMP_CAPPED" 2>/dev/null || true
    # Tier 4: sensitive extensions
    grep -iE '\.(env|config|bak|backup|sql|git|pem|key)(\?|$)' "$ALL_URL_FILE" | head -20 >> "$TMP_CAPPED" 2>/dev/null || true
    # Tier 5: fill remaining quota with everything else
    ALREADY=$(awk '!seen[$0]++' "$TMP_CAPPED" | wc -l | tr -d ' ')
    REMAINING=$(( MAX_URLS - ALREADY ))
    if [ "$REMAINING" -gt 0 ]; then
        grep -vxFf "$TMP_CAPPED" "$ALL_URL_FILE" 2>/dev/null | head -"$REMAINING" >> "$TMP_CAPPED" || true
    fi
    awk '!seen[$0]++' "$TMP_CAPPED" | head -"$MAX_URLS" > "$ALL_URL_FILE"
    rm -f "$TMP_CAPPED"
    log_ok "URL cap applied: $(file_lines "$ALL_URL_FILE") URLs kept (priority-ordered)"
fi

# uro — URL normalization: deduplicate semantically identical URLs before scanning
# Removes pattern noise (e.g. ?id=1, ?id=2 → ?id=GFP) so dalfox/sqlmap
# don't waste time on duplicate attack surfaces.
if tool_ok uro && [ -s "$RECON_DIR/urls/all.txt" ]; then
    log_step "uro (URL deduplication + normalization)..."
    uro < "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/all_uro.txt" 2>/dev/null || true
    URO_BEFORE=$(file_lines "$RECON_DIR/urls/all.txt")
    URO_AFTER=$(file_lines "$RECON_DIR/urls/all_uro.txt")
    if [ "$URO_AFTER" -gt 0 ]; then
        cp "$RECON_DIR/urls/all_uro.txt" "$RECON_DIR/urls/all.txt"
        log_done "uro: $URO_BEFORE → $URO_AFTER URLs (removed $((URO_BEFORE - URO_AFTER)) duplicates)"
    fi
fi

# Filter subsets
if [ -s "$RECON_DIR/urls/all.txt" ]; then
    grep '?' "$RECON_DIR/urls/all.txt" \
        > "$RECON_DIR/urls/with_params.txt" 2>/dev/null || true
    log_done "With parameters: $(file_lines "$RECON_DIR/urls/with_params.txt")"

    grep -iE '\.js(\?|$)' "$RECON_DIR/urls/all.txt" \
        > "$RECON_DIR/urls/js_files.txt" 2>/dev/null || true
    log_done "JS files: $(file_lines "$RECON_DIR/urls/js_files.txt")"

    grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/|/gql)' "$RECON_DIR/urls/all.txt" \
        > "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || true
    log_done "API endpoints: $(file_lines "$RECON_DIR/urls/api_endpoints.txt")"

    grep -iE '\.(env|config|xml|json|yaml|yml|bak|backup|old|orig|sql|db|log|txt|conf|ini|htaccess|htpasswd|git|pem|key|pfx|p12|ovpn)(\?|$)' \
        "$RECON_DIR/urls/all.txt" \
        > "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || true
    log_done "Sensitive paths: $(file_lines "$RECON_DIR/urls/sensitive_paths.txt")"

    # GraphQL endpoints specifically
    grep -iE '/graphql' "$RECON_DIR/urls/all.txt" \
        > "$RECON_DIR/urls/graphql.txt" 2>/dev/null || true
fi
fi  # end Phase 6 resume skip

# Refresh prioritization once URL and JS artifacts exist.
if [ -s "$RECON_DIR/urls/with_params.txt" ] || [ -s "$RECON_DIR/urls/js_files.txt" ]; then
    echo ""
    log_info "Phase 6.2: Refresh Technology CVE Prioritization"
    refresh_priority "URL and JavaScript fingerprint pass" || true
fi

# ── OpenAPI / Swagger discovery (autoswagger-style) ──────────────────────────
echo ""
log_info "Phase 6.5: OpenAPI / Swagger Discovery"
if phase_done "$RECON_DIR/api_specs/summary.md"; then true; else

OPENAPI_AUDIT="$SCRIPT_DIR/openapi_audit.py"
if [ -f "$OPENAPI_AUDIT" ] && [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Discovering Swagger / OpenAPI specs and probing public GET operations..."
    python3 "$OPENAPI_AUDIT" --recon-dir "$RECON_DIR" --max-hosts 20 --max-ops 40 2>/dev/null || true

    if [ -s "$RECON_DIR/api_specs/all_operations.txt" ]; then
        cat "$RECON_DIR/urls/api_endpoints.txt" "$RECON_DIR/api_specs/all_operations.txt" 2>/dev/null \
            | sed '/^$/d' | sort -u > "$RECON_DIR/urls/api_endpoints.txt.tmp" || true
        [ -f "$RECON_DIR/urls/api_endpoints.txt.tmp" ] && mv "$RECON_DIR/urls/api_endpoints.txt.tmp" "$RECON_DIR/urls/api_endpoints.txt"
    fi

    [ -s "$RECON_DIR/api_specs/spec_urls.txt" ] && \
        log_done "OpenAPI specs: $(file_lines "$RECON_DIR/api_specs/spec_urls.txt")"
    [ -s "$RECON_DIR/api_specs/public_operations.txt" ] && \
        log_done "Public OpenAPI ops: $(file_lines "$RECON_DIR/api_specs/public_operations.txt")"
    [ -s "$RECON_DIR/api_specs/unauth_api_findings.txt" ] && \
        log_warn "Unauth API findings from specs: $(file_lines "$RECON_DIR/api_specs/unauth_api_findings.txt")"
else
    log_warn "openapi_audit.py not found or no live hosts — skipping OpenAPI discovery"
fi

fi

# ============================================================
# Phase 7: JavaScript Analysis
# ============================================================
echo ""
log_info "Phase 7: JavaScript Analysis"
if phase_done "$RECON_DIR/js/endpoints.txt"; then true; else

mkdir -p "$RECON_DIR/js"

if [ -s "$RECON_DIR/urls/js_files.txt" ]; then
    JS_COUNT=$(file_lines "$RECON_DIR/urls/js_files.txt")
    log_step "Analysing $JS_COUNT JS files (capped at 100)..."

    # Extract endpoints and potential secrets
    head -100 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
        CONTENT=$(curl -s --max-time "$CURL_TIMEOUT" "$js_url" 2>/dev/null)

        # API endpoints in JS
        echo "$CONTENT" \
            | sed -nE 's/.*["'"'"']([a-zA-Z0-9_/.-]*(\/[a-zA-Z0-9_/.-]+){2,})["'"'"'].*/\1/p' \
            >> "$RECON_DIR/js/endpoints_raw.txt" 2>/dev/null || true

        # Potential secrets (expanded patterns)
        echo "$CONTENT" \
            | grep -oiE '(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|client[_-]?id|password|secret[_-]?key|private[_-]?key|aws[_-]?key|aws[_-]?secret|stripe[_-]?key|sendgrid[_-]?key|twilio|firebase|authorization)["\s]*[:=]["\s]*[a-zA-Z0-9_/+\-]{10,}' \
            >> "$RECON_DIR/js/potential_secrets.txt" 2>/dev/null || true

        # Source map detection
        echo "$CONTENT" | grep -oE '//# sourceMappingURL=.*\.map' \
            >> "$RECON_DIR/js/sourcemaps.txt" 2>/dev/null || true
    done

    [ -f "$RECON_DIR/js/endpoints_raw.txt" ] && \
        sort -u "$RECON_DIR/js/endpoints_raw.txt" > "$RECON_DIR/js/endpoints.txt" && \
        log_done "JS endpoints: $(file_lines "$RECON_DIR/js/endpoints.txt")"

    [ -s "$RECON_DIR/js/potential_secrets.txt" ] && \
        sort -u "$RECON_DIR/js/potential_secrets.txt" -o "$RECON_DIR/js/potential_secrets.txt" && \
        log_warn "Potential secrets in JS: $(file_lines "$RECON_DIR/js/potential_secrets.txt")"

    [ -s "$RECON_DIR/js/sourcemaps.txt" ] && \
        log_warn "Source maps found: $(file_lines "$RECON_DIR/js/sourcemaps.txt") (may expose unminified source)"
fi

# trufflehog on JS bundle dir (if available)
if tool_ok trufflehog && [ -s "$RECON_DIR/urls/js_files.txt" ]; then
    log_step "trufflehog secret scan on JS URLs..."
    head -20 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
        trufflehog --json --no-update filesystem \
            <(curl -s --max-time "$CURL_TIMEOUT" "$js_url" 2>/dev/null) \
            2>/dev/null >> "$RECON_DIR/js/trufflehog.json" || true
    done
    [ -s "$RECON_DIR/js/trufflehog.json" ] && \
        log_warn "trufflehog findings: $RECON_DIR/js/trufflehog.json"
fi

# SecretFinder — dedicated JS secret/credential extractor
_SECRETFINDER="${SCRIPT_DIR}/tools/SecretFinder/SecretFinder.py"
if [ -f "$_SECRETFINDER" ] && [ -s "$RECON_DIR/urls/js_files.txt" ]; then
    log_step "SecretFinder on JS files (top 50)..."
    mkdir -p "$RECON_DIR/js/secretfinder"
    head -50 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
        _safe_name=$(echo "$js_url" | sed 's|[^a-zA-Z0-9]|_|g' | cut -c1-80)
        python3 "$_SECRETFINDER" -i "$js_url" -o cli \
            2>/dev/null >> "$RECON_DIR/js/secretfinder/findings.txt" || true
    done
    _sf_count=$(grep -c "." "$RECON_DIR/js/secretfinder/findings.txt" 2>/dev/null || echo 0)
    [ "$_sf_count" -gt 0 ] && \
        log_warn "SecretFinder: $_sf_count potential secrets — $RECON_DIR/js/secretfinder/findings.txt"
fi

# LinkFinder — extract endpoints from JavaScript files (complements katana)
_LINKFINDER="${SCRIPT_DIR}/tools/LinkFinder/linkfinder.py"
if [ -f "$_LINKFINDER" ] && [ -s "$RECON_DIR/urls/js_files.txt" ]; then
    log_step "LinkFinder endpoint extraction on JS files (top 50)..."
    mkdir -p "$RECON_DIR/js/linkfinder"
    head -50 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
        python3 "$_LINKFINDER" -i "$js_url" -o cli \
            2>/dev/null >> "$RECON_DIR/js/linkfinder/endpoints_raw.txt" || true
    done
    if [ -s "$RECON_DIR/js/linkfinder/endpoints_raw.txt" ]; then
        sort -u "$RECON_DIR/js/linkfinder/endpoints_raw.txt" \
            > "$RECON_DIR/js/linkfinder/endpoints.txt"
        # Merge into main JS endpoints file
        cat "$RECON_DIR/js/linkfinder/endpoints.txt" >> "$RECON_DIR/js/endpoints.txt" 2>/dev/null || true
        sort -u "$RECON_DIR/js/endpoints.txt" -o "$RECON_DIR/js/endpoints.txt" 2>/dev/null || true
        log_done "LinkFinder: $(file_lines "$RECON_DIR/js/linkfinder/endpoints.txt") additional endpoints"
    fi
fi

# gf — pattern-match collected URLs for interesting params (xss, sqli, ssrf, lfi, redirect, rce)
if tool_ok gf && [ -s "$RECON_DIR/urls/all.txt" ]; then
    log_step "gf pattern matching on collected URLs..."
    mkdir -p "$RECON_DIR/urls/gf"
    for pattern in xss sqli ssrf lfi redirect rce idor cors; do
        gf "$pattern" < "$RECON_DIR/urls/all.txt" \
            > "$RECON_DIR/urls/gf/${pattern}.txt" 2>/dev/null || true
        _cnt=$(file_lines "$RECON_DIR/urls/gf/${pattern}.txt")
        [ "$_cnt" -gt 0 ] && log_warn "gf[$pattern]: $_cnt URLs — $RECON_DIR/urls/gf/${pattern}.txt"
    done
fi
# Gxss — JS sink detection: find reflected parameters that land in JS contexts
# Better signal than raw dalfox — narrows XSS surface to real sinks first.
if tool_ok Gxss && [ -s "$RECON_DIR/urls/with_params.txt" ]; then
    log_step "Gxss JS sink detection..."
    mkdir -p "$RECON_DIR/urls/gf"
    GXSS_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 50 || echo 200)
    head -"$GXSS_LIMIT" "$RECON_DIR/urls/with_params.txt" \
        | Gxss -c 100 -p Rxss \
        > "$RECON_DIR/urls/gf/gxss_sinks.txt" 2>/dev/null || true
    GXSS_COUNT=$(file_lines "$RECON_DIR/urls/gf/gxss_sinks.txt")
    [ "$GXSS_COUNT" -gt 0 ] && \
        log_warn "Gxss: $GXSS_COUNT JS sink candidates — $RECON_DIR/urls/gf/gxss_sinks.txt"
fi

fi  # end Phase 7 resume skip

# ============================================================
# Phase 7.5: Virtual Host Discovery
# ============================================================
echo ""
log_info "Phase 7.5: Virtual Host Discovery (Host header fuzzing)"
if phase_done "$RECON_DIR/vhosts/found.txt"; then true; else

mkdir -p "$RECON_DIR/vhosts"
# Use resolved subdomains as Host header wordlist, fuzz against live IPs
# This finds assets not in DNS — same IP, different virtual host
if tool_ok ffuf && [ -s "$RECON_DIR/subdomains/resolved.txt" ] && [ -s "$RECON_DIR/live/ips.txt" ]; then
    log_step "Fuzzing Host headers against live IPs..."
    VHOST_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 5 || echo 20)
    head -"$VHOST_LIMIT" "$RECON_DIR/live/ips.txt" | while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        # Get baseline response size to filter false positives
        BASELINE=$(curl -sk --max-time 5 -o /dev/null -w "%{size_download}" \
            "https://$ip" 2>/dev/null || echo 0)
        ffuf -u "https://$ip/" \
            -H "Host: FUZZ.$TARGET" \
            -w "$RECON_DIR/subdomains/resolved.txt" \
            -mc 200,201,301,302,401,403 \
            -fs "$BASELINE" \
            -t 30 -timeout 5 -s \
            -o "$RECON_DIR/vhosts/ffuf_${ip//./_}.json" \
            -of json 2>/dev/null || true
        # Extract found vhosts
        python3 -c "
import json, sys
try:
    d = json.load(open('$RECON_DIR/vhosts/ffuf_${ip//./_}.json'))
    for r in d.get('results', []):
        print(r.get('input', {}).get('FUZZ','') + '.$TARGET | IP: $ip | HTTP ' + str(r.get('status',0)))
except: pass
" 2>/dev/null >> "$RECON_DIR/vhosts/found.txt" || true
    done
    VHOST_COUNT=$(file_lines "$RECON_DIR/vhosts/found.txt")
    [ "$VHOST_COUNT" -gt 0 ] && \
        log_warn "Virtual hosts found: $VHOST_COUNT — $RECON_DIR/vhosts/found.txt"
    log_done "Virtual host discovery done"
else
    log_warn "vhost discovery skipped (needs ffuf + resolved.txt + live IPs)"
    touch "$RECON_DIR/vhosts/found.txt"
fi

fi  # end Phase 7.5 resume skip

# ============================================================
# Phase 8: Directory Fuzzing (on prioritised hosts)
# ============================================================
echo ""
log_info "Phase 8: Directory Fuzzing"
if phase_done "$RECON_DIR/dirs/ffuf_https.json"; then true; else

WORDLIST_DIR="$BASE_DIR/wordlists"
WORDLIST=""
RAFT_WORDLIST=""
SUPPLEMENT_WORDLIST="$WORDLIST_DIR/high_value_paths.txt"
SENSITIVE_WORDLIST="$WORDLIST_DIR/sensitive-files.txt"
if [ -f "$WORDLIST_DIR/common.txt" ]; then
    WORDLIST="$WORDLIST_DIR/common.txt"
elif [ -f /usr/share/wordlists/dirb/common.txt ]; then
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
fi
if [ -f "$WORDLIST_DIR/raft-medium-dirs.txt" ]; then
    RAFT_WORDLIST="$WORDLIST_DIR/raft-medium-dirs.txt"
fi

if tool_ok ffuf && { [ -n "$WORDLIST" ] || [ -n "$RAFT_WORDLIST" ] || [ -f "$SUPPLEMENT_WORDLIST" ] || [ -f "$SENSITIVE_WORDLIST" ]; }; then
    COMBINED_WORDLIST="$RECON_DIR/dirs/.ffuf_wordlist.txt"
    : > "$COMBINED_WORDLIST"
    [ -n "$WORDLIST" ] && cat "$WORDLIST" >> "$COMBINED_WORDLIST"
    [ -n "$RAFT_WORDLIST" ] && cat "$RAFT_WORDLIST" >> "$COMBINED_WORDLIST"
    [ -f "$SUPPLEMENT_WORDLIST" ] && cat "$SUPPLEMENT_WORDLIST" >> "$COMBINED_WORDLIST"
    [ -f "$SENSITIVE_WORDLIST" ] && cat "$SENSITIVE_WORDLIST" >> "$COMBINED_WORDLIST"
    awk '!seen[$0]++' "$COMBINED_WORDLIST" > "${COMBINED_WORDLIST}.dedup" && mv "${COMBINED_WORDLIST}.dedup" "$COMBINED_WORDLIST"
    log_step "ffuf wordlist: $(file_lines "$COMBINED_WORDLIST") entries (common + raft-medium + high-value + sensitive supplement)"

    # Fuzz priority targets first (CRITICAL > HIGH > sample live)
    # Use a temp file instead of mapfile — mapfile is bash 4+ only (macOS ships bash 3.2)
    FUZZ_LIST_TMP="$RECON_DIR/dirs/.fuzz_targets_tmp.txt"
    : > "$FUZZ_LIST_TMP"
    [ -s "$RECON_DIR/priority/critical_hosts.txt" ] && head -3 "$RECON_DIR/priority/critical_hosts.txt" >> "$FUZZ_LIST_TMP"
    [ -s "$RECON_DIR/priority/high_hosts.txt" ]     && head -3 "$RECON_DIR/priority/high_hosts.txt"     >> "$FUZZ_LIST_TMP"
    [ -s "$RECON_DIR/live/urls.txt" ]               && head -4 "$RECON_DIR/live/urls.txt"               >> "$FUZZ_LIST_TMP"
    # Dedup preserving order
    awk '!seen[$0]++' "$FUZZ_LIST_TMP" > "${FUZZ_LIST_TMP}.dedup" && mv "${FUZZ_LIST_TMP}.dedup" "$FUZZ_LIST_TMP"

    MAX_FUZZ=$([ "$QUICK_MODE" = "--quick" ] && echo 3 || echo 10)
    FUZZ_COUNT=0

    while IFS= read -r url && [ "$FUZZ_COUNT" -lt "$MAX_FUZZ" ]; do
        [ -z "$url" ] && continue
        domain=$(echo "$url" | sed 's|https\?://||;s|[/:].*||')
        log_step "ffuf: $url"
        ffuf -u "${url}/FUZZ" \
            -w "$COMBINED_WORDLIST" \
            -mc 200,201,301,302,401,403,405 \
            -ac -t "$THREADS" \
            -rate "$RATE_LIMIT" \
            -sf \
            -timeout "$CURL_TIMEOUT" \
            -o "$RECON_DIR/dirs/ffuf_${domain}.json" \
            -of json 2>/dev/null || true
        FUZZ_COUNT=$((FUZZ_COUNT + 1))
    done < "$FUZZ_LIST_TMP"
    rm -f "$FUZZ_LIST_TMP" "$COMBINED_WORDLIST"
    log_done "ffuf: fuzzed $FUZZ_COUNT hosts"
else
    [ -z "$WORDLIST" ] && [ -z "$RAFT_WORDLIST" ] && [ ! -f "$SUPPLEMENT_WORDLIST" ] && [ ! -f "$SENSITIVE_WORDLIST" ] && log_warn "No wordlist found — run: python3 hunt.py --setup-wordlists"
    ! tool_ok ffuf && log_warn "ffuf not installed"
fi
fi  # end Phase 8 resume skip

# ============================================================
# Phase 9: Exposed Config File Check
# ============================================================
echo ""
log_info "Phase 9: Exposed Config Files & Sensitive Paths"
if phase_done "$RECON_DIR/exposure/config_files.txt"; then true; else

CONFIG_PATHS=(
    "/.env" "/.env.local" "/.env.production" "/.env.development" "/.env.backup"
    "/env.js" "/app_env.js" "/config.js" "/settings.js"
    "/config/env.js" "/static/env.js" "/assets/env.js"
    "/.git/config" "/.git/HEAD"
    "/wp-config.php.bak" "/configuration.php.bak"
    "/uploads/" "/CHANGELOG.txt" "/install.php" "/update.php"
    "/phpinfo.php" "/info.php" "/adminer.php" "/phpmyadmin/"
    "/backup/" "/backups/" "/db/"
    "/console" "/h2-console/" "/manager/html"
    "/administrator/" "/xmlrpc.php" "/cgi-bin/"
    "/server-status" "/server-info"
    "/actuator/env" "/actuator/heapdump" "/actuator/mappings"
    "/api/swagger.json" "/swagger.json" "/openapi.json" "/api-docs"
    "/.DS_Store" "/Thumbs.db" "/web.config.bak"
)

: > "$RECON_DIR/exposure/config_files.txt"
CONFIG_TARGETS="$RECON_DIR/exposure/.config_targets.txt"
CONFIG_PATHS_FILE="$RECON_DIR/exposure/.config_paths.txt"
CONFIG_PROBE_JOBS=$([ "$QUICK_MODE" = "--quick" ] && echo 4 || echo 12)
printf '%s\n' "${CONFIG_PATHS[@]}" > "$CONFIG_PATHS_FILE"

# Check config paths on priority hosts first, then broader live sample
if [ "$QUICK_MODE" = "--quick" ]; then
    CONFIG_MAX_HOSTS=30
    {
        [ -s "$RECON_DIR/priority/critical_hosts.txt" ] && cat "$RECON_DIR/priority/critical_hosts.txt"
        [ -s "$RECON_DIR/priority/high_hosts.txt" ] && head -20 "$RECON_DIR/priority/high_hosts.txt"
        [ -s "$RECON_DIR/live/urls.txt" ] && head -40 "$RECON_DIR/live/urls.txt"
    } | sort -u | head -"$CONFIG_MAX_HOSTS" > "$CONFIG_TARGETS"
else
    {
        [ -s "$RECON_DIR/priority/critical_hosts.txt" ] && cat "$RECON_DIR/priority/critical_hosts.txt"
        [ -s "$RECON_DIR/priority/high_hosts.txt" ] && cat "$RECON_DIR/priority/high_hosts.txt"
        [ -s "$RECON_DIR/live/urls.txt" ] && cat "$RECON_DIR/live/urls.txt"
    } | awk '!seen[$0]++' > "$CONFIG_TARGETS"
    CONFIG_MAX_HOSTS=$(file_lines "$CONFIG_TARGETS")
fi
log_step "Config-path coverage: $CONFIG_MAX_HOSTS hosts, ${#CONFIG_PATHS[@]} paths, $CONFIG_PROBE_JOBS parallel jobs"

JOB_COUNT=0
CONFIG_PIDS=()
while IFS= read -r base_url; do
    [ -z "$base_url" ] && continue
    (
        while IFS= read -r path; do
            STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
                --max-time "$CURL_TIMEOUT" "${base_url}${path}" 2>/dev/null || echo "000")
            if [ "$STATUS" = "200" ]; then
                CT=$(curl -sI --max-time "$CURL_TIMEOUT" "${base_url}${path}" 2>/dev/null \
                    | grep -i content-type | head -1)
                if echo "$CT" | grep -qiE '(javascript|json|text/plain|text/html|text/xml)'; then
                    echo "[EXPOSED] ${base_url}${path}"
                fi
            fi
        done < "$CONFIG_PATHS_FILE"
    ) >> "$RECON_DIR/exposure/config_files.txt" &
    CONFIG_PIDS+=("$!")
    JOB_COUNT=$((JOB_COUNT + 1))
    if [ $((JOB_COUNT % CONFIG_PROBE_JOBS)) -eq 0 ]; then
        if [ "${#CONFIG_PIDS[@]}" -gt 0 ]; then
            for pid in "${CONFIG_PIDS[@]}"; do
                wait "$pid"
            done
        fi
        CONFIG_PIDS=()
    fi
done < "$CONFIG_TARGETS"
if [ "${#CONFIG_PIDS[@]}" -gt 0 ]; then
    for pid in "${CONFIG_PIDS[@]}"; do
        wait "$pid"
    done
fi
sort -u "$RECON_DIR/exposure/config_files.txt" -o "$RECON_DIR/exposure/config_files.txt" 2>/dev/null || true
rm -f "$CONFIG_TARGETS" "$CONFIG_PATHS_FILE"

CFG=$(file_lines "$RECON_DIR/exposure/config_files.txt")
[ "$CFG" -gt 0 ] && log_warn "Exposed config files: $CFG" || log_done "Config files: clean"
fi  # end Phase 9 resume skip

# ============================================================
# Phase 10: Parameter Discovery
# ============================================================
echo ""
log_info "Phase 10: Parameter Discovery"
if phase_done "$RECON_DIR/params/unique_params.txt"; then true; else

if [ -s "$RECON_DIR/urls/with_params.txt" ]; then
    sed -nE 's/.*[?&]([^=&]+)=.*/\1/p' "$RECON_DIR/urls/with_params.txt" 2>/dev/null \
        | sort | uniq -c | sort -rn > "$RECON_DIR/params/param_frequency.txt" || true

    awk '{print $2}' "$RECON_DIR/params/param_frequency.txt" \
        > "$RECON_DIR/params/unique_params.txt" || true
    log_done "Unique params: $(file_lines "$RECON_DIR/params/unique_params.txt")"

    # Interesting params for SSRF / redirect / injection
    grep -iE '^(url|redirect|next|return|callback|dest|file|path|page|template|include|src|ref|uri|link|target|goto|out|view|dir|show|site|domain|rurl|return_to|continue|window|data|reference|to|img|load|doc|download|source|feed)$' \
        "$RECON_DIR/params/unique_params.txt" \
        > "$RECON_DIR/params/interesting_params.txt" 2>/dev/null || true

    if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
        log_warn "Interesting params (SSRF/redirect/LFI): $(file_lines "$RECON_DIR/params/interesting_params.txt")"
    fi

    # arjun — hidden parameter discovery on API endpoints
    if tool_ok arjun && [ -s "$RECON_DIR/urls/api_endpoints.txt" ]; then
        log_step "arjun hidden parameter discovery (sample endpoints)..."
        head -10 "$RECON_DIR/urls/api_endpoints.txt" | while IFS= read -r ep; do
            arjun -u "$ep" --stable -q \
                -oJ "$RECON_DIR/params/arjun_$(echo "$ep" | md5sum | cut -c1-8).json" \
                2>/dev/null || true
        done
        log_done "arjun done"
    fi
fi
fi  # end Phase 10 resume skip

wait_async_phases

# ============================================================
# Summary
# ============================================================
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  Recon Summary — $TARGET${NC}"
echo -e "  Completed: $(date)"
echo -e "${BOLD}============================================================${NC}"
printf "  %-24s %s\n" "Subdomains found:"       "$(file_lines "$RECON_DIR/subdomains/all.txt")"
printf "  %-24s %s\n" "Resolved hosts:"         "$(file_lines "$RECON_DIR/subdomains/resolved.txt")"
printf "  %-24s %s\n" "Live HTTP hosts:"         "$(file_lines "$RECON_DIR/live/urls.txt")"
printf "  %-24s %s\n" "CRITICAL CVE hosts:"      "$(file_lines "$RECON_DIR/priority/critical_hosts.txt")"
printf "  %-24s %s\n" "HIGH CVE hosts:"          "$(file_lines "$RECON_DIR/priority/high_hosts.txt")"
printf "  %-24s %s\n" "Open ports (apex):"       "$(file_lines "$RECON_DIR/ports/open_ports.txt")"
printf "  %-24s %s\n" "Total URLs:"              "$(file_lines "$RECON_DIR/urls/all.txt")"
printf "  %-24s %s\n" "Parameterized URLs:"      "$(file_lines "$RECON_DIR/urls/with_params.txt")"
printf "  %-24s %s\n" "API endpoints:"           "$(file_lines "$RECON_DIR/urls/api_endpoints.txt")"
printf "  %-24s %s\n" "JS files:"                "$(file_lines "$RECON_DIR/urls/js_files.txt")"
printf "  %-24s %s\n" "Exposed configs:"         "$(file_lines "$RECON_DIR/exposure/config_files.txt")"
printf "  %-24s %s\n" "Unique params:"           "$(file_lines "$RECON_DIR/params/unique_params.txt")"
echo ""
echo -e "  Results : $RECON_DIR/"
echo -e "  Priority: $RECON_DIR/priority/prioritized_hosts.txt"
echo ""
echo -e "  Next: Run vulnerability scanner"
echo -e "    bash $SCRIPT_DIR/scanner.sh $RECON_DIR"
echo -e "${BOLD}============================================================${NC}"
echo ""

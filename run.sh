#!/bin/bash
# HackerOne 20-Day Hunt — Master Runner
# Run this script after setting your tokens below.
# It runs all automation tools in the right order.
#
# Usage:
#   chmod +x run.sh
#   ./run.sh

set -euo pipefail

# ─── SET THESE BEFORE RUNNING ────────────────────────────────────────────────
TOKEN_A=""          # Account A Bearer token (resource owner — your main account)
TOKEN_B=""          # Account B Bearer token (attacker — second account)
REPORT_ID=""        # A report ID that Account A submitted to its sandbox program
USER_ID=""          # Account A's numeric user ID (from /users/me)
PROGRAM=""          # Account A's sandbox program handle
EMAIL_A=""          # Account A's email (for password reset test)
ATTACHMENT_URL=""   # (Optional) Signed S3 URL from a private report attachment

# ─── Validation ──────────────────────────────────────────────────────────────
if [[ -z "$TOKEN_A" || -z "$TOKEN_B" ]]; then
  echo "ERROR: Set TOKEN_A and TOKEN_B before running"
  echo ""
  echo "To get your token:"
  echo "  1. Login to hackerone.com"
  echo "  2. Open DevTools → Network → any /graphql request"
  echo "  3. Copy the 'Authorization: Bearer ...' value"
  exit 1
fi

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FINDINGS_DIR="$TOOLS_DIR/findings/hackerone"
mkdir -p "$FINDINGS_DIR/auto"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG="$FINDINGS_DIR/auto/scan_${TIMESTAMP}.log"

echo "═══════════════════════════════════════════════════"
echo "  HackerOne Automated Hunt"
echo "  Date: $(date)"
echo "  Log: $LOG"
echo "═══════════════════════════════════════════════════"
echo ""

# Helper to get Account A's user ID if not set
if [[ -z "$USER_ID" ]]; then
  echo "[*] Fetching Account A user ID..."
  # Do NOT let a curl/parse failure abort the whole run (set -e/pipefail);
  # capture explicitly and validate the result so a bad/empty response is
  # detected (fail-loud) rather than silently producing a blank USER_ID.
  USER_ID=$(curl -sf \
    -H "Authorization: Bearer $TOKEN_A" \
    -H "Content-Type: application/json" \
    https://hackerone.com/graphql \
    -d '{"query":"{ me { id databaseId } }"}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('me',{}).get('databaseId',''))") || USER_ID=""
  if [[ "$USER_ID" =~ ^[0-9]+$ ]]; then
    echo "  Account A user ID: $USER_ID"
  else
    echo "  WARNING: could not resolve a numeric Account A user ID (got '${USER_ID}'); user-scoped IDOR tests will be skipped."
    USER_ID=""
  fi
fi

echo ""
echo "══ PHASE 1: Authenticated GraphQL Schema Mapping ══"
echo ""
# Map all authenticated mutations (not visible unauthenticated)
curl -sf \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  https://hackerone.com/graphql \
  -d '{"query":"{ __type(name: \"Mutation\") { fields { name args { name type { name kind } } } } }"}' \
  | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    print('  WARNING: empty/invalid GraphQL response for Mutation schema')
    sys.exit(0)
fields = d.get('data', {}).get('__type', {}).get('fields') or []
print(f'  Authenticated mutations found: {len(fields)}')
for f in sorted(fields, key=lambda x: x['name']):
    args = ', '.join(a['name'] for a in f.get('args', []))
    print(f\"  {f['name']}({args})\")
" | tee -a "$LOG" || echo "  WARNING: Mutation schema map failed (curl/network error)" | tee -a "$LOG"

echo ""
echo "  Authenticated queries:"
curl -sf \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  https://hackerone.com/graphql \
  -d '{"query":"{ __type(name: \"Query\") { fields { name } } }"}' \
  | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    print('  WARNING: empty/invalid GraphQL response for Query schema')
    sys.exit(0)
fields = d.get('data', {}).get('__type', {}).get('fields') or []
names = sorted(f['name'] for f in fields)
print(f'  Total queries: {len(names)}')
for n in names: print(f'  - {n}')
" | tee -a "$LOG" || echo "  WARNING: Query schema map failed (curl/network error)" | tee -a "$LOG"

sleep 2

echo ""
echo "══ PHASE 2: Cross-User IDOR Scanner ══"
echo ""
# Build the command as an ARRAY so every value is passed verbatim and is
# never re-parsed by the shell. This closes the eval-injection / word-splitting
# vector: a value containing a quote, space, ';', '$(...)', etc. is treated as a
# single literal argument instead of shell syntax.
CMD=(python3 "$TOOLS_DIR/idor.py" --token-a "$TOKEN_A" --token-b "$TOKEN_B")
[[ -n "$REPORT_ID" ]]      && CMD+=(--report-id "$REPORT_ID")
[[ -n "$USER_ID" ]]       && CMD+=(--user-id "$USER_ID")
[[ -n "$PROGRAM" ]]       && CMD+=(--program "$PROGRAM")
[[ -n "$ATTACHMENT_URL" ]] && CMD+=(--attachment-url "$ATTACHMENT_URL")

# Echo a REDACTED form: never print the live Bearer token values to the
# terminal/scrollback. Replace the two token args with placeholders.
SAFE_CMD=("${CMD[@]}")
for i in "${!SAFE_CMD[@]}"; do
  if [[ "${SAFE_CMD[$i]}" == "$TOKEN_A" || "${SAFE_CMD[$i]}" == "$TOKEN_B" ]]; then
    SAFE_CMD[$i]="***REDACTED***"
  fi
done
echo "  Running: ${SAFE_CMD[*]}"
# A nonzero exit from one scan tool must not abort the remaining phases
# (pipefail is on); surface it as a warning and continue.
"${CMD[@]}" 2>&1 | tee -a "$LOG" || echo "  WARNING: idor.py exited non-zero" | tee -a "$LOG"

sleep 2

echo ""
echo "══ PHASE 3: Auth / OAuth Checks ══"
echo ""
python3 "$TOOLS_DIR/oauth.py" \
  --check-cors \
  --check-oauth \
  --check-ssrf \
  2>&1 | tee -a "$LOG" || echo "  WARNING: oauth.py checks exited non-zero" | tee -a "$LOG"

if [[ -n "$EMAIL_A" ]]; then
  echo ""
  echo "  [Password Reset Test] email=$EMAIL_A"
  python3 "$TOOLS_DIR/oauth.py" \
    --check-reset \
    --email "$EMAIL_A" \
    2>&1 | tee -a "$LOG" || echo "  WARNING: oauth.py reset test exited non-zero" | tee -a "$LOG"
fi

sleep 2

echo ""
echo "══ PHASE 4: Race Condition Tests ══"
echo ""

# Negative bounty test (safe — doesn't actually award, tests validation)
if [[ -n "$REPORT_ID" ]]; then
  python3 "$TOOLS_DIR/race.py" \
    --token-a "$TOKEN_A" \
    --test negative-bounty \
    --report-id "$REPORT_ID" \
    2>&1 | tee -a "$LOG" || echo "  WARNING: race.py exited non-zero" | tee -a "$LOG"
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  SCAN COMPLETE"
echo "  Full log: $LOG"
echo "═══════════════════════════════════════════════════"
echo ""
echo "MANUAL TESTS STILL REQUIRED:"
echo "  [ ] Hai AI — test IDOR via chat (Day 17) — must be done in browser"
echo "  [ ] GitHub OAuth redirect_uri — browser + Burp (Day 9)"
echo "  [ ] SSRF webhook — sandbox program integration settings (Day 15)"
echo "  [ ] 2FA rate limit — run: python3 race.py --token-a TOKEN_B --test 2fa"
echo "  [ ] PullRequest.com — manual browse + Autorize (Day 16)"
echo "  [ ] Stored XSS — submit report with payloads (Day 14)"
echo ""
echo "NEXT IF NO FINDINGS:"
echo "  Move to a different target — try live app testing on another program"

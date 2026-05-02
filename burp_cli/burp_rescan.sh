#!/bin/bash
# burp_rescan.sh — Drive Burp Suite Pro from the CLI
#
# Modes:
#   ./burp_rescan.sh start                        # launch Burp Pro headless with REST API
#   ./burp_rescan.sh scan <har-file> [scope-host] # extract URLs from HAR + active scan
#   ./burp_rescan.sh scan-url <url> [scope-host]  # active scan a single URL
#   ./burp_rescan.sh status <task-id>             # poll scan status
#   ./burp_rescan.sh issues <task-id>             # pull issues as JSON
#   ./burp_rescan.sh export <task-id> <out.json>  # save findings to disk + reporter.py-friendly JSON
#   ./burp_rescan.sh stop                         # shut Burp down cleanly

set -e
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin

BURP_BIN="/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
PROJECT_DIR="$HOME/burp-projects"
CONFIG="$HOME/burp-configs/api-enabled.json"
PROJECT="$PROJECT_DIR/$(date +%Y%m%d).burp"
BURP_API_KEY="${BURP_API_KEY:-}"
REPORT_DIR="${REPORT_DIR:-/tmp/burp-reports}"
mkdir -p "$PROJECT_DIR" "$REPORT_DIR"

require() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }
require_burp_key() {
  if [ -z "$BURP_API_KEY" ]; then
    echo "ERROR: BURP_API_KEY env var not set." >&2
    echo "Generate a key in Burp: User options -> Misc -> REST API -> New" >&2
    echo "Then: export BURP_API_KEY=<key>" >&2
    exit 1
  fi
}
require jq
require curl
require_burp_key
API="http://127.0.0.1:1337/${BURP_API_KEY}/v0.1"

cmd_start() {
  if curl -fsS "$API/" >/dev/null 2>&1; then
    echo "Burp REST API already up at $API"
    return 0
  fi
  if [ ! -f "$PROJECT" ]; then
    # Burp creates the project on first launch — pass --project-file alone the first time
    "$BURP_BIN" --project-file="$PROJECT" --config-file="$CONFIG" &>/tmp/burp.log &
  else
    "$BURP_BIN" --project-file="$PROJECT" --config-file="$CONFIG" &>/tmp/burp.log &
  fi
  echo "Burp launching with project=$PROJECT  config=$CONFIG  log=/tmp/burp.log"
  for i in $(seq 1 30); do
    if curl -fsS "$API/" >/dev/null 2>&1; then
      echo "REST API up after ${i}s"
      return 0
    fi
    sleep 2
  done
  echo "ERROR: REST API did not come up. tail /tmp/burp.log:"
  tail -20 /tmp/burp.log
  exit 1
}

cmd_stop() {
  pkill -f "Burp Suite Professional" 2>/dev/null || true
  echo "Burp stopped"
}

cmd_scan_url() {
  local url="$1"
  local scope_host="${2:-$(echo "$url" | awk -F/ '{print $3}')}"
  local body
  body=$(jq -n --arg url "$url" --arg host "$scope_host" '
    {
      urls: [$url],
      scope: {type:"SimpleScope", include: [{rule: ("https://" + $host)}]}
    }')
  echo "$body" | jq -c .
  curl -fsS -X POST "$API/scan" -H 'Content-Type: application/json' -d "$body" | jq .
}

cmd_scan_har() {
  local har="$1"
  local scope_host="$2"
  [ -f "$har" ] || { echo "HAR file not found: $har"; exit 1; }
  local urls
  urls=$(jq -r '.log.entries[].request.url' "$har" | grep -E "^https?://" | sort -u)
  if [ -n "$scope_host" ]; then
    urls=$(echo "$urls" | grep -F "$scope_host" || true)
  fi
  local count
  count=$(echo "$urls" | wc -l | tr -d ' ')
  echo "Submitting $count URLs for scan (scope_host='${scope_host:-any}')"
  local urls_json
  urls_json=$(echo "$urls" | jq -R . | jq -s .)
  local rule
  rule=${scope_host:+"https://${scope_host}"}
  rule=${rule:-"https://"}
  local body
  body=$(jq -n --argjson urls "$urls_json" --arg rule "$rule" '
    {
      urls: $urls,
      scope: {type:"SimpleScope", include: [{rule: $rule}]}
    }')
  curl -fsS -X POST "$API/scan" -H 'Content-Type: application/json' -d "$body" | jq .
}

cmd_status() {
  local task="$1"
  curl -fsS "$API/scan/$task" | jq '{task_id, scan_status, scan_metrics, issue_events_count: (.issue_events | length)}'
}

cmd_issues() {
  local task="$1"
  curl -fsS "$API/scan/$task" \
    | jq '.issue_events[] | {
        name: .issue.name,
        severity: .issue.severity,
        confidence: .issue.confidence,
        url: .issue.origin + .issue.path,
        evidence: (.issue.evidence // [] | map({type, request: .request_response.request, response: .request_response.response}) )
      }'
}

cmd_export() {
  local task="$1"
  local out="${2:-$REPORT_DIR/burp_$(date +%Y%m%d_%H%M%S)_task${task}.json}"
  local raw
  raw=$(curl -fsS "$API/scan/$task")
  echo "$raw" | jq '{
    burp_task_id: .task_id,
    status: .scan_status,
    metrics: .scan_metrics,
    findings: [.issue_events[].issue | {
      name, severity, confidence,
      cve: (.references // []),
      url: (.origin + .path),
      description: .description_html,
      remediation: .remediation_html
    }]
  }' > "$out"
  echo "Wrote $(jq '.findings | length' "$out") findings -> $out"
}

case "${1:-help}" in
  start)     cmd_start ;;
  stop)      cmd_stop ;;
  scan)      shift; cmd_scan_har "$@" ;;
  scan-url)  shift; cmd_scan_url "$@" ;;
  status)    shift; cmd_status "$@" ;;
  issues)    shift; cmd_issues "$@" ;;
  export)    shift; cmd_export "$@" ;;
  *) sed -n '2,11p' "$0"; exit 1 ;;
esac

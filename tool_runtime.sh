# Shared runtime pins for health-checked ProjectDiscovery tools. Source only
# after SCRIPT_DIR is set; never fall back to a known-broken PATH shadow.
if ! _VIK_TOOL_EXPORTS=$(python3 "$SCRIPT_DIR/tool_resolution.py" --shell-env); then
    echo "[!] Tool resolution failed; ProjectDiscovery tools disabled" >&2
    _VIK_TOOL_EXPORTS='export VIK_HTTPX_BIN= VIK_DNSX_BIN= VIK_NUCLEI_BIN= VIK_KATANA_BIN='
fi
eval "$_VIK_TOOL_EXPORTS"
unset _VIK_TOOL_EXPORTS
VIK_NUCLEI_SCOPE_HELPER="$SCRIPT_DIR/nuclei_scope.py"
export VIK_NUCLEI_SCOPE_HELPER

httpx()  { [ -n "${VIK_HTTPX_BIN:-}" ] && "$VIK_HTTPX_BIN" "$@"; }
dnsx()   { [ -n "${VIK_DNSX_BIN:-}" ] && "$VIK_DNSX_BIN" "$@"; }
nuclei() {
    [ -n "${VIK_NUCLEI_BIN:-}" ] || return 1
    local _nuclei_scope_flags _nuclei_rc
    # SCOPE_LOCK can be shell-local in recon.sh, so check it before invoking
    # the shared detector. Append -dr last so caller flags cannot undo it.
    if [ "${SCOPE_LOCK:-0}" = "1" ]; then
        _nuclei_scope_flags="-dr"
    else
        _nuclei_scope_flags=$(python3 "$VIK_NUCLEI_SCOPE_HELPER" --shell-flags \
            "${RECON_DIR:-}" "${FINDINGS_DIR:-}") || return 1
    fi
    if [ "$_nuclei_scope_flags" = "-dr" ]; then
        "$VIK_NUCLEI_BIN" "$@" -dr && _nuclei_rc=0 || _nuclei_rc=$?
        python3 "$VIK_NUCLEI_SCOPE_HELPER" --record-coverage --locked --exit-code "$_nuclei_rc" \
            "${RECON_DIR:-}" "${FINDINGS_DIR:-}" || \
            echo "[!] Nuclei coverage marker could not be recorded (rc=$_nuclei_rc)" >&2
        return "$_nuclei_rc"
    fi
    "$VIK_NUCLEI_BIN" "$@"
}
katana() { [ -n "${VIK_KATANA_BIN:-}" ] && "$VIK_KATANA_BIN" "$@"; }
export -f httpx dnsx nuclei katana

_vik_tool_ok() {
    case "$1" in
        httpx)  [ -n "${VIK_HTTPX_BIN:-}" ] && [ -x "$VIK_HTTPX_BIN" ] ;;
        dnsx)   [ -n "${VIK_DNSX_BIN:-}" ] && [ -x "$VIK_DNSX_BIN" ] ;;
        nuclei) [ -n "${VIK_NUCLEI_BIN:-}" ] && [ -x "$VIK_NUCLEI_BIN" ] ;;
        katana) [ -n "${VIK_KATANA_BIN:-}" ] && [ -x "$VIK_KATANA_BIN" ] ;;
        *) command -v "$1" >/dev/null 2>&1 ;;
    esac
}

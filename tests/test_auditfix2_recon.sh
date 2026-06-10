#!/usr/bin/env bash
# Regression test for the BSD/macOS sed domain-extraction bug in recon.sh
# (ffuf per-host loop, ~line 1536). The previous fix used 'https\?://' which
# is NOT an optional quantifier on BSD/macOS sed (bash 3.2 dev platform), so
# every host collapsed to bare 'https'/'http', colliding all per-host ffuf
# output files. This asserts the live recon.sh expression yields the bare host.
#
# Run: bash tests/test_auditfix2_recon.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RECON="$SCRIPT_DIR/recon.sh"
fail=0

# Extract the EXACT domain-extraction sed pipeline from recon.sh so the test
# tracks the real source line (not a copy that could drift).
EXTRACT_LINE=$(grep -n 'domain=$(echo "$url" | sed' "$RECON" | head -n1 | cut -d: -f1)
if [ -z "$EXTRACT_LINE" ]; then
    echo "FAIL: could not locate domain-extraction line in recon.sh"
    exit 1
fi
# Pull just the command substitution body: sed ... (between $( and ))
SED_EXPR=$(grep 'domain=$(echo "$url" | sed' "$RECON" | head -n1 \
    | sed -E 's/.*domain=\$\(echo "\$url" \| (sed[^)]*)\)/\1/')
echo "recon.sh line $EXTRACT_LINE extracts domain via: $SED_EXPR"
echo "-----------------------------------------------------------"

# Helper: run the extracted sed expression against a URL exactly as recon.sh does.
extract_domain() {
    url="$1"
    echo "$url" | eval "$SED_EXPR"
}

assert_eq() {
    desc="$1"; got="$2"; want="$3"
    if [ "$got" = "$want" ]; then
        echo "PASS  $desc :: '$got'"
    else
        echo "FAIL  $desc :: got '$got' want '$want'"
        fail=1
    fi
}

assert_eq "https + path"        "$(extract_domain 'https://host.example.com/x')"      "host.example.com"
assert_eq "http + path"         "$(extract_domain 'http://host.example.com/x')"       "host.example.com"
assert_eq "https + port + path" "$(extract_domain 'https://host.example.com:8443/p')" "host.example.com"
assert_eq "http + port"         "$(extract_domain 'http://10.0.0.5:80')"              "10.0.0.5"
assert_eq "https bare host"     "$(extract_domain 'https://sub.domain.co.uk')"        "sub.domain.co.uk"
assert_eq "https + trailing /"  "$(extract_domain 'https://example.org/')"            "example.org"

echo "-----------------------------------------------------------"
# Collision check: two distinct hosts MUST yield distinct ffuf output filenames.
d1=$(extract_domain 'https://alpha.example.com/')
d2=$(extract_domain 'https://beta.example.com/')
if [ "$d1" != "$d2" ]; then
    echo "PASS  distinct hosts -> distinct domains ('$d1' != '$d2')"
else
    echo "FAIL  per-host output collision: both hosts -> '$d1'"
    fail=1
fi

# Negative guard: the OLD buggy expression must NOT be present in any actual
# assignment. Match only VAR=$(echo ... sed 's|https\?://||...) lines (the live
# code) — not comment lines that quote the pattern for documentation.
if grep -E "^[[:space:]]*[A-Za-z_]+=\\\$\\(echo .* sed 's\\|https\\\\\\?://" "$RECON"; then
    echo "FAIL  buggy BSD-incompatible sed assignment still present in recon.sh"
    fail=1
else
    echo "PASS  no live assignment uses the buggy 'https\\?://' BSD-incompatible sed"
fi

# Verify BOTH known extraction sites (ffuf loop + nmap critical-host loop) use
# the portable -E form. Both feed per-host output filenames, so both must yield
# distinct bare hosts on BSD/macOS.
PORTABLE_SITES=$(grep -cE "=\\\$\\(echo .* sed -E 's#https\\?://##; s#\\[/:\\]\\.\\*##'" "$RECON")
if [ "$PORTABLE_SITES" -ge 2 ]; then
    echo "PASS  $PORTABLE_SITES extraction sites use portable 'sed -E https?://'"
else
    echo "FAIL  expected >=2 portable extraction sites, found $PORTABLE_SITES"
    fail=1
fi

echo "-----------------------------------------------------------"
if [ "$fail" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "TESTS FAILED"
    exit 1
fi

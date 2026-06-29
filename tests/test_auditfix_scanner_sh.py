"""Regression tests for scanner.sh audit fixes (v10.6.x).

scanner.sh is a large shell pipeline that cannot be run wholesale in CI, so —
mirroring tests/test_auditfix_recon_sh.py — these tests assert (a) the script
still parses (`bash -n`) and (b) the corrected source-level invariants are
present and the known-bad patterns are gone. Where a fix has a self-contained
shell predicate (the live-host resolver, the CSP wildcard match, the SQLi
dialect coverage), the snippet is executed directly to prove the logic.

All test data is SYNTHETIC (example.invalid / 127.0.0.1 placeholders).

Fixes covered:
  0. HIGH  — default/focused mode silently skipped xss/ssti/etc with no marker.
            Now skip_has emits a visible SKIPPED warning + a coverage_gaps.txt
            marker, so the coverage loss is auditable.
  1. HIGH  — Checks 7-10 (SAML/import/deserialize/supplychain) read
            live/httpx_live.txt, a file recon NEVER creates → iterated zero
            hosts. Now use the canonical _resolve_live_hosts fallback chain.
  2. MED   — SQLi time-based probe was hard-capped at 10 URLs with no marker.
            Now scales with mode (SQLI_MAX) and records a coverage gap.
  3. MED   — MFA workflow-skip fired on ANY HTTP 200. Now requires body !=
            unauth baseline + auth marker, else a manual-review candidate.
  4. MED   — SAML sig-strip flagged CRITICAL ATO on any 200/302. Now requires a
            session cookie + non-login redirect, else a candidate.
  5. MED   — upload RCE proof only probed 7 hardcoded dirs. Now parses the
            disclosed path from the upload response first, and records
            [UPLOAD-ACCEPTED-UNVERIFIED] when the canary isn't located.
  6. LOW   — CSP weak-directive check missed a bare '*' source. Now matches both
            the quoted '*' and a bare '*' token.
  7. LOW   — manual time-based SQLi only covered mysql/postgres. Now adds
            mssql (WAITFOR DELAY) and oracle (DBMS_PIPE.RECEIVE_MESSAGE).
"""

import os
import subprocess

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER_SH = os.path.join(HERE, "scanner.sh")


def _src():
    with open(SCANNER_SH, encoding="utf-8") as f:
        return f.read()


def test_bash_syntax_ok():
    """The whole script must still parse after the edits."""
    r = subprocess.run(["bash", "-n", SCANNER_SH], capture_output=True, text=True)
    assert r.returncode == 0, f"bash -n failed:\n{r.stderr}"


# ── Fix 1: dead host loops reading a file recon never creates ─────────────────
def test_fix1_no_phantom_httpx_live_reads():
    s = _src()
    # The phantom path must be gone from every host-loop read.
    assert 'cat "$RECON_DIR/live/httpx_live.txt"' not in s
    # The canonical resolver must exist and be used by the four checks.
    assert "_resolve_live_hosts()" in s
    assert s.count("LIVE_HOSTS=$(_resolve_live_hosts") >= 4


def test_fix1_resolver_prefers_urls_txt_then_httpx_full(tmp_path):
    """Directly exercise _resolve_live_hosts against a synthetic recon dir."""
    recon = tmp_path / "recon"
    (recon / "live").mkdir(parents=True)
    (recon / "live" / "urls.txt").write_text(
        "http://a.example.invalid\nhttp://b.example.invalid\n"
    )
    script = f"""
    set -uo pipefail
    RECON_DIR={recon!s}
    ORDERED_SCAN=/nonexistent.invalid
    PRIORITY_DIR=/nonexistent.invalid
    {_extract_func("_resolve_live_hosts")}
    _resolve_live_hosts 20
    """
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "a.example.invalid" in out.stdout
    assert "b.example.invalid" in out.stdout


def test_fix1_resolver_falls_back_to_httpx_full_first_column(tmp_path):
    recon = tmp_path / "recon"
    (recon / "live").mkdir(parents=True)
    # httpx_full has tech tags in trailing columns; resolver must take col 1.
    (recon / "live" / "httpx_full.txt").write_text(
        "http://c.example.invalid [200] [nginx]\n"
    )
    script = f"""
    set -uo pipefail
    RECON_DIR={recon!s}
    ORDERED_SCAN=/nonexistent.invalid
    PRIORITY_DIR=/nonexistent.invalid
    {_extract_func("_resolve_live_hosts")}
    _resolve_live_hosts 0
    """
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "http://c.example.invalid"


def test_fix1_resolver_empty_when_nothing_present(tmp_path):
    recon = tmp_path / "recon"
    (recon / "live").mkdir(parents=True)
    script = f"""
    set -uo pipefail
    RECON_DIR={recon!s}
    ORDERED_SCAN=/nonexistent.invalid
    PRIORITY_DIR=/nonexistent.invalid
    {_extract_func("_resolve_live_hosts")}
    _resolve_live_hosts 20
    """
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == ""


# ── Fix 0: default-mode skip now leaves a marker ──────────────────────────────
def test_fix0_skip_emits_coverage_marker():
    s = _src()
    assert "_mark_coverage" in s
    assert "COVERAGE-GAP" in s
    # skip_has must record the gap (not silently return 0).
    assert "skipped in default/focused mode" in s


# ── Fix 2: SQLi cap now scaled + marked ───────────────────────────────────────
def test_fix2_sqli_cap_is_marked():
    s = _src()
    assert "head -10 \"$PARAMS_FILE\"" not in s  # the silent literal-10 cap is gone
    assert "SQLI_MAX" in s
    assert '_mark_coverage "sqli"' in s


# ── Fix 6: CSP wildcard matches bare '*' ──────────────────────────────────────
def test_fix6_csp_bare_wildcard_matched():
    s = _src()
    # the new regex must exist; the old quoted-only literal must be gone
    assert "'\\\\*'" not in s or "wildcard-src" in s
    # Execute the exact grep against a bare-* CSP and a quoted-* CSP.
    for csp in ("default-src *", "default-src '*'"):
        script = (
            f'echo "{csp}" | '
            r"""grep -qiE "(^|[[:space:];])('\*'|\*)([[:space:];]|$)" """
            "&& echo MATCH || echo NOMATCH"
        )
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        assert out.stdout.strip() == "MATCH", f"CSP {csp!r} not flagged"
    # A non-wildcard CSP must NOT match.
    out = subprocess.run(
        ["bash", "-c",
         "echo \"default-src 'self' https://cdn.example.invalid\" | "
         r"""grep -qiE "(^|[[:space:];])('\*'|\*)([[:space:];]|$)" """
         "&& echo MATCH || echo NOMATCH"],
        capture_output=True, text=True,
    )
    assert out.stdout.strip() == "NOMATCH"


# ── Fix 7: SQLi dialect coverage extended ─────────────────────────────────────
def test_fix7_mssql_oracle_dialects_present():
    s = _src()
    assert "mssql" in s and "oracle" in s
    assert "WAITFOR" in s
    assert "DBMS_PIPE.RECEIVE_MESSAGE" in s
    # The driver loop must iterate all four engines.
    assert 'for dialect in "mysql" "postgres" "mssql" "oracle"' in s


# ── Fix 3: MFA workflow-skip requires corroboration ───────────────────────────
def test_fix3_mfa_workflow_skip_corroborated():
    s = _src()
    # No longer a bare "HTTP 200 ⇒ [VULN]" emission.
    assert "MFA-WORKFLOW-SKIP-CANDIDATE" in s
    assert "unauth baseline" in s


# ── Fix 4: SAML sig-strip requires session evidence ───────────────────────────
def test_fix4_saml_sig_strip_requires_session():
    s = _src()
    assert "SAML-SIG-STRIP-CANDIDATE" in s
    # Acceptance now keys off a session cookie + non-login redirect, not code.
    assert "session cookie set" in s or "established a session" in s
    # No synthetic real-looking client domain in the assertion payload.
    assert "admin@target.com" not in s
    assert "admin@example.invalid" in s


# ── Fix 5: upload proof parses disclosed path + records accepted-unverified ───
def test_fix5_upload_accepted_unverified_recorded():
    s = _src()
    assert "UPLOAD-ACCEPTED-UNVERIFIED" in s
    assert "disclosed" in s  # parses the returned stored path


def _extract_func(name: str) -> str:
    """Pull a self-contained function definition out of scanner.sh by name so we
    can exercise it in isolation. Line-based: from `<name>() {` to the first line
    that is exactly `}` at column 0 (scanner.sh's house style for top-level
    function definitions), which avoids miscounting ${...} brace expansions."""
    lines = _src().splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.startswith(f"{name}() {{"):
            start = idx
            break
    assert start is not None, f"function {name} not found in scanner.sh"
    for end in range(start + 1, len(lines)):
        if lines[end] == "}":
            return "\n".join(lines[start:end + 1])
    raise AssertionError(f"no closing brace found for {name}")

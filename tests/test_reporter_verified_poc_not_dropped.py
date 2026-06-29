"""reporter.py must NOT silently drop an empirically-VERIFIED time-based SQLi PoC.

timebased_candidates.txt was blacklisted file-wide in NON_FINDING_FILES, so a [SQLI-POC-VERIFIED]
line (a CONFIRMED CRITICAL) never reached the report while summary.txt still counted it — a false
negative on a confirmed finding. The per-line NON_FINDING_PREFIXES still suppress the unverified
[SQLI-CANDIDATE]/[SQLI-TIMEOUT-CANDIDATE] lines. (Audit CRITICAL.)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import reporter  # noqa: E402


def test_verified_timebased_poc_becomes_a_critical_finding(tmp_path):
    sqli = tmp_path / "sqli"
    sqli.mkdir()
    (sqli / "timebased_candidates.txt").write_text(
        "[SQLI-CANDIDATE] http://t.example.invalid/x?id=1 (unverified)\n"
        "[SQLI-TIMEOUT-CANDIDATE] http://t.example.invalid/y?q=2 slow\n"
        "[SQLI-POC-VERIFIED] http://t.example.invalid/api?id=1 :: time-based confirmed, dumped users.email\n"
    )
    findings = reporter.load_findings(str(tmp_path))
    blob = "\n".join(str(f) for f in findings).lower()

    # the VERIFIED PoC must surface as a finding ...
    verified = [f for f in findings if "verified" in str(f).lower() or "dumped users.email" in str(f).lower()]
    assert verified, "the verified time-based SQLi PoC was dropped from the report"
    # ... scored critical ...
    assert any("critical" in str(f).lower() for f in verified), "verified SQLi PoC not scored critical"
    # ... while the UNVERIFIED candidate lines stay suppressed
    assert "[sqli-candidate]" not in blob and "sqli-timeout-candidate" not in blob, \
        "unverified candidate lines leaked into the report"

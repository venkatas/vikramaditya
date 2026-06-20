"""Regression tests for the brain.py audit-fix batch (group B).

Covers:
  * fork-safety: watchdog_diagnose / bash -n scan-plan check / notify ping no longer
    use raw subprocess (fork()+exec SIGSEGVs on macOS once Network.framework loads).
  * confirmed-impact promotion: a grounded CONFIRMED: line from exploit_finding() is
    upgraded into the structured verdict AND a report-visible artifact.

All hosts are synthetic (*.example.invalid). No network, no real targets.
"""
import inspect
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import brain  # noqa: E402


# ── fork-safety: the three migrated sinks must not call raw subprocess ─────────
def test_watchdog_diagnose_uses_procutil_not_raw_subprocess():
    src = inspect.getsource(brain.Brain.watchdog_diagnose)
    assert "procutil.run_capture" in src, "watchdog probes must route through procutil"
    # the old raw-subprocess probe calls must be gone
    assert "_sp.run(" not in src, "watchdog_diagnose still uses raw _sp.run (fork()+exec)"
    assert "_sp.check_output(" not in src, "watchdog_diagnose still uses raw _sp.check_output"


def test_post_recon_hook_bash_n_uses_procutil():
    src = inspect.getsource(brain.Brain.post_recon_hook)
    assert "procutil._fork_safe_spawn" in src, "bash -n check must use the fork-safe spawner"
    assert '_sp.run(["bash"' not in src, "bash -n still uses raw subprocess.run"


def test_notify_ping_uses_procutil():
    src = inspect.getsource(brain.Brain.auto_triage_and_exploit)
    assert "procutil._fork_safe_spawn" in src, "notify ping must use the fork-safe spawner"
    assert "_sub.Popen(" not in src, "notify ping still uses raw subprocess.Popen"


# ── confirmed-impact promotion into the verdict + report artifact ──────────────
def test_confirmed_impact_promoted_into_verdict_and_artifact(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()

    b = brain.Brain.__new__(brain.Brain)
    b.enabled = True
    b.allow_exploit = True
    monkeypatch.setattr(b, "_target_from_artifact_dir", lambda d: "t.example.invalid", raising=False)
    monkeypatch.setattr(
        b, "_collect_candidate_findings",
        lambda d: [("SQL Injection", "https://t.example.invalid/api?id=1 injectable")],
        raising=False)
    monkeypatch.setattr(b, "triage_finding", lambda f: ("SUBMIT", "exploitable"), raising=False)

    # exploit_finding returns a grounded confirmed impact; also write the artifact
    # the real function would, so _build_report_evidence can pick it up.
    def _fake_exploit(**k):
        cp = Path(k["findings_dir"]) / "brain" / "confirmed_exploits.txt"
        cp.parent.mkdir(parents=True, exist_ok=True)
        cp.write_text("[CONFIRMED] SQL Injection @ https://t.example.invalid/api\n"
                      "  impact: dumped 3 rows from users table\n")
        return "# transcript", "dumped 3 rows from users table"

    monkeypatch.setattr(b, "exploit_finding", _fake_exploit, raising=False)

    results = b.auto_triage_and_exploit(str(findings_dir))
    # the SUBMIT verdict must have been upgraded to CONFIRMED
    confirmed = [r for r in results if r.get("verdict") == "CONFIRMED"]
    assert confirmed, f"grounded impact not promoted to CONFIRMED verdict: {results}"
    assert "dumped 3 rows" in confirmed[0]["reasoning"]

    # the artifact must exist and be readable by the report evidence builder
    art = findings_dir / "brain" / "confirmed_exploits.txt"
    assert art.exists()
    evidence = b._build_report_evidence(str(findings_dir))
    assert "Confirmed Exploit Impact" in evidence
    assert "dumped 3 rows" in evidence


def test_build_report_evidence_reads_confirmed_exploits(tmp_path):
    findings_dir = tmp_path / "findings"
    (findings_dir / "brain").mkdir(parents=True)
    (findings_dir / "brain" / "confirmed_exploits.txt").write_text(
        "[CONFIRMED] IDOR @ https://t.example.invalid/u/2\n  impact: read another user's PII\n")
    b = brain.Brain.__new__(brain.Brain)
    out = b._build_report_evidence(str(findings_dir))
    assert "Confirmed Exploit Impact" in out
    assert "another user" in out

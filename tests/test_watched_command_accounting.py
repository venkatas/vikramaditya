"""Real local subprocess outcomes must reach manifest, coverage and CLI status."""
from __future__ import annotations

import signal

import pytest

import hunt
import phase_manifest as pm


@pytest.fixture
def accounting(tmp_path, monkeypatch):
    class QuietWatchdog:
        killed = False
        blocked = False

        def __init__(self, *args, **kwargs):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(hunt, "ProcessWatchdog", QuietWatchdog)
    monkeypatch.setattr(hunt, "_tool_env", lambda: {})
    monkeypatch.setattr(hunt, "_session_cache_lookup", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_session_cache_store", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_LAST_FINDINGS_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "_brain", None)
    hunt._reset_degraded()
    try:
        yield tmp_path
    finally:
        hunt._terminate_all_active_groups()
        hunt._reset_degraded()


@pytest.mark.parametrize("exit_code", [0, 7, 127])
def test_real_watched_exit_updates_manifest_and_final_status(accounting, exit_code):
    ok, output = hunt.run_cmd(f"printf fixture-output; exit {exit_code}",
                              watch_file=str(accounting), watch_phase="REPORTS")
    assert ok is (exit_code == 0)
    assert output == "fixture-output"
    records = pm.read_manifest(str(accounting))["phases"]
    assert len(records) == 1 and records[0]["exit_code"] == exit_code
    assert records[0]["status"] == ("ran" if ok else "failed")
    result = {"success": True}
    hunt._finalize_assessment(result, str(accounting))
    assert result["success"] is ok
    assert result["assessment_status"] == ("complete" if ok else "inconclusive")
    if not ok:
        with pytest.raises(SystemExit) as exc:
            hunt._exit_for_assessment([result])
        assert exc.value.code == 2


def test_spawn_failure_is_not_an_unrecorded_false_return(accounting, monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("fixture spawn unavailable")

    monkeypatch.setattr(hunt, "_fork_safe_spawn", unavailable)
    ok, output = hunt.run_cmd("exit 0", watch_file=str(accounting), watch_phase="REPORTS")
    assert not ok and "spawn unavailable" in output
    assert pm.read_manifest(str(accounting))["phases"][0]["status"] == "failed"
    assert hunt._DEGRADED_CAPABILITIES


def test_timeout_retains_partial_output_and_aborted_manifest(accounting):
    ok, output = hunt.run_cmd("printf partial; sleep 5", timeout=0.1,
                              watch_file=str(accounting), watch_phase="REPORTS")
    assert not ok and "partial" in output
    record = pm.read_manifest(str(accounting))["phases"][0]
    assert record["timed_out"] and record["status"] == "aborted"


def test_interrupt_records_phase_before_raising(accounting, monkeypatch):
    import select

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(select, "select", interrupted)
    with pytest.raises(KeyboardInterrupt):
        hunt.run_cmd("sleep 5", watch_file=str(accounting), watch_phase="REPORTS")
    record = pm.read_manifest(str(accounting))["phases"][0]
    assert record["status"] == "aborted" and record["signal"] == signal.SIGINT


def test_failed_report_does_not_count_existing_markdown_as_fresh_completion(accounting, monkeypatch):
    reports = accounting / "reports"
    reports.mkdir()
    (reports / "stale.md").write_text("old report")
    monkeypatch.setattr(hunt, "_AUTHED_COOKIE", "")
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(accounting))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda *a, **k: str(reports))
    monkeypatch.setattr(hunt, "_target_state_path", lambda *a: str(accounting / "state.json"))
    actual_runner = hunt.run_cmd
    monkeypatch.setattr(hunt, "run_cmd", lambda cmd, **kwargs: actual_runner("exit 7", **kwargs))
    assert hunt.generate_reports("example.invalid") == 0
    assert pm.is_inconclusive(str(accounting))
    assert (reports / "stale.md").read_text() == "old report"


def test_recon_binds_findings_before_its_first_subprocess(accounting, monkeypatch):
    recon = accounting / "recon"
    findings = accounting / "findings"
    recon.mkdir()
    findings.mkdir()
    monkeypatch.setattr(hunt, "_LAST_FINDINGS_DIR", None)
    monkeypatch.setattr(hunt, "_activate_recon_session", lambda *a, **k: ("s1", str(recon)))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_adaptive_runtime_overrides", lambda *a, **k: {})

    def run_local(*args, **kwargs):
        assert hunt._LAST_FINDINGS_DIR == str(findings)
        hunt._record_phase_manifest("RECON", "fixture", 0, False, str(recon))
        return True

    monkeypatch.setattr(hunt, "run_live", run_local)
    assert hunt.run_recon("example.invalid")
    assert pm.read_manifest(str(findings))["phases"][0]["phase"] == "RECON"

"""Autonomous completion must retain the same coverage truth as the reports.

All scan functions are replaced with local fixture producers. No external tool,
model, or target is contacted by these tests.
"""
from __future__ import annotations

import json
import re
import sys
from types import SimpleNamespace

import pytest

import hunt
import phase_manifest as pm
import reporter


@pytest.fixture
def autonomous(tmp_path, monkeypatch):
    paths = [tmp_path / tree / "example.invalid" / "sessions" / "test"
             for tree in ("recon", "findings", "reports")]
    for path in paths:
        path.mkdir(parents=True)
    recon, findings, reports = paths
    state = SimpleNamespace(
        recon=recon, findings=findings, reports=reports,
        session_file=recon / "autonomous_session.json",
        completed=["recon"], steps=["scan"], scan_hook=None,
        report_hook=None, report_statuses=[], scan_calls=[],
    )
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "check_tool_readiness", lambda *a, **k: [])
    monkeypatch.setattr(hunt, "_activate_recon_session", lambda *a, **k: ("test", str(recon)))
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda *a, **k: str(reports))
    monkeypatch.setattr(hunt, "_active_recon_session_id", lambda *a: "test")
    monkeypatch.setattr(hunt, "_update_target_state_from_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_log_best_validation_targets", lambda *a, **k: None)

    def forbidden(*args, **kwargs):
        pytest.fail("autonomous status test launched an external phase")

    monkeypatch.setattr(hunt, "run_recon", forbidden)
    monkeypatch.setattr(hunt, "run_prioritize", forbidden)

    def load_session(*args, **kwargs):
        return {
            "target": "example.invalid", "session_id": "test",
            "session_file": str(state.session_file),
            "completed_steps": list(state.completed), "attempted_steps": [],
            "last_result": {},
        }

    def plan(*args, completed_steps, **kwargs):
        return {}, [{"step": step, "reason": "fixture coverage"}
                    for step in state.steps if step not in completed_steps]

    def scan(*args, **kwargs):
        state.scan_calls.append(True)
        pm.record_phase(str(findings), "VULN SCAN", exit_code=0,
                        artifact_counts={"findings": 0})
        if state.scan_hook:
            state.scan_hook()
        return True

    def generate_reports(*args, **kwargs):
        state.report_statuses.append(pm.assessment_status(str(findings)))
        if state.report_hook:
            state.report_hook()
        return 1

    monkeypatch.setattr(hunt, "_load_autonomous_session", load_session)
    monkeypatch.setattr(hunt, "_build_autonomous_plan", plan)
    monkeypatch.setattr(hunt, "run_vuln_scan", scan)
    monkeypatch.setattr(hunt, "generate_reports", generate_reports)
    hunt._reset_degraded()
    try:
        yield state
    finally:
        hunt._reset_degraded()


def _persist_gap(state, source):
    if source == "recon":
        (state.recon / "coverage_degraded.json").write_text(json.dumps([
            {"tool": "browser", "reason": "guarded rendering only"}]))
    elif source == "scanner":
        (state.findings / "manual_review").mkdir()
        (state.findings / "manual_review" / "coverage_gaps.txt").write_text(
            "[COVERAGE-GAP] nuclei: templates unavailable\n")
    elif source == "canonical":
        (state.findings / "coverage.json").write_text(json.dumps([
            {"source": "hunt", "tool_or_phase": "gf",
             "reason": "patterns unavailable", "status": "degraded"}]))
    elif source == "manifest":
        pm.record_phase(str(state.findings), "CVE HUNT", exit_code=0,
                        timed_out=True)


def _assert_result_and_saved_session(state, result, inconclusive):
    expected = "inconclusive" if inconclusive else "complete"
    assert result["success"] is not inconclusive
    assert result["assessment_status"] == expected
    assert result["session_id"] == "test"
    saved = json.loads(state.session_file.read_text())["last_result"]
    assert saved["success"] is result["success"]
    assert saved["assessment_status"] == expected
    assert saved["reports"] == result["reports"]
    if inconclusive:
        with pytest.raises(SystemExit) as exc:
            hunt._exit_for_assessment([result])
        assert exc.value.code == 2
    else:
        hunt._exit_for_assessment([result])


@pytest.mark.parametrize("source", ["recon", "scanner", "canonical", "manifest", "none"])
@pytest.mark.parametrize("resume_without_steps", [False, True])
def test_autonomous_persisted_coverage_matches_report_cli_and_saved_result(
        autonomous, capsys, source, resume_without_steps):
    state = autonomous
    _persist_gap(state, source)
    if resume_without_steps:
        state.completed = ["recon", "scan"]
    result = hunt.run_autonomous_hunt(
        "example.invalid", resume=resume_without_steps, scope_lock=True)
    inconclusive = source != "none"
    _assert_result_and_saved_session(state, result, inconclusive)
    assert len(state.scan_calls) == (0 if resume_without_steps else 1)
    if not resume_without_steps:
        assert state.report_statuses == ["inconclusive" if inconclusive else "complete"]
    for directory in (state.recon, state.findings, state.reports):
        for rendered in (
                reporter._render_coverage_limitations_md(str(directory)),
                reporter._render_coverage_limitations_html(str(directory))):
            assert ("INCONCLUSIVE" in rendered) == inconclusive
    hunt.print_dashboard([result])
    dashboard = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
    assert ("[INCONCLUSIVE] example.invalid" in dashboard) == inconclusive
    if source in {"recon", "scanner", "canonical"}:
        rows = json.loads((state.findings / "coverage.json").read_text())
        assert rows, "autonomous finalization erased recorded coverage gaps"


@pytest.mark.parametrize("unwritable", [False, True])
def test_autonomous_in_memory_coverage_survives_failed_persistence(
        autonomous, monkeypatch, unwritable):
    state = autonomous
    state.scan_hook = lambda: hunt._mark_degraded("gf", "patterns unavailable")
    if unwritable:
        monkeypatch.setattr(hunt, "write_coverage_json", lambda *a, **k: None)
    result = hunt.run_autonomous_hunt("example.invalid", scope_lock=True)
    _assert_result_and_saved_session(state, result, True)
    # A file-only reporter cannot see an unwritten memory-only limitation.
    if not unwritable:
        assert state.report_statuses == ["inconclusive"]


def test_autonomous_does_not_inherit_another_targets_in_memory_gaps(autonomous):
    hunt._mark_degraded("other-target", "missing tool for a previous target")
    result = hunt.run_autonomous_hunt("example.invalid", scope_lock=True)
    _assert_result_and_saved_session(autonomous, result, False)
    assert pm.assessment_status(str(autonomous.findings)) == "complete"


@pytest.mark.parametrize("source", ["memory", "manifest"])
def test_autonomous_report_created_gap_is_folded_into_saved_final_result(autonomous, source):
    state = autonomous
    if source == "memory":
        state.report_hook = lambda: hunt._mark_degraded("report", "report renderer failed")
    else:
        state.report_hook = lambda: pm.record_phase(str(state.findings), "REPORTS", exit_code=1)
    result = hunt.run_autonomous_hunt("example.invalid", scope_lock=True)
    assert state.report_statuses == ["complete"]
    _assert_result_and_saved_session(state, result, True)
    assert pm.assessment_status(str(state.findings)) == "inconclusive"


def test_autonomous_keeps_prior_canonical_gap_when_merge_cannot_persist(
        autonomous, monkeypatch):
    state = autonomous
    _persist_gap(state, "canonical")

    def merge_without_write(findings_dir, *, prior_rows=None):
        # merge_coverage returns its rows even when its final write fails. The
        # earlier raw writer may already have replaced canonical-only evidence.
        return pm.collect_coverage(findings_dir) + list(prior_rows or [])

    monkeypatch.setattr(pm, "merge_coverage", merge_without_write)
    result = hunt.run_autonomous_hunt("example.invalid", scope_lock=True)
    _assert_result_and_saved_session(state, result, True)


def test_autonomous_recon_failure_persists_final_result(autonomous, monkeypatch):
    state = autonomous
    state.completed = []
    monkeypatch.setattr(hunt, "run_recon", lambda *a, **k: False)
    result = hunt.run_autonomous_hunt("example.invalid", scope_lock=True)
    _assert_result_and_saved_session(state, result, True)
    assert not state.scan_calls and not state.report_statuses


@pytest.mark.parametrize("mode", ["autonomous", "synchronous"])
@pytest.mark.parametrize("preflight", ["auth", "wordlists", "clean"])
def test_main_preserves_current_preflight_gaps_but_not_previous_invocation_gaps(
        autonomous, monkeypatch, mode, preflight):
    """Exercise parse/preflight/real dispatch/CLI exit, not a mocked dispatcher."""
    state = autonomous
    wordlists = state.recon.parent / "wordlists"
    wordlists.mkdir()
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(wordlists))
    monkeypatch.setattr(hunt, "check_tools", lambda: ([], []))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: (
        ["sqli-payloads.txt"] if preflight == "wordlists" else []))
    monkeypatch.setattr(hunt, "_verify_authenticated", lambda *a, **k: (
        False, "expired fixture cookie", ""))
    monkeypatch.setattr(hunt, "_enrich_targets_with_whitebox_asset_feed", lambda *a, **k: [])
    # main() assigns these globals; monkeypatch restores their prior values.
    monkeypatch.setattr(hunt, "_AUTHED_COOKIE", "")
    monkeypatch.setattr(hunt, "_SEED_URLS", [])
    monkeypatch.setattr(hunt, "ASSESS_CREDS", False)

    def cors(*args, **kwargs):
        pm.record_phase(str(state.findings), "CORS", exit_code=0,
                        artifact_counts={"findings": 0})
        return True

    monkeypatch.setattr(hunt, "run_cors_check", cors)
    argv = ["hunt.py", "--target", "example.invalid", "--scope-lock", "--no-brain",
            "--no-auto-install-tools"]
    if mode == "autonomous":
        argv.append("--autonomous")
    else:
        argv += ["--cors-check", "--resume", "test", "--skip", "nextjs_bypass,email_audit"]
    if preflight == "auth":
        argv += ["--cookie", "session=expired"]
    monkeypatch.setattr(sys, "argv", argv)

    results = []
    exit_for_assessment = hunt._exit_for_assessment

    def capture_exit(value):
        results.extend(value)
        return exit_for_assessment(value)

    monkeypatch.setattr(hunt, "_exit_for_assessment", capture_exit)
    hunt._mark_degraded("previous-invocation", "must not reach the new session")
    inconclusive = preflight != "clean"
    if inconclusive:
        with pytest.raises(SystemExit) as exc:
            hunt.main()
        assert exc.value.code == 2
    else:
        hunt.main()

    assert len(results) == 1
    result = results[0]
    assert result["success"] is not inconclusive
    assert result["assessment_status"] == ("inconclusive" if inconclusive else "complete")
    rows = pm.collect_coverage(str(state.findings))
    tools = {row["tool_or_phase"] for row in rows}
    assert "previous-invocation" not in tools
    if inconclusive:
        assert preflight in tools
    for rendered in (
            reporter._render_coverage_limitations_md(str(state.findings)),
            reporter._render_coverage_limitations_html(str(state.findings))):
        assert ("INCONCLUSIVE" in rendered) == inconclusive
    if mode == "autonomous":
        saved = json.loads(state.session_file.read_text())["last_result"]
        assert saved["assessment_status"] == result["assessment_status"]
        assert saved["success"] is result["success"]
        assert state.report_statuses == [result["assessment_status"]]
    else:
        assert not state.scan_calls, "targeted sync test unexpectedly launched a scan"


def test_direct_autonomous_initial_coverage_is_retained_without_mutation(autonomous):
    initial = [{"tool": "auth", "reason": "current invocation's cookie expired"}]
    before = [dict(row) for row in initial]
    hunt._mark_degraded("other-target", "unrelated target's missing tool")
    result = hunt.run_autonomous_hunt(
        "example.invalid", scope_lock=True, initial_coverage=initial)
    _assert_result_and_saved_session(autonomous, result, True)
    assert initial == before
    tools = {row["tool_or_phase"] for row in pm.collect_coverage(str(autonomous.findings))}
    assert "auth" in tools and "other-target" not in tools

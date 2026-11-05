"""Shared assessment finalization stays conservative without counting findings."""
from __future__ import annotations

import json

import pytest

import hunt
import phase_manifest as pm


@pytest.fixture(autouse=True)
def isolated_coverage():
    hunt._reset_degraded()
    try:
        yield
    finally:
        hunt._reset_degraded()


@pytest.mark.parametrize("result", [
    {"success": False},
    {"success": True, "assessment_status": "inconclusive"},
    *({"success": True, "phase_status": {"scan": status}}
      for status in ("failed", "aborted", "error", "partial")),
])
def test_explicit_failure_is_retained_and_visible_to_file_only_reporter(tmp_path, result):
    hunt._finalize_assessment(result, str(tmp_path))
    assert result["success"] is False
    assert result["assessment_status"] == "inconclusive"
    assert pm.assessment_status(str(tmp_path)) == "inconclusive"
    rows = json.loads((tmp_path / "coverage.json").read_text())
    assert rows and rows[0]["tool_or_phase"] == "assessment"


@pytest.mark.parametrize("failure", ["read", "write_none", "write_exception", "merge", "status"])
def test_coverage_io_failure_cannot_become_a_clean_result(tmp_path, monkeypatch, failure):
    def broken(*args, **kwargs):
        raise OSError("fixture coverage storage unavailable")

    if failure == "read":
        monkeypatch.setattr(pm, "collect_coverage", broken)
    elif failure == "write_none":
        monkeypatch.setattr(hunt, "write_coverage_json", lambda *a, **k: None)
    elif failure == "write_exception":
        monkeypatch.setattr(hunt, "write_coverage_json", broken)
    elif failure == "merge":
        monkeypatch.setattr(pm, "merge_coverage", broken)
    else:
        monkeypatch.setattr(pm, "assessment_status", broken)
    result = {"success": True}
    hunt._finalize_assessment(result, str(tmp_path))
    assert result == {"success": False, "assessment_status": "inconclusive"}
    assert any(row["tool"] == "coverage" for row in hunt._DEGRADED_CAPABILITIES)


def test_repeated_finalization_is_idempotent_and_keeps_prior_coverage(tmp_path):
    prior = {"source": "test", "tool_or_phase": "nuclei",
             "reason": "template coverage incomplete", "status": "degraded"}
    (tmp_path / "coverage.json").write_text(json.dumps([prior]))
    result = {"success": True}
    hunt._finalize_assessment(result, str(tmp_path))
    first = (tmp_path / "coverage.json").read_text()
    hunt._finalize_assessment(result, str(tmp_path))
    assert (tmp_path / "coverage.json").read_text() == first
    assert json.loads(first) == [prior]


def test_successful_zero_finding_phase_remains_complete(tmp_path):
    pm.record_phase(str(tmp_path), "scan", exit_code=0,
                    artifact_counts={"findings": 0})
    result = {"success": True, "scan": False, "phase_status": {"scan": "skipped"}}
    hunt._finalize_assessment(result, str(tmp_path))
    assert result["success"] is True
    assert result["assessment_status"] == "complete"
    assert json.loads((tmp_path / "coverage.json").read_text()) == []


@pytest.mark.parametrize("late_failure", ["memory", "manifest"])
def test_synchronous_pipeline_folds_failures_recorded_during_report_generation(
        tmp_path, monkeypatch, late_failure):
    recon, findings, reports = [
        tmp_path / tree / "example.invalid" / "sessions" / "test"
        for tree in ("recon", "findings", "reports")]
    for path in (recon, findings, reports):
        path.mkdir(parents=True)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "check_tool_readiness", lambda: [])
    monkeypatch.setattr(hunt, "_activate_recon_session", lambda *a, **k: ("test", str(recon)))
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda *a, **k: str(reports))
    monkeypatch.setattr(hunt, "_active_recon_session_id", lambda *a: "test")
    monkeypatch.setattr(hunt, "_enrich_targets_with_whitebox_asset_feed", lambda *a, **k: [])
    monkeypatch.setattr(hunt, "run_cors_check", lambda *a, **k: True)

    def forbidden(*args, **kwargs):
        pytest.fail("status finalization launched an unrequested active phase")

    monkeypatch.setattr(hunt, "run_recon", forbidden)
    monkeypatch.setattr(hunt, "run_vuln_scan", forbidden)

    def render(*args, **kwargs):
        assert pm.assessment_status(str(findings)) == "complete"
        if late_failure == "memory":
            hunt._mark_degraded("reports", "fixture renderer failed")
        else:
            pm.record_phase(str(findings), "REPORTS", exit_code=1)
        return 0

    monkeypatch.setattr(hunt, "generate_reports", render)
    result = hunt.hunt_target(
        "example.invalid", cors_check=True, scan_only=True, skip_scan=True,
        resume_session_id="test", skip_items={"nextjs_bypass", "email_audit"})
    assert result["success"] is False
    assert result["assessment_status"] == "inconclusive"
    assert pm.assessment_status(str(findings)) == "inconclusive"
    with pytest.raises(SystemExit) as exc:
        hunt._exit_for_assessment([result])
    assert exc.value.code == 2

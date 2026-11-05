"""Persisted coverage must drive the same report, dashboard and CLI outcome."""
from __future__ import annotations

import json
import re

import pytest

import hunt
import phase_manifest as pm
import reporter


def _session(tmp_path):
    paths = [tmp_path / tree / "example.invalid" / "sessions" / "test"
             for tree in ("recon", "findings", "reports")]
    for path in paths:
        path.mkdir(parents=True)
    return paths


def _gap(recon, findings, source):
    if source == "recon":
        (recon / "coverage_degraded.json").write_text(json.dumps([
            {"tool": "browser", "reason": "exact-scope rendering only"}]))
    elif source == "scanner":
        (findings / "manual_review").mkdir()
        (findings / "manual_review" / "coverage_gaps.txt").write_text(
            "[COVERAGE-GAP] nuclei: templates unavailable\n")
    elif source == "canonical":
        (findings / "coverage.json").write_text(json.dumps([
            {"source": "hunt", "tool_or_phase": "gf", "reason": "patterns unavailable",
             "status": "degraded"}]))
    elif source == "manifest":
        pm.record_phase(str(findings), "browser", exit_code=0, degraded=True)


@pytest.mark.parametrize("source", ["recon", "scanner", "canonical", "manifest",
                                    "memory", "memory_unwritable", "none"])
@pytest.mark.parametrize("phase_has_result", [False, True])
def test_real_targeted_resume_finalization_matches_report_dashboard_and_cli(
        tmp_path, monkeypatch, capsys, source, phase_has_result):
    recon, findings, reports = _session(tmp_path)
    _gap(recon, findings, source)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "check_tool_readiness", lambda: [])
    monkeypatch.setattr(hunt, "_activate_recon_session", lambda *a, **k: ("test", str(recon)))
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda *a, **k: str(reports))
    monkeypatch.setattr(hunt, "_active_recon_session_id", lambda *a: "test")
    monkeypatch.setattr(hunt, "_enrich_targets_with_whitebox_asset_feed", lambda *a, **k: [])

    def forbidden(*args, **kwargs):
        pytest.fail("targeted resume launched an unrequested phase")

    monkeypatch.setattr(hunt, "run_recon", forbidden)
    monkeypatch.setattr(hunt, "run_vuln_scan", forbidden)
    monkeypatch.setattr(hunt, "generate_reports", forbidden)
    if source == "memory_unwritable":
        monkeypatch.setattr(hunt, "write_coverage_json", lambda *a: None)

    def completed_zero_result(*args, **kwargs):
        if source.startswith("memory"):
            hunt._mark_degraded("gf", "patterns unavailable")
        pm.record_phase(str(findings), "cors", exit_code=0, artifact_counts={"findings": 0})
        return phase_has_result

    monkeypatch.setattr(hunt, "run_cors_check", completed_zero_result)
    try:
        result = hunt.hunt_target(
            "example.invalid", cors_check=True, resume_session_id="test",
            skip_items={"nextjs_bypass", "email_audit"})
        expected = source != "none"
        assert result["success"] is not expected
        assert result["assessment_status"] == ("inconclusive" if expected else "complete")
        assert result["session_id"] == "test" and result["recon"] is False
        for entry in (findings, reports, recon):
            for text in (reporter._render_coverage_limitations_md(str(entry)),
                         reporter._render_coverage_limitations_html(str(entry))):
                # A failed write cannot teach the file-only reporter about an
                # in-memory gap; the CLI must still retain its failure signal.
                assert ("INCONCLUSIVE" in text) == (expected and source != "memory_unwritable")
        hunt.print_dashboard([result])
        dashboard = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
        assert ("[INCONCLUSIVE] example.invalid" in dashboard) == expected
        assert ("[OK] example.invalid" in dashboard) != expected
        if expected:
            with pytest.raises(SystemExit) as exc:
                hunt._exit_for_assessment([result])
            assert exc.value.code == 2
        else:
            hunt._exit_for_assessment([result])
    finally:
        hunt._reset_degraded()


@pytest.mark.parametrize("status", ["degraded", "failed", "aborted", "ran", "skipped"])
def test_shared_assessment_status_uses_reporter_coverage_status_semantics(tmp_path, status):
    recon, findings, reports = _session(tmp_path)
    (findings / "coverage.json").write_text(json.dumps([
        {"source": "test", "tool_or_phase": "tool", "reason": "coverage note", "status": status}]))
    expected = "inconclusive" if status in {"degraded", "failed", "aborted"} else "complete"
    for entry in (findings, recon, reports):
        assert pm.assessment_status(str(entry)) == expected
    assert not pm.is_inconclusive(str(findings)), "manifest-only public helper changed meaning"

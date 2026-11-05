"""Local regressions for producer exits, invocation state and honest dashboards."""
from __future__ import annotations

import json
import re
import shlex
from types import SimpleNamespace

import pytest

import hunt
import phase_manifest as pm


@pytest.fixture
def local_session(tmp_path, monkeypatch):
    recon, findings, reports = [tmp_path / tree / "example.invalid" / "sessions" / "s1"
                                for tree in ("recon", "findings", "reports")]
    for path in (recon, findings, reports):
        path.mkdir(parents=True)
    (recon / "live").mkdir()
    (recon / "params").mkdir()
    (recon / "live/urls.txt").write_text("https://example.invalid\n")
    (recon / "live/httpx_full.txt").write_text(
        "https://example.invalid [200] [348] [192.0.2.1] [IIS:10.0]\n")
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    monkeypatch.delenv("SCOPE_LOCK", raising=False)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_SEED_URLS", [])
    monkeypatch.setattr(hunt, "check_tool_readiness", lambda: [])
    monkeypatch.setattr(hunt, "_LAST_FINDINGS_DIR", str(findings))
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda *a, **k: str(reports))
    monkeypatch.setattr(hunt, "_active_recon_session_id", lambda *a: "s1")
    monkeypatch.setattr(hunt, "_activate_recon_session", lambda *a, **k: ("s1", str(recon)))
    monkeypatch.setattr(hunt, "_enrich_targets_with_whitebox_asset_feed", lambda *a, **k: [])
    monkeypatch.setattr(hunt, "_session_cache_lookup", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_session_cache_store", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_tool_env", lambda: {})

    class QuietWatchdog:
        killed = blocked = False
        def __init__(self, *a, **k): pass
        def stop(self): pass

    monkeypatch.setattr(hunt, "ProcessWatchdog", QuietWatchdog)
    hunt._reset_degraded()
    try:
        yield SimpleNamespace(recon=recon, findings=findings, reports=reports)
    finally:
        hunt._terminate_all_active_groups()
        hunt._reset_degraded()


@pytest.mark.parametrize("exit_code", [0, 7, 127])
def test_real_pipeline_preserves_producer_exit_and_partial_evidence(local_session, exit_code):
    artifact = local_session.recon / "partial output.txt"
    command = f"(printf fixture-output; exit {exit_code}) | /usr/bin/tee {shlex.quote(str(artifact))}"
    ok, output = hunt.run_cmd(command, watch_file=str(artifact), watch_phase="SECRET HUNT")
    assert ok is (exit_code == 0)
    assert output == artifact.read_text() == "fixture-output"
    record = pm.read_manifest(str(local_session.findings))["phases"][-1]
    assert record["command"] == command and record["exit_code"] == exit_code
    result = {"success": True, "secret_hunt": ok, "phase_requested": {"secret_hunt": True}}
    hunt._finalize_assessment(result, str(local_session.findings))
    assert result["assessment_status"] == ("complete" if ok else "inconclusive")
    assert result["phase_status"]["secret_hunt"] == ("ran" if ok else "failed")


def test_middle_pipeline_failure_survives_successful_final_tee(local_session):
    ok, output = hunt.run_cmd(
        "printf partial | (/bin/cat; exit 7) | /usr/bin/tee /dev/null",
        watch_file=str(local_session.recon), watch_phase="SECRET HUNT")
    assert not ok and output == "partial"
    assert pm.read_manifest(str(local_session.findings))["phases"][-1]["exit_code"] == 7


def test_empty_success_and_quoted_shell_metacharacters_remain_valid(local_session):
    for command, expected in (("printf '' | /usr/bin/tee /dev/null", ""),
                              ("printf '%s' 'literal | $(not-a-command); text'", "literal | $(not-a-command); text")):
        ok, output = hunt.run_cmd(command, cwd=str(local_session.recon),
                                  watch_file=str(local_session.recon), watch_phase="SECRET HUNT")
        assert ok and output == expected
    assert not hunt._DEGRADED_CAPABILITIES


def test_optional_unwatched_nonzero_probe_does_not_become_assessment_failure(local_session):
    assert hunt.run_cmd("exit 1") == (False, "")
    assert not hunt._DEGRADED_CAPABILITIES
    assert pm.read_manifest(str(local_session.findings))["phases"] == []


@pytest.mark.parametrize("produced", [False, True])
def test_get_cap_is_error_or_partial_not_clean(local_session, produced):
    result = {"param_discovery": produced, "phase_requested": {"param_discovery": True}}
    hunt._mark_degraded("arjun", "URL surface capped: probed 5 of 23 candidate URLs")
    hunt._update_phase_status(result, str(local_session.findings))
    assert result["phase_status"]["param_discovery"] == ("partial" if produced else "error")


def test_post_failure_does_not_relabel_successful_uncapped_get_probe(local_session):
    result = {"param_discovery": True, "post_params": False,
              "phase_requested": {"param_discovery": True, "post_params": True}}
    hunt._mark_degraded("arjun", "POST parameter discovery command failed or timed out")
    hunt._update_phase_status(result, str(local_session.findings))
    assert result["phase_status"] == {"param_discovery": "ran", "post_params": "error"}


def test_persisted_recon_and_nested_api_gaps_affect_their_phases(local_session):
    (local_session.recon / "coverage_degraded.json").write_text(json.dumps([
        {"tool": "gf", "reason": "pattern matcher unavailable"}]))
    (local_session.recon / "api_specs").mkdir()
    (local_session.recon / "api_specs/coverage.json").write_text(json.dumps([
        {"source": "api_audit", "tool_or_phase": "api_audit", "reason": "request failed", "status": "degraded"}]))
    result = {"recon": True, "api_fuzz": True, "phase_requested": {"recon": True, "api_fuzz": True}}
    hunt._update_phase_status(result, str(local_session.findings))
    assert result["phase_status"] == {"recon": "partial", "api_fuzz": "partial"}


@pytest.mark.parametrize("phase,name,exit_code,expected", [
    ("api_fuzz", "API FUZZ", 7, "failed"),
    ("scan", "VULN SCAN (Batch 1/2)", -9, "aborted"),
])
def test_manifest_failure_overrides_truthy_legacy_return(local_session, phase, name, exit_code, expected):
    pm.record_phase(str(local_session.findings), name, exit_code=exit_code)
    result = {phase: True, "phase_requested": {phase: True}}
    hunt._update_phase_status(result, str(local_session.findings))
    assert result["phase_status"][phase] == expected


def test_legacy_optimistic_status_cannot_override_failed_exit(local_session):
    pm.record_phase(str(local_session.findings), "API FUZZ", exit_code=7, status="ran")
    result = {"api_fuzz": True, "phase_requested": {"api_fuzz": True}}
    hunt._update_phase_status(result, str(local_session.findings))
    assert result["phase_status"]["api_fuzz"] == "failed"


def test_requested_false_and_prefix_collisions_do_not_create_phase_execution(local_session):
    result = {"scan": True, "api_fuzz": True, "phase_requested": {"scan": True, "api_fuzz": False}}
    hunt._mark_degraded("scanner.sh", "unrelated artifact producer label")
    hunt._update_phase_status(result, str(local_session.findings))
    assert result["phase_status"] == {"scan": "ran", "api_fuzz": "skipped"}


def test_actual_nonapplicable_rce_is_skipped_without_becoming_retry_failure(local_session, monkeypatch):
    monkeypatch.setattr(hunt, "run_cmd", lambda *a, **k: (True, ""))
    assert hunt.run_rce_scan("example.invalid") is True
    result = {"success": True, "rce_scan": True, "phase_requested": {"rce_scan": True}}
    hunt._finalize_assessment(result, str(local_session.findings))
    assert result["phase_status"]["rce_scan"] == "skipped"
    assert result["assessment_status"] == "complete"


def test_actual_targeted_dashboard_shows_get_cap(local_session, monkeypatch, capsys):
    def parameters(*a, **k):
        hunt._mark_degraded("arjun", "URL surface capped: probed 5 of 23 candidate URLs")
        return True
    monkeypatch.setattr(hunt, "run_param_discovery", parameters)
    result = hunt.hunt_target("example.invalid", param_discover=True, resume_session_id="s1",
                              skip_items={"nextjs_bypass", "email_audit"})
    assert result["phase_status"]["param_discovery"] == "partial"
    assert result["assessment_status"] == "inconclusive"
    hunt.print_dashboard([result])
    text = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
    assert "Params⚠" in text and "Params✓" not in text


def test_actual_hunt_post_failure_is_attempted_once_per_invocation(local_session, monkeypatch):
    calls = []
    monkeypatch.setattr(hunt, "_tool_bin", lambda name: name)
    monkeypatch.setattr(hunt, "_which", lambda name: name == "sqlmap")
    def failed_post(*a, **k):
        calls.append("post")
        hunt._mark_degraded("arjun", "POST parameter discovery command failed or timed out")
        return False
    monkeypatch.setattr(hunt, "run_post_param_discovery", failed_post)
    for invocation in range(2):
        result = hunt.hunt_target("example.invalid", sqlmap_scan=True, post_param_discover=True,
                                  resume_session_id="s1", skip_items={"nextjs_bypass", "email_audit"})
        assert len(calls) == invocation + 1
        assert result["phase_status"]["post_params"] == "error"
        assert result["assessment_status"] == "inconclusive"
        assert not (local_session.recon / "params/post_params_done.marker").exists()


def test_explicit_post_skip_also_disables_sqlmap_post_preflight(local_session, monkeypatch):
    monkeypatch.setattr(hunt, "_tool_bin", lambda name: name)
    monkeypatch.setattr(hunt, "_which", lambda name: name == "sqlmap")
    def forbidden(*a, **k): pytest.fail("--skip post_params invoked POST discovery")
    monkeypatch.setattr(hunt, "run_post_param_discovery", forbidden)
    result = hunt.hunt_target("example.invalid", sqlmap_scan=True, resume_session_id="s1",
                              skip_items={"post_params", "nextjs_bypass", "email_audit"})
    assert result["phase_requested"]["post_params"] is False


@pytest.mark.parametrize("succeeded", [True, False])
def test_synchronous_scan_consumes_pending_core_only_on_success(local_session, monkeypatch, succeeded):
    (local_session.recon / "api").mkdir()
    (local_session.recon / "api/discovery_feedback.json").write_text(json.dumps({
        "pending_consumers": ["scan", "param_discovery"]}))
    monkeypatch.setattr(hunt, "run_api_fuzz", lambda *a, **k: True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *a, **k: succeeded)
    hunt.hunt_target("example.invalid", scan_only=True, api_fuzz=True, resume_session_id="s1",
                     skip_items={"auth_bypass", "xxe_hunt", "open_redirect_hunt", "saml_xsw",
                                 "actuator_probe", "ldap_injection", "nextjs_bypass", "email_audit", "reports"})
    expected = {"param_discovery"} if succeeded else {"scan", "param_discovery"}
    assert hunt._api_pending_consumers("example.invalid") == expected

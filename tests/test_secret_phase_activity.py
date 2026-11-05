"""Secret-scan activity must not be invented from missing tools or old evidence."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import cred_blast_radius
import hunt
import phase_manifest as pm


@pytest.fixture
def secret_session(tmp_path, monkeypatch):
    recon = tmp_path / "recon/example.invalid/sessions/s1"
    findings = tmp_path / "findings/example.invalid/sessions/s1"
    recon.mkdir(parents=True)
    findings.mkdir(parents=True)
    state = SimpleNamespace(recon=recon, findings=findings, installed=set(), configured=True,
                            calls=[], results={}, completions=[], passive_calls=[])
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_tool_bin", lambda name: name)
    monkeypatch.setattr(hunt, "_which", lambda name: name in state.installed)
    monkeypatch.setattr(hunt, "_githound_config_candidates", lambda: [])
    monkeypatch.setattr(hunt, "_githound_config_ready", lambda *a: state.configured)
    monkeypatch.setattr(hunt, "_brain_phase_complete", lambda *a, **k: state.completions.append((a, k)))
    monkeypatch.setattr(hunt, "ASSESS_CREDS", False)

    def passive(*args, **kwargs):
        state.passive_calls.append((args, kwargs))
        assert kwargs["active"] is False
        return None

    monkeypatch.setattr(cred_blast_radius, "run", passive)

    def command(cmd, **kwargs):
        engine = "trufflehog" if cmd.startswith("trufflehog ") else "git-hound"
        assert engine in state.installed
        state.calls.append(engine)
        ok, output = state.results.get(engine, (True, ""))
        filename = "trufflehog_recon.json" if engine == "trufflehog" else "githound.txt"
        (recon / "secrets" / filename).write_text(output)
        pm.record_phase(str(findings), "SECRET HUNT", command=cmd, exit_code=0 if ok else 7)
        return ok, output

    monkeypatch.setattr(hunt, "run_cmd", command)
    hunt._reset_degraded()
    try:
        yield state
    finally:
        hunt._reset_degraded()


def _run(state):
    ok = hunt.run_secret_hunt("example.invalid")
    result = {"success": True, "secret_hunt": ok,
              "phase_requested": {"secret_hunt": True}}
    hunt._finalize_assessment(result, str(state.findings))
    return ok, result, pm.read_manifest(str(state.findings))["phases"]


def test_both_missing_engines_record_no_invocation_and_incomplete_coverage(secret_session):
    state = secret_session
    ok, result, phases = _run(state)
    assert ok is False and state.calls == []
    assert len(phases) == 1 and phases[0]["status"] == "skipped"
    assert phases[0]["artifact_counts"] == {"attempted_engines": 0, "successful_engines": 0}
    assert result["assessment_status"] == "inconclusive"
    assert result["phase_status"]["secret_hunt"] == "error"
    assert {row["tool"] for row in hunt._DEGRADED_CAPABILITIES} == {"trufflehog", "git-hound"}
    assert len(state.passive_calls) == 1  # passive reporting is not engine activity


def test_unconfigured_only_engine_is_not_treated_as_successful_scan(secret_session):
    state = secret_session
    state.installed = {"git-hound"}
    state.configured = False
    ok, result, phases = _run(state)
    assert not ok and not state.calls
    assert phases[-1]["status"] == "skipped"
    assert result["phase_status"]["secret_hunt"] == "error"
    assert result["assessment_status"] == "inconclusive"


def test_zero_exit_authentication_error_has_no_usable_engine_success(secret_session):
    state = secret_session
    state.installed = {"git-hound"}
    state.results["git-hound"] = (True, "[!] authentication failed\n")
    ok, result, phases = _run(state)
    assert not ok and state.calls == ["git-hound"]
    assert phases[0]["status"] == "ran"  # raw process exit remains factual
    assert phases[-1]["status"] == "failed"  # semantic scanner outcome is authoritative
    assert phases[-1]["artifact_counts"] == {"attempted_engines": 1, "successful_engines": 0}
    assert result["phase_status"]["secret_hunt"] == "failed"
    assert result["assessment_status"] == "inconclusive"


@pytest.mark.parametrize("unavailable", ["missing", "unconfigured"])
def test_one_completed_engine_and_unavailable_peer_are_useful_partial_coverage(secret_session, unavailable):
    state = secret_session
    state.installed = {"trufflehog"} if unavailable == "missing" else {"trufflehog", "git-hound"}
    state.configured = unavailable != "unconfigured"
    ok, result, phases = _run(state)
    assert ok and state.calls == ["trufflehog"]
    assert all(phase["status"] == "ran" for phase in phases)
    assert result["phase_status"]["secret_hunt"] == "partial"
    assert result["assessment_status"] == "inconclusive"


def test_successful_zero_result_engines_are_valid_complete_activity(secret_session):
    state = secret_session
    state.installed = {"trufflehog", "git-hound"}
    ok, result, phases = _run(state)
    assert ok and state.calls == ["trufflehog", "git-hound"]
    assert len(phases) == 2 and all(phase["status"] == "ran" for phase in phases)
    assert result["phase_status"]["secret_hunt"] == "ran"
    assert result["assessment_status"] == "complete"
    assert not hunt._DEGRADED_CAPABILITIES


def test_command_failure_preserves_partial_artifacts_without_becoming_success(secret_session):
    state = secret_session
    state.installed = {"trufflehog", "git-hound"}
    partial = '{"DetectorName":"Fixture","Verified":false}\n'
    state.results["trufflehog"] = (False, partial)
    ok, result, phases = _run(state)
    assert not ok and state.calls == ["trufflehog", "git-hound"]
    assert (state.recon / "secrets/trufflehog_recon.json").read_text() == partial
    assert phases[0]["status"] == "failed" and phases[1]["status"] == "ran"
    assert result["phase_status"]["secret_hunt"] == "failed"
    assert result["assessment_status"] == "inconclusive"


def test_stale_secret_artifacts_and_passive_evidence_do_not_invent_scan_activity(secret_session, monkeypatch):
    state = secret_session
    (state.recon / "secrets").mkdir()
    stale = state.recon / "secrets/trufflehog_recon.json"
    stale.write_text('{"Verified":true,"DetectorName":"Fixture"}\n')
    monkeypatch.setattr(cred_blast_radius, "run", lambda *a, **k: {"creds_assessed": 1})
    ok, result, phases = _run(state)
    assert not ok and not state.calls
    assert stale.read_text() == '{"Verified":true,"DetectorName":"Fixture"}\n'
    assert phases[-1]["status"] == "skipped"
    assert result["phase_status"]["secret_hunt"] == "error"
    assert result["assessment_status"] == "inconclusive"

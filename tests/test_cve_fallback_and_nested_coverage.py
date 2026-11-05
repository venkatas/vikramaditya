"""Local regressions for API coverage handoff and pinned CVE HTTPX fallback."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import api_audit
import cve
import phase_manifest as pm
import reporter
import tool_resolution


def session_dirs(tmp_path):
    paths = [tmp_path / tree / "example.invalid" / "sessions" / "one"
             for tree in ("recon", "findings", "reports")]
    for path in paths:
        path.mkdir(parents=True)
    return paths


def api_outputs(recon, *, blocked=False, capped=False, discover_only=False):
    events = [{"url": "https://outside.invalid/", "reason": "scope blocked"}] if blocked else []
    api_audit.write_outputs(
        recon / "api_specs", [], [], [], raw_specs=[],
        coverage={"probed_hosts": 1, "total_hosts": 2 if capped else 1,
                  "max_hosts": 1, "tested_ops": 0,
                  "total_probeable_ops": 3 if capped or discover_only else 0,
                  "max_ops": 1, "discover_only": discover_only,
                  "scope_blocks": events},
    )


@pytest.mark.parametrize("entry_tree", ["recon", "findings", "reports"])
@pytest.mark.parametrize("kind", ["scope", "cap", "both"])
def test_real_nested_api_producer_drives_all_entry_points_read_only(tmp_path, entry_tree, kind):
    recon, findings, reports = session_dirs(tmp_path)
    api_outputs(recon, blocked=kind != "cap", capped=kind != "scope")
    entry = tmp_path / entry_tree / "example.invalid" / "sessions" / "one"
    before = {str(path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    rows = pm.collect_coverage(str(entry))
    assert len(rows) == 1 and rows[0]["source"] == "api_audit"
    assert pm.assessment_status(str(entry)) == "inconclusive"
    for render in (reporter._render_coverage_limitations_md,
                   reporter._render_coverage_limitations_html):
        assert "INCONCLUSIVE" in render(str(entry))
    after = {str(path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert after == before


def test_nested_api_merge_is_idempotent_and_retains_unrelated_root_gap(tmp_path):
    recon, findings, _ = session_dirs(tmp_path)
    api_outputs(recon, blocked=True, capped=True)
    (findings / "coverage.json").write_text(json.dumps([
        {"tool": "gf", "reason": "patterns missing"}]))
    first = pm.merge_coverage(str(findings))
    second = pm.merge_coverage(str(findings))
    assert first == second and len(first) == 2
    assert {row["tool_or_phase"] for row in first} == {"api_audit", "gf"}


@pytest.mark.parametrize("field", ["scope", "hosts", "operations", "unknown", "legacy"])
def test_rich_api_summary_is_authoritative_without_canonical_list(tmp_path, field):
    recon, findings, _ = session_dirs(tmp_path)
    directory = recon / "api_specs"
    directory.mkdir()
    payload = {"probed_hosts": 1, "total_hosts": 1,
               "tested_public_operations": 2, "total_probeable_public_operations": 2,
               "scope_blocked": 0, "degraded": False, "discover_only": False}
    if field == "scope":
        payload["scope_blocked"] = 2
    elif field == "hosts":
        payload["total_hosts"] = 4
    elif field == "operations":
        payload["total_probeable_public_operations"] = 7
    elif field == "unknown":
        payload["degraded"] = True
    else:
        payload["degraded"] = [{"tool": "spec-parser", "reason": "fixture parser failure"}]
    (directory / "api_coverage.json").write_text(json.dumps(payload))
    assert pm.assessment_status(str(findings)) == "inconclusive"
    assert len(pm.collect_coverage(str(findings))) == 1


def test_nested_api_scope_is_same_session_only_and_discover_only_is_not_op_failure(tmp_path):
    recon, findings, _ = session_dirs(tmp_path)
    api_outputs(recon, discover_only=True)
    other = recon.parent / "other" / "api_specs"
    other.mkdir(parents=True)
    (other / "coverage.json").write_text(json.dumps([
        {"source": "api_audit", "tool_or_phase": "api_audit", "reason": "other session failed"}]))
    assert pm.collect_coverage(str(findings)) == []
    assert pm.assessment_status(str(findings)) == "complete"


@pytest.fixture
def offline_tech_probe(monkeypatch):
    for key in ("SCOPE_LOCK", "SCOPE_ALLOW_FILE", "FINDINGS_OUT_DIR"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(cve, "_fetch_body_status", lambda *a, **k: ("", "404"))
    calls = []

    def command(cmd, timeout=30):
        calls.append(cmd)
        if isinstance(cmd, list):
            return True, "https://example.invalid [200] [Apache]"
        return False, ""

    monkeypatch.setattr(cve, "run_cmd", command)
    return calls


def test_cve_fallback_executes_healthy_absolute_pin_without_shell_or_redirects(
        tmp_path, monkeypatch, offline_tech_probe):
    recon, _, _ = session_dirs(tmp_path)
    binary = str(tmp_path / "healthy-pd-httpx")
    monkeypatch.setattr(tool_resolution, "resolve", lambda name: (binary, None))
    techs = cve.detect_technologies("example.invalid", str(recon))
    argv = offline_tech_probe[0]
    assert argv[0] == binary and Path(argv[0]).is_absolute()
    assert argv[argv.index("-u") + 1] == "https://example.invalid"
    assert "-follow-redirects=false" in argv and "-follow-host-redirects=false" in argv
    assert "apache" in techs
    assert cve.detect_technologies.last_status["status"] == "ok"


@pytest.mark.parametrize("failure", ["missing", "wrong_cli", "nonzero", "timeout"])
def test_cve_fallback_failure_persists_inconclusive_coverage(
        tmp_path, monkeypatch, offline_tech_probe, failure):
    recon, findings, _ = session_dirs(tmp_path)
    if failure in {"missing", "wrong_cli"}:
        reason = "Python HTTP client, not ProjectDiscovery httpx" if failure == "wrong_cli" else None
        monkeypatch.setattr(tool_resolution, "resolve", lambda name: (None, reason))
    else:
        monkeypatch.setattr(tool_resolution, "resolve", lambda name: ("/fake/pd-httpx", None))
        monkeypatch.setattr(cve, "run_cmd", lambda *a, **k: (
            False, "timeout after 30s" if failure == "timeout" else "fixture exited 7"))
    assert cve.detect_technologies("example.invalid", str(recon)) == {}
    assert cve.detect_technologies.last_status["status"] == "degraded"
    assert pm.assessment_status(str(findings)) == "inconclusive"
    assert any(row["tool_or_phase"] == "httpx" for row in pm.collect_coverage(str(findings)))
    if failure in {"missing", "wrong_cli"}:
        assert all(not isinstance(command, list) for command in offline_tech_probe)


@pytest.mark.parametrize("policy", ["www.example.invalid", "", "example.invalid:8443"])
def test_technology_probe_fails_closed_when_initial_target_not_authorized(
        tmp_path, monkeypatch, offline_tech_probe, policy):
    recon, findings, _ = session_dirs(tmp_path)
    (recon / "scope").mkdir()
    (recon / "scope/allow.txt").write_text(policy)

    def forbidden(*args, **kwargs):
        pytest.fail("off-scope technology probe reached a subprocess or resolver")

    monkeypatch.setattr(cve, "run_cmd", forbidden)
    monkeypatch.setattr(cve, "_fetch_body_status", forbidden)
    monkeypatch.setattr(tool_resolution, "resolve", forbidden)
    assert cve.detect_technologies("example.invalid", str(recon)) == {}
    assert pm.assessment_status(str(findings)) == "inconclusive"


def test_healthy_zero_technology_probe_is_not_a_tool_failure(
        tmp_path, monkeypatch, offline_tech_probe):
    recon, findings, _ = session_dirs(tmp_path)
    monkeypatch.setattr(tool_resolution, "resolve", lambda name: ("/fake/pd-httpx", None))
    monkeypatch.setattr(cve, "run_cmd", lambda *a, **k: (True, ""))
    assert cve.detect_technologies("example.invalid", str(recon)) == {}
    assert cve.detect_technologies.last_status["status"] == "ok"
    assert pm.assessment_status(str(findings)) == "complete"


def test_recon_fingerprints_do_not_probe_or_resolve_httpx_again(
        tmp_path, monkeypatch, offline_tech_probe):
    recon, _, _ = session_dirs(tmp_path)
    (recon / "live").mkdir()
    (recon / "live/httpx_full.txt").write_text("https://example.invalid [200] [IIS:10.0]\n")
    monkeypatch.setattr(tool_resolution, "resolve", lambda *a, **k: pytest.fail("unexpected HTTPX fallback"))
    assert "iis:10.0" in cve.detect_technologies("example.invalid", str(recon))
    assert all(not isinstance(command, list) for command in offline_tech_probe)


def test_actual_resolver_rejects_python_shadow_and_executes_fake_pd_binary(
        tmp_path, monkeypatch, offline_tech_probe):
    shadow = tmp_path / "python env" / "httpx"
    selected = tmp_path / "PD tools" / "httpx"
    for path in (shadow, selected):
        path.parent.mkdir()
    shadow.write_text("#!/bin/sh\nprintf '%s\\n' 'python-httpx 0.28'\nexit 2\n")
    selected.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = '-version' ]; then\n"
        "  printf '%s\\n' 'ProjectDiscovery httpx v1.7.0'\n"
        "else\n"
        "  printf '%s\\n' 'https://example.invalid [200] [Apache]'\n"
        "fi\n")
    shadow.chmod(0o755)
    selected.chmod(0o755)
    monkeypatch.setattr(tool_resolution, "candidate_paths", lambda *a, **k: [str(shadow), str(selected)])
    # Keep manual curl probes offline while exercising the actual argv launcher.
    calls = []

    def local_only(command, timeout=30):
        calls.append(command)
        if isinstance(command, list):
            from subprocess import run
            response = run(command, capture_output=True, text=True, timeout=timeout)
            return response.returncode == 0, response.stdout
        return False, ""

    monkeypatch.setattr(cve, "run_cmd", local_only)
    assert "apache" in cve.detect_technologies("example.invalid")
    assert calls[0][0] == str(selected)
    assert cve.detect_technologies.last_status["status"] == "ok"


def test_standalone_cve_run_persists_fallback_failure_in_findings_root(
        tmp_path, monkeypatch, offline_tech_probe):
    findings = tmp_path / "standalone"
    monkeypatch.setattr(tool_resolution, "resolve", lambda *a, **k: (None, None))
    monkeypatch.setattr(cve, "check_exposed_configs", lambda *a, **k: [])
    monkeypatch.setattr(cve, "run_nuclei_cve_scan", lambda *a, **k: [])
    cve.hunt_cves("example.invalid", findings_root=str(findings))
    assert (findings / "manual_review/coverage_gaps.txt").is_file()
    assert pm.assessment_status(str(findings)) == "inconclusive"


@pytest.mark.parametrize("json_state", ["present", "overwritten", "absent"])
def test_recon_append_only_gap_survives_json_overwrite_and_deduplicates(tmp_path, json_state):
    recon, findings, _ = session_dirs(tmp_path)
    (recon / "manual_review").mkdir()
    (recon / "manual_review/coverage_gaps.txt").write_text(
        "[COVERAGE-GAP] nmap: partial port scan exited 7\n")
    if json_state == "present":
        (recon / "coverage_degraded.json").write_text(json.dumps([
            {"source": "recon.sh", "tool": "nmap", "reason": "partial port scan exited 7"}]))
    elif json_state == "overwritten":
        (recon / "coverage_degraded.json").write_text("[]")
    rows = pm.collect_coverage(str(findings))
    assert rows == [{"source": "recon.sh", "tool_or_phase": "nmap",
                     "reason": "partial port scan exited 7", "status": "degraded"}]
    assert pm.assessment_status(str(findings)) == "inconclusive"
    assert pm.merge_coverage(str(findings)) == rows
    assert pm.merge_coverage(str(findings)) == rows


def test_nested_producer_cannot_be_shadowed_by_clean_canonical_duplicate(tmp_path):
    recon, findings, _ = session_dirs(tmp_path)
    entry = {"source": "api_audit", "tool_or_phase": "api_audit",
             "reason": "scope blocked 1 destination(s) or policy failures; partial coverage"}
    (findings / "coverage.json").write_text(json.dumps([{**entry, "status": "ran"}]))
    (recon / "api_specs").mkdir()
    (recon / "api_specs/coverage.json").write_text(json.dumps([{**entry, "status": "degraded"}]))
    rows = pm.collect_coverage(str(findings))
    assert rows == [{**entry, "status": "degraded"}]
    assert pm.assessment_status(str(findings)) == "inconclusive"


def test_rich_api_summary_preserves_error_details_alongside_surface_caps(tmp_path):
    recon, findings, _ = session_dirs(tmp_path)
    (recon / "api_specs").mkdir()
    (recon / "api_specs/api_coverage.json").write_text(json.dumps({
        "probed_hosts": 1, "total_hosts": 3,
        "tested_public_operations": 0, "total_probeable_public_operations": 0,
        "degraded": [{"tool_or_phase": "spec-parser", "reason": "parse failed", "status": "failed"}],
    }))
    rows = pm.collect_coverage(str(findings))
    assert len(rows) == 2
    assert any(row["tool_or_phase"] == "spec-parser" and row["status"] == "failed" for row in rows)

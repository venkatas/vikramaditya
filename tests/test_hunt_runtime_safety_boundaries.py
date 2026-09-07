from __future__ import annotations

import json
from pathlib import Path

import hunt


def _bind_session_dirs(monkeypatch, recon_dir: Path, findings_dir: Path) -> None:
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *args, **kwargs: str(recon_dir))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *args, **kwargs: str(findings_dir))


def test_resume_ignores_error_candidate_partial_and_empty_artifacts(tmp_path, monkeypatch):
    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    rce_dir = findings_dir / "rce"
    rce_dir.mkdir(parents=True)
    recon_dir.mkdir()
    (rce_dir / "error.txt").write_text("scanner crashed\n")
    (rce_dir / "candidate_urls.txt").write_text("https://example.invalid/maybe\n")
    (rce_dir / "partial_output.txt").write_text("incomplete\n")
    (rce_dir / "result.txt").write_text("")
    _bind_session_dirs(monkeypatch, recon_dir, findings_dir)

    assert "rce_scan" not in hunt._collect_completed_steps("example.invalid")


def test_resume_accepts_meaningful_legacy_artifact_when_manifest_absent(tmp_path, monkeypatch):
    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    rce_dir = findings_dir / "rce"
    rce_dir.mkdir(parents=True)
    recon_dir.mkdir()
    (rce_dir / "nuclei_rce.txt").write_text("[CVE-TEST] https://example.invalid\n")
    _bind_session_dirs(monkeypatch, recon_dir, findings_dir)

    assert "rce_scan" in hunt._collect_completed_steps("example.invalid")


def test_failed_manifest_overrides_stale_artifact_on_resume(tmp_path, monkeypatch):
    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    rce_dir = findings_dir / "rce"
    rce_dir.mkdir(parents=True)
    recon_dir.mkdir()
    (rce_dir / "nuclei_rce.txt").write_text("stale prior result\n")
    hunt.phase_manifest.record_phase(
        str(findings_dir), "RCE SCAN", status=hunt.phase_manifest.PHASE_FAILED
    )
    _bind_session_dirs(monkeypatch, recon_dir, findings_dir)

    assert "rce_scan" not in hunt._collect_completed_steps("example.invalid")


def test_success_manifest_completes_zero_finding_phase(tmp_path, monkeypatch):
    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    recon_dir.mkdir()
    findings_dir.mkdir()
    hunt.phase_manifest.record_phase(
        str(findings_dir), "SQLMAP", status=hunt.phase_manifest.PHASE_OK
    )
    _bind_session_dirs(monkeypatch, recon_dir, findings_dir)

    assert "sqlmap" in hunt._collect_completed_steps("example.invalid")


def test_latest_manifest_attempt_controls_resume(tmp_path, monkeypatch):
    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    recon_dir.mkdir()
    findings_dir.mkdir()
    hunt.phase_manifest.record_phase(
        str(findings_dir), "JWT AUDIT", status=hunt.phase_manifest.PHASE_FAILED
    )
    hunt.phase_manifest.record_phase(
        str(findings_dir), "JWT AUDIT", status=hunt.phase_manifest.PHASE_OK
    )
    _bind_session_dirs(monkeypatch, recon_dir, findings_dir)

    assert "jwt_audit" in hunt._collect_completed_steps("example.invalid")


def test_exact_allowlist_rejects_subdomain_and_userinfo(tmp_path):
    recon_dir = tmp_path / "recon"
    scope_dir = recon_dir / "scope"
    scope_dir.mkdir(parents=True)
    (scope_dir / "allow.txt").write_text("https://api.example.invalid:8443/path\n")
    allowed = hunt._exact_allowed_hosts("example.invalid", str(recon_dir))

    assert allowed == {"api.example.invalid"}
    assert hunt._url_in_exact_allowed_hosts(
        "https://api.example.invalid:8443/v1", allowed
    )
    assert not hunt._url_in_exact_allowed_hosts(
        "https://sub.api.example.invalid/v1", allowed
    )
    assert not hunt._url_in_exact_allowed_hosts(
        "https://api.example.invalid@evil.invalid/v1", allowed
    )


def test_openapi_operations_and_servers_are_exact_scope_filtered(tmp_path):
    specs = tmp_path / "api_specs"
    specs.mkdir()
    (specs / "operations.json").write_text(json.dumps([
        {"method": "POST", "path": "/ok", "sample_url": "https://api.example.invalid/ok"},
        {"method": "POST", "path": "/bad", "sample_url": "https://evil.invalid/bad"},
    ]))

    endpoints = hunt._collect_openapi_post_endpoints(
        str(tmp_path), allowed_hosts={"api.example.invalid"}
    )
    assert [item["url"] for item in endpoints] == ["https://api.example.invalid/ok"]

    (specs / "operations.json").unlink()
    (specs / "raw.json").write_text(json.dumps({
        "openapi": "3.0.0",
        "servers": [{"url": "https://evil.invalid/v1"}],
        "paths": {"/write": {"post": {}}},
    }))
    assert hunt._collect_openapi_post_endpoints(
        str(tmp_path), allowed_hosts={"api.example.invalid"}
    ) == []


def test_post_discovery_records_but_never_consumes_off_scope_form_action(
    tmp_path, monkeypatch
):
    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "scope").mkdir()
    (recon_dir / "live" / "urls.txt").write_text(
        "https://app.example.invalid/login.html\n"
    )
    (recon_dir / "scope" / "allow.txt").write_text("app.example.invalid\n")
    findings_dir.mkdir()
    _bind_session_dirs(monkeypatch, recon_dir, findings_dir)
    monkeypatch.setattr(hunt, "_lightpanda_bin", lambda: "/fake/lightpanda")
    monkeypatch.setattr(hunt, "_which", lambda _name: False)
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", lambda *args, **kwargs: [
        {"action": "/submit", "method": "POST", "inputs": ["name"]},
        {"action": "https://evil.invalid/collect", "method": "POST", "inputs": ["secret"]},
    ])

    assert hunt.run_post_param_discovery("example.invalid") is True
    params = json.loads((recon_dir / "params" / "post_params.json").read_text())
    assert set(params) == {"https://app.example.invalid/submit"}
    forms = json.loads((recon_dir / "params" / "lightpanda_forms.json").read_text())
    rejected = next(item for item in forms if item["action"].startswith("https://evil.invalid"))
    assert rejected["scope_allowed"] is False


def _prepare_drupal_case(tmp_path: Path, monkeypatch):
    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "priority").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://cms.example.invalid [200] [Drupal]\n"
    )
    (recon_dir / "live" / "urls.txt").write_text("https://cms.example.invalid\n")
    (recon_dir / "priority" / "attack_surface.json").write_text(json.dumps({
        "top_hosts": [{
            "url": "https://cms.example.invalid",
            "tech_matches": ["Drupal"],
            "version_hints": ["Drupal 7.30"],
        }]
    }))
    findings_dir.mkdir()
    poc = tmp_path / "drupalgeddon2.py"
    poc.write_text("print('test')\n")
    _bind_session_dirs(monkeypatch, recon_dir, findings_dir)
    monkeypatch.setattr(
        hunt, "_tool_bin", lambda name: str(poc) if name == "drupalgeddon2" else name
    )
    monkeypatch.setattr(hunt, "_which", lambda _name: False)
    monkeypatch.setattr(hunt, "run_msf", lambda *args, **kwargs: False)
    return findings_dir


def test_drupalgeddon_commands_and_post_are_disabled_by_default(tmp_path, monkeypatch):
    findings_dir = _prepare_drupal_case(tmp_path, monkeypatch)
    commands = []
    monkeypatch.setattr(
        hunt, "run_cmd", lambda command, **kwargs: (commands.append(command) or True, "")
    )
    hunt._reset_degraded()

    assert hunt.run_cms_exploit("example.invalid", allow_destructive=False) is True
    assert not any("drupalgeddon2.py" in command for command in commands)
    assert not any("user/password" in command for command in commands)
    marker = findings_dir / "exploits" / "drupalgeddon2_manual_review.txt"
    assert marker.is_file() and "were not run" in marker.read_text()
    assert any(item["tool"] == "cms_exploit" for item in hunt._DEGRADED_CAPABILITIES)


def test_allow_destructive_help_covers_non_msf_state_changes(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["hunt.py", "--help"])
    try:
        hunt.main()
    except SystemExit as exc:
        assert exc.code == 0
    output = " ".join(capsys.readouterr().out.split())
    assert "standalone Drupalgeddon commands" in output
    assert "remote file creation/execution" in output

"""Scope enforcement at recon launch, CMS consumers and authenticated preflight."""
import builtins
import json
import shlex
from pathlib import Path

import pytest

import hunt
import scoped_http


def test_allowlist_write_failure_prevents_recon_launch(tmp_path, monkeypatch):
    recon = tmp_path / "recon"
    recon.mkdir()
    monkeypatch.setattr(hunt, "_activate_recon_session", lambda *a, **k: ("test", str(recon)))
    monkeypatch.setattr(hunt, "_adaptive_runtime_overrides", lambda *a: {})
    monkeypatch.setattr(hunt, "_brain", None)
    calls = []
    monkeypatch.setattr(hunt, "run_live", lambda *a, **k: calls.append(a) or True)
    real_open = builtins.open

    def failing_open(path, *args, **kwargs):
        if str(path) == str(recon / "scope" / "allow.txt"):
            raise PermissionError("test denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", failing_open)
    hunt._reset_degraded()
    assert hunt.run_recon("example.invalid", scope_lock=True) is False
    assert calls == []
    assert any("allowlist persist failed" in d["reason"] for d in hunt._DEGRADED_CAPABILITIES)


def _cms_case(tmp_path, monkeypatch, allow="example.invalid\n"):
    recon = tmp_path / "recon"
    findings = tmp_path / "findings"
    (recon / "live").mkdir(parents=True)
    (recon / "scope").mkdir()
    (recon / "priority").mkdir()
    findings.mkdir()
    (recon / "scope" / "allow.txt").write_text(allow)
    (recon / "live" / "urls.txt").write_text("https://example.invalid\nhttps://outside.invalid\n")
    (recon / "live" / "httpx_full.txt").write_text(
        "https://example.invalid [200] [WordPress]\nhttps://outside.invalid [200] [Drupal]\n")
    (recon / "priority" / "attack_surface.json").write_text(json.dumps({"top_hosts": [
        {"url": "https://example.invalid", "tech_matches": ["WordPress"]},
        {"url": "https://outside.invalid", "tech_matches": ["Drupal"]},
    ]}))
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_which", lambda binary: binary == "whatweb")
    monkeypatch.setattr(hunt, "_tool_bin", lambda name: name)
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    commands = []

    def capture(command, **kwargs):
        commands.append(command)
        # Error text contains a CMS marker, but cannot count as body proof.
        return False, "scope blocked HTTP destination https://wordpress.outside.invalid"

    monkeypatch.setattr(hunt, "run_cmd", capture)
    return findings, commands


def test_cms_filters_inputs_disables_external_redirects_and_uses_scoped_get(tmp_path, monkeypatch):
    findings, commands = _cms_case(tmp_path, monkeypatch)
    hunt.run_cms_exploit("example.invalid")
    fingerprint = [c for c in commands if "whatweb -a1" in c]
    assert len(fingerprint) == 1
    assert "--follow-redirect=never" in fingerprint[0]
    assert "outside.invalid" not in fingerprint[0]
    assert (findings / "exploits" / "scoped_live_urls.txt").read_text() == "https://example.invalid\n"
    getters = [shlex.split(c) for c in commands if "scoped_http.py" in c]
    assert getters
    assert all("--allow-file" in c and c[-1].startswith("https://example.invalid") for c in getters)
    assert not any("curl -sk -L" in c for c in commands)
    assert not list((findings / "exploits").glob("wordpress_*.txt"))


def test_cms_empty_allowlist_never_launches_tools(tmp_path, monkeypatch):
    _, commands = _cms_case(tmp_path, monkeypatch, allow="")
    assert hunt.run_cms_exploit("example.invalid") is False
    assert commands == []


def test_scoped_authenticated_preflight_stops_disallowed_redirect(monkeypatch):
    def blocked(url, exact_hosts, **kwargs):
        assert exact_hosts == {"example.invalid"}
        assert kwargs["headers"]["Cookie"] == "session=secret"
        raise scoped_http.ScopeError(url, "https://outside.invalid/login")

    monkeypatch.setattr(scoped_http, "get", blocked)
    ok, reason, cookies = hunt._verify_authenticated(
        "example.invalid", "session=secret", exact_hosts={"example.invalid"})
    assert ok is False and "scope blocked" in reason and cookies == ""


def test_failed_recon_stops_full_pipeline_before_active_consumers(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt, "check_tool_readiness", lambda: [])
    monkeypatch.setattr(hunt, "run_recon", lambda *a, **k: False)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(tmp_path / "recon"))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda *a, **k: str(tmp_path / "reports"))
    monkeypatch.setattr(hunt, "_active_recon_session_id", lambda *a: "test")

    def forbidden(*a, **k):
        raise AssertionError("failed recon reached an active consumer")

    for name in ("run_vuln_scan", "run_cms_exploit", "run_rce_scan", "run_js_analysis",
                 "run_browser_scan", "run_post_param_discovery"):
        monkeypatch.setattr(hunt, name, forbidden)
    result = hunt.hunt_target("example.invalid", full=True, scope_lock=True)
    assert result["success"] is False
    assert result["assessment_status"] == "inconclusive"
    assert result["phase_status"]["recon"] == hunt.PHASE_STATUS_FAILED


def test_failed_recon_stops_autonomous_planning(tmp_path, monkeypatch):
    recon = tmp_path / "recon"
    recon.mkdir()
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "run_recon", lambda *a, **k: False)
    monkeypatch.setattr(hunt, "_activate_recon_session", lambda *a, **k: ("test", str(recon)))
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda *a, **k: str(tmp_path / "reports"))
    monkeypatch.setattr(hunt, "_load_autonomous_session", lambda *a, **k: {
        "session_file": str(tmp_path / "autonomous.json"), "completed_steps": [],
    })
    monkeypatch.setattr(hunt, "_save_autonomous_session", lambda *a: None)

    def forbidden(*a, **k):
        raise AssertionError("failed recon reached autonomous planning")

    monkeypatch.setattr(hunt, "_build_autonomous_plan", forbidden)
    result = hunt.run_autonomous_hunt("example.invalid", scope_lock=True)
    assert result["success"] is False and result["assessment_status"] == "inconclusive"

"""Regression for the 2026-07-23 real-engagement scan failures: vuln scan never ran (Check 0 starved
it), open-redirect crashed on an httpx kwarg, JS analysis blew the watchdog uncapped, and
the active scanner hit the WAF-403 apex instead of a live host."""
import os, sys
from pathlib import Path
REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

OR = (REPO / "open_redirect_hunt.py").read_text()
SC = (REPO / "scanner.sh").read_text()
HU = (REPO / "hunt.py").read_text()
VK = (REPO / "vikramaditya.py").read_text()


def test_open_redirect_uses_follow_redirects():
    # httpx renamed allow_redirects -> follow_redirects; the old kwarg crashed every run
    assert "follow_redirects=False" in OR
    assert "allow_redirects" not in OR


def test_check0_is_time_boxed():
    assert "CHECK0_BUDGET" in SC and "_C0_DEADLINE" in SC
    # the deadline is actually enforced inside the probe loop (breaks + marks coverage)
    assert 'date +%s' in SC and "_C0_TIMEOUT=1" in SC
    assert "time-boxed" in SC


def test_js_analysis_uses_selected_corpus():
    assert "JS_ANALYSIS_MAX_URLS" in HU and "js_scan_file" in HU
    # The selected file is the only URL source for the one-time parallel download.
    assert "_download_js_corpus(js_scan_file, dl_dir)" in HU
    assert 'cat "{js_urls_file}"' not in HU


def test_run_vuln_scan_forwards_extended_scanner_skip_names(tmp_path, monkeypatch):
    import hunt

    recon_dir = tmp_path / "recon" / "example.com" / "sessions" / "s1"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "priority").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text("https://example.com [200]\n")
    (recon_dir / "priority" / "prioritized_hosts.txt").write_text("https://example.com\n")

    commands = []
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda domain: str(recon_dir))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "_adaptive_runtime_overrides", lambda domain: {})
    monkeypatch.setattr(hunt, "_shell_env_prefix", lambda env: "")
    monkeypatch.setattr(hunt, "run_prioritize", lambda domain: True)
    monkeypatch.setattr(hunt, "run_live", lambda cmd, **kwargs: commands.append(cmd) or True)
    monkeypatch.setattr(hunt, "_brain_phase_complete", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_update_target_state_from_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_propagate_exposed_paths", lambda *a, **k: 0)
    monkeypatch.setattr(hunt, "_scan_exposed_data_pii", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_runtime_session_id", lambda domain: None)
    monkeypatch.setattr(hunt, "_active_recon_session_id", lambda domain: None)

    assert hunt.run_vuln_scan(
        "example.com",
        full=True,
        skip_items={"mfa", "saml", "import", "deserialization", "supply_chain", "upload"},
    )

    assert commands, "scanner command was not invoked"
    assert '--skip "deserialize,import,mfa,saml,supplychain,upload"' in commands[0]
    assert "VAPT_ALLOW_STATE_CHANGES=0" in commands[0]


def test_destructive_opt_in_is_forwarded_to_scanner(tmp_path, monkeypatch):
    import hunt

    recon_dir = tmp_path / "recon" / "example.com" / "sessions" / "s1"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "priority").mkdir()
    (recon_dir / "live" / "httpx_full.txt").write_text("https://example.com [200]\n")
    (recon_dir / "priority" / "prioritized_hosts.txt").write_text("https://example.com\n")
    commands = []
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda domain: str(recon_dir))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "_adaptive_runtime_overrides", lambda domain: {})
    monkeypatch.setattr(hunt, "_shell_env_prefix", lambda env: "")
    monkeypatch.setattr(hunt, "run_prioritize", lambda domain: True)
    monkeypatch.setattr(hunt, "run_live", lambda cmd, **kwargs: commands.append(cmd) or True)
    monkeypatch.setattr(hunt, "_brain_phase_complete", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_update_target_state_from_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_propagate_exposed_paths", lambda *a, **k: 0)
    monkeypatch.setattr(hunt, "_scan_exposed_data_pii", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_runtime_session_id", lambda domain: None)
    monkeypatch.setattr(hunt, "_active_recon_session_id", lambda domain: None)

    assert hunt.run_vuln_scan("example.com", full=True, allow_destructive=True)
    assert "VAPT_ALLOW_STATE_CHANGES=1" in commands[0]


def test_scanner_fail_closed_state_change_and_scope_gates_are_wired():
    assert 'ALLOW_STATE_CHANGES="${VAPT_ALLOW_STATE_CHANGES:-0}"' in SC
    assert 'if [ "$ALLOW_STATE_CHANGES" != "1" ]; then' in SC
    assert 'if [ -s "$_SCOPE_ALLOW" ]; then' in SC
    assert '--in "$ORDERED_SCAN" --out "$ORDERED_SCAN"' in SC
    assert "synthetic assertion POST skipped" in SC


def test_brain_target_prefers_live_host(tmp_path, monkeypatch):
    import vikramaditya as v
    # build a fake findings/recon layout with a WAF-403 apex + a live 200 host
    fdir = tmp_path / "findings" / "hotel.example" / "sessions" / "s1"
    rdir = tmp_path / "recon" / "hotel.example" / "sessions" / "s1" / "live"
    fdir.mkdir(parents=True); rdir.mkdir(parents=True)
    (rdir / "httpx_full.txt").write_text(
        "https://hotel.example [403] [Access Denied]\n"
        "https://www.app.hotel.example [200] [123] [Real App]\n")
    picked = v._best_live_target("https://hotel.example", str(fdir))
    assert picked == "https://www.app.hotel.example", "did not swap the 403 apex for the live 200 host"


def test_brain_target_falls_back_when_no_recon():
    import vikramaditya as v
    assert v._best_live_target("https://x.example", "") == "https://x.example"

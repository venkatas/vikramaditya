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


def test_js_analysis_is_capped():
    assert "JS_ANALYSIS_MAX_URLS" in HU and "js_scan_file" in HU
    # the per-URL loops must read the capped file, not the full js_urls_file
    assert 'cat "{js_scan_file}"' in HU
    assert 'cat "{js_urls_file}"' not in HU


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

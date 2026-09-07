"""Hunt timeout / JS cap defaults (env-overridable)."""

from __future__ import annotations

import os
import re


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _hunt_src() -> str:
    with open(os.path.join(ROOT, "hunt.py"), encoding="utf-8") as fh:
        return fh.read()


def test_scan_timeout_default_7200_env_overridable():
    src = _hunt_src()
    assert 'os.environ.get("VIK_SCAN_TIMEOUT")' in src
    assert 'or os.environ.get("SCAN_TIMEOUT")' in src
    assert 'or "7200"' in src
    # Ensure we no longer hard-code the old 5400 default assignment
    assert not re.search(r"^SCAN_TIMEOUT\s*=\s*5400\b", src, re.M)


def test_js_analysis_max_urls_default_800():
    src = _hunt_src()
    assert 'os.environ.get("JS_ANALYSIS_MAX_URLS", "800")' in src


def test_js_download_failure_summary_helper_present():
    src = _hunt_src()
    assert "def _js_download_failure_summary" in src
    assert "Cloudflare/WAF" in src

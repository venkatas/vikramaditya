"""Regression tests for prioritize.py IIS version-gating.

Confirms CVE-2017-7269 (IIS 6.0-only ScStoragePathFromUrl WebDAV RCE) is NOT
emitted against a modern IIS 10.0 host (the false-critical found in the
clientd.com e2e run), while a genuine IIS 6.0 banner still surfaces it.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import prioritize  # noqa: E402


def _cves(line):
    result = prioritize.score_host(line)
    assert result is not None
    return result["cves"], result


def test_iis10_does_not_emit_cve_2017_7269():
    # Exact format httpx produced in the real run.
    line = (
        "https://www.clientd.com [200] [6243] [Home] [148.72.90.65] "
        "[IIS:10.0,Microsoft ASP.NET,Plesk,Windows Server,jQuery:1.7.1]"
    )
    cves, result = _cves(line)
    joined = " ".join(cves)
    assert "CVE-2017-7269" not in joined, joined
    # Should not be flagged CRITICAL purely off the IIS-6 CVE substring match.
    assert result["priority"] != "CRITICAL", result
    assert result["score"] <= 4, result
    # A version-appropriate note should mention the detected version + that the
    # WebDAV RCE is IIS-6 only.
    assert "10.0" in joined and "IIS 6.0" in joined, joined


def test_iis6_still_emits_cve_2017_7269():
    line = (
        "http://legacy.example.com [200] [123] [Old App] [10.0.0.5] "
        "[IIS:6.0,Microsoft ASP.NET]"
    )
    cves, result = _cves(line)
    joined = " ".join(cves)
    assert "CVE-2017-7269" in joined, joined
    # IIS-6 RCE keeps its severity (mapped score 5 -> MEDIUM at minimum).
    assert result["priority"] in {"MEDIUM", "HIGH", "CRITICAL"}, result


def test_iis_slash_format_version_gated():
    # whatweb / server-header style: Microsoft-IIS/10.0
    line = "https://h.example.com [200] [10] [t] [1.2.3.4] [Microsoft-IIS/10.0]"
    cves, _ = _cves(line)
    assert "CVE-2017-7269" not in " ".join(cves)


def test_iis_no_version_softened_not_critical():
    # Bare IIS banner with no version attached.
    line = "https://h.example.com [200] [10] [t] [1.2.3.4] [IIS]"
    cves, result = _cves(line)
    joined = " ".join(cves)
    assert "CVE-2017-7269" not in joined, joined
    assert result["priority"] != "CRITICAL", result


def test_detect_product_version_helper():
    assert prioritize.detect_product_version("iis:10.0", "iis") == "10.0"
    assert prioritize.detect_product_version("microsoft-iis/10.0", "microsoft-iis") == "10.0"
    assert prioritize.detect_product_version("iis 6.0", "iis") == "6.0"
    assert prioritize.detect_product_version("plain iis banner", "iis") is None

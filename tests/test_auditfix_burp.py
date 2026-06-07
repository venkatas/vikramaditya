"""Tests for reporter Method 1g — Burp Suite findings ingestion (v10.2.0).

burp_scanner.run_burp_scan writes burp/findings.json as a JSON list of normalized
issues {severity, type, title, url, detail, poc, confidence, source:"burp"}. The
reporter must ingest them, mapping the burp "type" key onto the renderer's "vtype",
clamping severity (Burp has no CRITICAL), defaulting unknown types to misconfig,
and NOT emitting an unmapped-subdir warning for burp/.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporter import SEVERITY_ORDER, VULN_TEMPLATES, load_findings


def _seed_burp(tmp_path, items):
    d = tmp_path / "burp"
    d.mkdir()
    (d / "findings.json").write_text(json.dumps(items))
    return d


def _burp_findings(findings):
    # Method 1g emits no explicit source flag; identify by the seeded titles/urls.
    return findings


def test_burp_issue_ingested_with_type_mapped_to_vtype(tmp_path):
    _seed_burp(tmp_path, [{
        "severity": "high", "type": "sqli",
        "title": "SQL injection (https://x.test/p?id=1)",
        "url": "https://x.test/p?id=1", "detail": "SQL injection",
        "poc": "Burp Suite issue: SQL injection", "source": "burp",
    }])
    fs = load_findings(str(tmp_path))
    sqli = [f for f in fs if f.get("vtype") == "sqli"]
    assert len(sqli) == 1
    assert sqli[0]["severity"] == "high"
    assert "x.test" in sqli[0]["title"]
    assert "Burp Suite issue" in sqli[0]["poc"]


def test_burp_information_severity_clamped_to_info(tmp_path):
    _seed_burp(tmp_path, [{"severity": "Information", "type": "misconfig",
                           "title": "Strict transport security not enforced", "url": "https://x.test/"}])
    f = load_findings(str(tmp_path))[0]
    assert f["severity"] == "info"


def test_burp_unknown_type_falls_back_to_misconfig(tmp_path):
    _seed_burp(tmp_path, [{"severity": "low", "type": "some_burp_only_class",
                           "title": "Weird issue", "url": "https://x.test/"}])
    f = load_findings(str(tmp_path))[0]
    assert f["vtype"] == "misconfig"
    assert f["vtype"] in VULN_TEMPLATES


def test_burp_explicit_cvss_honored(tmp_path):
    _seed_burp(tmp_path, [{"severity": "medium", "type": "xss", "title": "XSS",
                           "url": "https://x.test/", "cvss": "6.1"}])
    f = load_findings(str(tmp_path))[0]
    assert f.get("cvss") == "6.1"


def test_burp_dir_does_not_trigger_unmapped_warning(tmp_path, capsys):
    _seed_burp(tmp_path, [{"severity": "low", "type": "cors", "title": "CORS", "url": "https://x.test/"}])
    load_findings(str(tmp_path))
    out = capsys.readouterr().out
    assert "'burp/' is not" not in out


def test_burp_empty_or_malformed_is_safe(tmp_path):
    d = tmp_path / "burp"
    d.mkdir()
    (d / "findings.json").write_text("{ not valid json")
    # Must not raise; just yields no burp findings.
    load_findings(str(tmp_path))


def test_burp_severity_clamps_unknown_to_info(tmp_path):
    _seed_burp(tmp_path, [{"severity": "bogus", "type": "misconfig", "title": "x", "url": "https://x.test/"}])
    f = load_findings(str(tmp_path))[0]
    assert f["severity"] in SEVERITY_ORDER and f["severity"] == "info"


def test_burp_critical_clamped_to_high(tmp_path):
    # Burp has no Critical severity; a stray "critical" must be clamped, not kept.
    _seed_burp(tmp_path, [{"severity": "critical", "type": "sqli", "title": "x", "url": "https://x.test/"}])
    f = load_findings(str(tmp_path))[0]
    assert f["severity"] == "high"


# ── burp_scanner request-shaping (desktop-Burp + scope-safety) ────────────────
import burp_scanner  # noqa: E402


class _FakeResp:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.text = ""


def test_scope_rules_are_bounded_and_no_enterprise_fields(monkeypatch):
    captured = {}

    def _post(url, json=None, timeout=None):
        captured["b"] = json
        return _FakeResp(201, {"Location": "/v0.1/scan/9"})
    monkeypatch.setattr(burp_scanner.requests, "post", _post)
    tid = burp_scanner.BurpClient(api_key="k").start_scan(["https://ex.test/"], scope_host="ex.test", scope_lock=True)
    assert tid == "9"
    body = captured["b"]
    assert "name" not in body                       # Enterprise-only field omitted
    assert "scan_configurations" not in body        # no config unless explicit
    rules = [r["rule"] for r in body["scope"]["include"]]
    # Trailing slash bounds the prefix so "ex.test.evil" can't match.
    assert rules == ["https://ex.test/", "http://ex.test/"]
    assert not any(r == "https://ex.test" for r in rules)


def test_scope_host_preserves_port_and_seed_gets_path(monkeypatch):
    captured = {}

    def _post(url, json=None, timeout=None):
        captured["b"] = json
        return _FakeResp(201, {"Location": "/v0.1/scan/3"})
    monkeypatch.setattr(burp_scanner.requests, "post", _post)
    monkeypatch.setattr(burp_scanner.BurpClient, "reachable", lambda self: True)
    monkeypatch.setattr(burp_scanner.BurpClient, "run", lambda self, tid, timeout=0: [])
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        burp_scanner.run_burp_scan("essl.example.com:8443", os.path.join(d, "burp"),
                                   api_key="k", scope_lock=True)
    body = captured["b"]
    assert body["urls"] == ["https://essl.example.com:8443/"]      # seed normalized w/ path
    rules = [r["rule"] for r in body["scope"]["include"]]
    assert "https://essl.example.com:8443/" in rules               # port preserved in scope

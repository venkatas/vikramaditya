#!/usr/bin/env python3
"""Unit tests for tool_parsers (inline fixtures, *.example.invalid only)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tool_parsers as tp  # noqa: E402


NUCLEI_JSONL = """
{"template-id":"tech-detect","info":{"name":"Wappalyzer Tech Detect","severity":"info"},"host":"https://app.example.invalid","matched-at":"https://app.example.invalid","extracted-results":["nginx"]}
{"template-id":"CVE-2021-41773","info":{"name":"Apache Path Traversal","severity":"critical"},"host":"https://vuln.example.invalid","matched-at":"https://vuln.example.invalid/cgi-bin/.%2e/%2e%2e/etc/passwd","matcher-name":"body"}
""".strip()

SQLMAP_SNIPPET = """
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
        Parameter: id is vulnerable. Do you want to keep testing?
        back-end DBMS: MySQL >= 5.0
"""

FFUF_JSON = json.dumps({
    "results": [
        {
            "url": "https://app.example.invalid/admin",
            "status": 200,
            "length": 1234,
            "input": {"FUZZ": "admin"},
        },
        {
            "url": "https://app.example.invalid/backup.zip",
            "status": 200,
            "length": 99999,
            "input": {"FUZZ": "backup.zip"},
        },
    ]
})

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <hostnames><hostname name="scanme.example.invalid" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nuclei_jsonl():
    findings = tp.parse_nuclei_json(NUCLEI_JSONL)
    assert len(findings) == 2
    assert findings[0]["tool"] == "nuclei"
    assert findings[0]["status"] == "suspected"
    assert findings[0]["severity"] == "info"
    crit = findings[1]
    assert crit["severity"] == "critical"
    assert "CVE-2021-41773" in crit["template_id"]
    assert "vuln.example.invalid" in crit["url"]


def test_parse_sqlmap_confirmed():
    findings = tp.parse_sqlmap_output(SQLMAP_SNIPPET)
    assert findings
    assert any(f["status"] == "confirmed" for f in findings)
    assert any(f.get("param") == "id" for f in findings)
    assert any("MySQL" in (f.get("dbms") or "") for f in findings)


def test_parse_sqlmap_not_injectable_empty():
    text = "all tested parameters do not appear to be injectable."
    assert tp.parse_sqlmap_output(text) == []


def test_parse_ffuf_json():
    findings = tp.parse_ffuf_json(FFUF_JSON)
    assert len(findings) == 2
    assert findings[0]["tool"] == "ffuf"
    assert findings[0]["status_code"] == 200
    assert "admin" in findings[0]["url"]


def test_parse_nmap_xml():
    findings = tp.parse_nmap_xml(NMAP_XML)
    assert len(findings) == 2  # closed 443 excluded
    ports = {f["port"] for f in findings}
    assert ports == {"22", "80"}
    assert any(f["service"] == "ssh" for f in findings)
    assert any("scanme.example.invalid" in f["host"] for f in findings)


def test_write_parsed_findings(tmp_path):
    findings = tp.parse_nuclei_json(NUCLEI_JSONL) + tp.parse_sqlmap_output(SQLMAP_SNIPPET)
    written = tp.write_parsed_findings(str(tmp_path), findings)
    assert "nuclei" in written["parsed"]
    assert "sqlmap" in written["parsed"]
    assert os.path.isfile(written["parsed"]["nuclei"])
    # critical nuclei → cves/ or misconfig/; confirmed sqlmap → sqli/
    assert any("sqli" in p for p in written["appended"])


def test_auto_parse_stdout_nuclei():
    parsed = tp.auto_parse_stdout(NUCLEI_JSONL)
    assert parsed
    assert parsed[0]["tool"] == "nuclei"


def test_cli(tmp_path):
    nfile = tmp_path / "n.jsonl"
    nfile.write_text(NUCLEI_JSONL)
    sfile = tmp_path / "s.txt"
    sfile.write_text(SQLMAP_SNIPPET)
    out = tmp_path / "out"
    out.mkdir()
    rc = tp.main(["--nuclei", str(nfile), "--sqlmap", str(sfile), "--out", str(out)])
    assert rc == 0
    assert (out / "parsed" / "nuclei.json").is_file()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))

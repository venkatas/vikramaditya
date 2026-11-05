"""Local evidence fixtures for inventory, scoring, and methodology accuracy."""
from __future__ import annotations

import json

import pytest

import reporter


@pytest.mark.parametrize("line,expected", [
    ("https://example.invalid [200] [348] [192.0.2.1] [IIS:10.0,ASP.NET]",
     ("200", "192.0.2.1", "", "IIS:10.0,ASP.NET")),
    ("https://example.invalid [200] [348] [Home] [192.0.2.1] [nginx]",
     ("200", "192.0.2.1", "Home", "nginx")),
    ("https://example.invalid [200] [Home] [192.0.2.1] [nginx]",
     ("200", "192.0.2.1", "Home", "nginx")),
    ("https://example.invalid [Home] [192.0.2.1] [nginx]",
     ("", "192.0.2.1", "Home", "nginx")),
    ("https://example.invalid [200] [348] [] [192.0.2.1] [nginx]",
     ("200", "192.0.2.1", "", "nginx")),
    ("https://example.invalid [200] [1000] [2001:db8::1] [nginx]",
     ("200", "2001:db8::1", "", "nginx")),
    ("https://[2001:db8::1] [200] [1000] [[2001:db8::1]] [nginx]",
     ("200", "2001:db8::1", "", "nginx")),
    ("https://example.invalid [200] [1000] [Dashboard [beta]] [192.0.2.1] [nginx]",
     ("200", "192.0.2.1", "Dashboard [beta]", "nginx")),
    ("https://example.invalid [200] [1000] [Dashboard [2001:db8::1]] [192.0.2.1]",
     ("200", "192.0.2.1", "Dashboard [2001:db8::1]", "")),
    ("https://example.invalid [200] [0] [192.0.2.1]",
     ("200", "192.0.2.1", "", "")),
    ("https://example.invalid [301,200] [1000] [Home] [192.0.2.1] [nginx]",
     ("301,200", "192.0.2.1", "Home", "nginx")),
    ("https://example.invalid [200] [1000] [Home] [nginx]",
     ("200", "", "Home", "nginx")),
    ("https://example.invalid [200]", ("200", "", "", "")),
    ("https://example.invalid", ("", "", "", "")),
])
def test_legacy_httpx_optional_fields_are_anchored_to_typed_address(line, expected):
    parsed = reporter._parse_httpx_inventory_line(line)
    assert tuple(parsed[key] for key in ("status", "ip", "title", "tech")) == expected


@pytest.mark.parametrize("record,expected", [
    ({"url": "https://example.invalid", "status_code": 200, "host": "192.0.2.1",
      "tech": ["nginx", "Python"]}, ("200", "192.0.2.1", "", "nginx,Python")),
    ({"url": "https://example.invalid", "status_code": "200", "host_ip": "2001:db8::1",
      "title": "[Home]", "tech": "nginx"}, ("200", "2001:db8::1", "[Home]", "nginx")),
    ({"input": "https://example.invalid", "host": "example.invalid", "a": ["192.0.2.2"],
      "title": "123", "tech": ["nginx"]}, ("", "192.0.2.2", "123", "nginx")),
    ({"url": "https://example.invalid", "title": "Home", "tech": ["nginx"]},
     ("", "", "Home", "nginx")),
    ({"url": "https://example.invalid", "status_code": True, "ip": "not-an-ip"},
     ("", "", "", "")),
])
def test_structured_httpx_does_not_depend_on_field_presence_or_order(record, expected):
    parsed = reporter._parse_httpx_inventory_line(json.dumps(record))
    assert tuple(parsed[key] for key in ("status", "ip", "title", "tech")) == expected


@pytest.mark.parametrize("line", ["", "garbage", "{not-json", "{}", "[]"])
def test_httpx_unusable_records_are_not_invented_as_hosts(line):
    assert reporter._parse_httpx_inventory_line(line) is None


def test_inventory_renderers_keep_missing_title_ip_and_tech_in_correct_columns(tmp_path):
    recon = tmp_path / "recon/example.invalid/sessions/s1"
    (recon / "live").mkdir(parents=True)
    (recon / "live/httpx_full.txt").write_text(
        "https://example.invalid [200] [348] [192.0.2.1] [IIS:10.0,ASP.NET]\n")
    inventory = reporter._collect_asset_inventory(str(recon))
    assert inventory["live_hosts"] == [{"url": "https://example.invalid", "status": "200",
                                       "ip": "192.0.2.1", "title": "", "tech": "IIS:10.0,ASP.NET"}]
    html = reporter._render_recon_inventory_html(str(recon), "example.invalid")
    md = reporter._render_recon_inventory_md(str(recon), "example.invalid")
    assert "<td>192.0.2.1</td><td>—</td><td>IIS:10.0,ASP.NET</td>" in html
    assert "| 200 | 192.0.2.1 | — |" in md


@pytest.mark.parametrize("finding,expected", [
    ({"vtype": "misconfig", "severity": "low"}, "N/A"),
    ({"vtype": "misconfig", "severity": "info"}, "N/A"),
    ({"vtype": "misconfig", "severity": "medium"}, "5.3"),
    ({"vtype": "misconfig", "severity": "low", "cvss": "2.1"}, "2.1"),
    ({"vtype": "misconfig", "severity": "low", "cvss": 0}, "0"),
    ({"vtype": "misconfig", "severity": "low", "cvss": 0.0}, "0.0"),
    ({"vtype": "misconfig", "severity": "low", "cvss": "0.0"}, "0.0"),
    ({"vtype": "misconfig", "severity": "medium", "cvss": "N/A"}, "N/A"),
    ({"vtype": "misconfig", "severity": "medium", "cvss": False}, "N/A"),
    ({"vtype": "misconfig", "severity": "medium", "cvss": 11}, "N/A"),
    ({"vtype": "misconfig", "severity": "medium", "cvss": "nan"}, "N/A"),
    ({"vtype": "cves", "severity": "high", "poc": "CVE: example\nCVSS: 8.1"}, "8.1"),
    ({"vtype": "cves", "severity": "high", "poc": "CVSS: 8.1.", "cvss": "7.2"}, "8.1"),
    ({"vtype": "cves", "severity": "high", "poc": "CVSS:3.1/AV:N/AC:L", "cvss": "7.2"}, "7.2"),
    ({"vtype": "cves", "severity": "high", "poc": "CVSS: 50"}, "N/A"),
    ({"vtype": "unknown", "severity": "high"}, "N/A"),
])
def test_cvss_policy_preserves_recorded_scores_without_inventing_mismatched_defaults(finding, expected):
    assert reporter._finding_cvss(finding) == expected


def test_unscored_low_csp_is_na_in_both_summaries_and_details(tmp_path):
    finding = reporter.parse_custom_line(
        "[LOW] Missing Content-Security-Policy (CSP) response header — https://example.invalid", "misconfig")
    html = reporter.render_html_report([finding], "example.invalid", str(tmp_path), "", "", "VAPT")
    md = reporter.render_markdown_report([finding], "example.invalid", str(tmp_path), "", "", "VAPT")
    assert "<td>N/A</td>" in html and "CVSS: N/A" in html
    assert "| low | N/A | example.invalid |" in md
    assert "**Severity:** low | **CVSS:** N/A" in md
    assert "CVSS: 5.3" not in html and "**CVSS:** 5.3" not in md


@pytest.mark.parametrize("recorded,expected", [(None, "N/A"), (0.0, "0.0"), ("2.1", "2.1")])
def test_flat_json_loader_does_not_reintroduce_mismatched_template_score(tmp_path, recorded, expected):
    row = {"type": "misconfig", "severity": "low", "url": "https://example.invalid",
           "detail": "Missing CSP", "evidence": "Recorded response headers", "cvss": recorded}
    (tmp_path / "finding_csp.json").write_text(json.dumps(row))
    finding = reporter.load_findings(str(tmp_path))[0]
    assert finding["cvss"] == expected
    assert reporter._finding_cvss(finding) == expected


def _session(tmp_path):
    findings = tmp_path / "findings/example.invalid/sessions/s1"
    recon = tmp_path / "recon/example.invalid/sessions/s1"
    reports = tmp_path / "reports/example.invalid/sessions/s1"
    findings.mkdir(parents=True)
    (recon / "scope").mkdir(parents=True)
    reports.mkdir(parents=True)
    (recon / "scope/allow.txt").write_text("example.invalid\n")
    return findings, recon, reports


def test_report_methodology_is_derived_from_this_session_manifest_not_tools_or_files(tmp_path):
    findings, recon, reports = _session(tmp_path)
    (findings / "phase_manifest.json").write_text(json.dumps({"phases": [
        {"phase": "RECON", "status": "ran", "exit_code": 0, "command": "fixture --cookie SECRET"},
        {"phase": "API FUZZ", "status": "failed", "exit_code": 7, "command": "fixture-api"},
        {"phase": "UNPROVEN", "status": "ran"},
    ]}))
    # Existing directories and neighboring sessions must not imply model use or
    # tool execution. Only this session's explicit invocation records are shown.
    (recon / "brain").mkdir()
    (recon / "brain/triage.json").write_text("{}")
    other = findings.parent / "s2"
    other.mkdir()
    (other / "phase_manifest.json").write_text(json.dumps({"phases": [
        {"phase": "FOREIGN", "status": "ran", "command": "another-session"}]}))
    evidence = reporter._methodology_evidence(str(reports))
    assert evidence["scope"] == ["example.invalid"]
    assert [row["phase"] for row in evidence["phases"]] == ["RECON", "API FUZZ"]
    html = reporter.render_html_report([], "example.invalid", str(reports), "", "", "VAPT")
    md = reporter.render_markdown_report([], "example.invalid", str(reports), "", "", "VAPT")
    assert "<td>API FUZZ</td><td>failed</td><td>7</td>" in html
    assert "| API FUZZ | failed | 7 |" in md
    for text in (html, md):
        assert "Recorded exact-host allowlist" in text
        assert "SECRET" not in text and "FOREIGN" not in text and "UNPROVEN" not in text
        for claim in ("AI-assisted triage", "Automated and manual testing", "Controlled PoC to confirm impact"):
            assert claim not in text
    assert "Tools Used" not in html


@pytest.mark.parametrize("manifest", [None, "{broken", '{"phases": 3}', '{"phases": []}'])
def test_missing_or_invalid_methodology_evidence_never_implies_activities(tmp_path, manifest):
    findings, _, reports = _session(tmp_path)
    if manifest is not None:
        (findings / "phase_manifest.json").write_text(manifest)
    evidence = reporter._methodology_evidence(str(reports))
    assert evidence["phases"] == []
    assert evidence["manifest_state"] != "recorded"
    html = reporter.render_html_report([], "example.invalid", str(reports), "", "", "VAPT")
    assert "Phase execution:" in html
    assert "Subdomain enumeration, port scanning" not in html
    assert "AI-assisted triage" not in html


def test_execution_labels_are_escaped_and_commands_are_never_rendered(tmp_path):
    findings, _, reports = _session(tmp_path)
    (findings / "phase_manifest.json").write_text(json.dumps({"phases": [
        {"phase": "<script>bad</script>|phase", "status": "failed", "exit_code": 7,
         "command": "fixture --password DO-NOT-RENDER"}]}))
    evidence = reporter._methodology_evidence(str(reports))
    html = reporter._execution_evidence_html(evidence)
    md = reporter._methodology_md(evidence)
    assert "<script>bad</script>" not in html
    assert "&lt;script&gt;bad&lt;/script&gt;" in html
    assert "\\|phase" in md
    assert "DO-NOT-RENDER" not in html + md

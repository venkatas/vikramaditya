"""Session-replay honesty fixes."""
import json
from pathlib import Path

import email_audit
import hunt
import nomore403_audit as nm
import phase_manifest as pm
import reporter


def test_js_filter_drops_concatenated_junk_before_cap():
    lines = [
        "404page.html?404;http://cdn.example/404.js",
        ";",
        "http://a.example/x.jshttp://b.example/y.js",
        "https://cdn.example/static/app.js",
        "https://cdn.example/vendor/lib.js?v=1",
        "https://cdn.example/not-js",
        "relative/file.js",
    ]
    ordered, rejected, unique = hunt.select_js_analysis_urls(lines)
    assert rejected == 4
    assert unique == 7
    assert ordered[:2] == [
        "https://cdn.example/static/app.js",
        "https://cdn.example/vendor/lib.js?v=1",
    ]
    assert "404page.html?404;http://cdn.example/404.js" not in ordered
    assert all(";" not in url for url in ordered)
    assert ordered[:1] == ["https://cdn.example/static/app.js"]


def test_js_download_degrade_reason_includes_curl_rc_histogram(tmp_path):
    dl = tmp_path / "downloaded"
    dl.mkdir()
    header = hunt._JS_MANIFEST_HEADER
    rows = [header, "a.js\thttps://h/a.js\t7\t0\t0\tabc"]
    for i in range(3):
        rows.append("b%d.js\thttps://h/b%d.js\t56\t0\t0\tabc" % (i, i))
    (dl / "manifest.tsv").write_text("\n".join(rows) + "\n")
    reason = hunt._js_download_failure_summary(str(dl), 4, 0)
    assert "curl_7=1" in reason
    assert "curl_56=3" in reason


class _Dns:
    def __init__(self, records):
        self.records = records

    def query(self, name, rtype):
        return list(self.records.get((name, rtype), []))


def test_dmarc_absent_alignment_tags_are_not_claimed_as_explicit():
    domain = "example.invalid"
    dns = _Dns({
        ("_dmarc.%s" % domain, "TXT"): ["v=DMARC1; p=none; rua=mailto:dmarc@example.invalid"],
    })
    result = email_audit.audit_dmarc(domain, dns, "domain")
    details = " ".join(issue["detail"] for issue in result["issues"])
    assert "default relaxed alignment" in details
    assert "tag absent" in details
    assert "uses adkim=r" not in details
    assert "uses aspf=r" not in details
    assert result["alignment"]["adkim_tag"] == "absent"
    assert result["alignment"]["aspf_tag"] == "absent"


def test_dmarc_explicit_relaxed_tags_still_say_uses_r():
    domain = "example.invalid"
    dns = _Dns({
        ("_dmarc.%s" % domain, "TXT"): ["v=DMARC1; p=none; adkim=r; aspf=r"],
    })
    result = email_audit.audit_dmarc(domain, dns, "domain")
    details = " ".join(issue["detail"] for issue in result["issues"])
    assert "uses adkim=r" in details
    assert "uses aspf=r" in details
    assert "tag absent" not in details


def test_204_and_options_preflight_are_not_bypass_hits():
    results = [
        {"status_code": 403, "content_length": 9, "technique": "default", "payload": "https://api.example"},
        {"status_code": 204, "content_length": 0, "technique": "OPTIONS", "payload": "OPTIONS https://api.example"},
        {"status_code": 204, "content_length": 0, "technique": "verbs", "payload": "https://api.example method=OPTIONS"},
        {"status_code": 200, "content_length": 0, "technique": "cors-preflight", "payload": "OPTIONS"},
    ]
    assert nm.calibrate_hits(results, 403) == []

    content = [
        {"status_code": 403, "content_length": 9, "technique": "default", "payload": "https://api.example"},
        {"status_code": 200, "content_length": 512, "technique": "hdr-ip", "payload": "https://api.example"},
    ]
    hits = nm.calibrate_hits(content, 403)
    assert len(hits) == 1 and hits[0]["technique"] == "hdr-ip"


def test_email_posture_cap_is_labelled_in_report(tmp_path):
    email_auth = tmp_path / "email_auth"
    email_auth.mkdir()
    (email_auth / "findings.json").write_text(json.dumps([
        {
            "severity": "high",
            "cvss": "8.1",
            "vuln_class": "email_spf",
            "title": "SPF exceeds the DNS lookup limit",
            "endpoint": "dns:spf:example.invalid",
            "result": "confirmed",
            "notes": "The published SPF tree requires 17 DNS lookups.",
        },
        {
            "severity": "medium",
            "title": "DKIM RSA key is below modern hardening guidance",
            "endpoint": "dns:dkim:example.invalid",
            "notes": "Selector google appears to use an RSA key around 1024 bits.",
            "evidence": "google._domainkey.example.invalid",
        },
        {
            "severity": "medium",
            "title": "DKIM RSA key is below modern hardening guidance",
            "endpoint": "dns:dkim:example.invalid",
            "notes": "Selector selector2 appears to use an RSA key around 1024 bits.",
            "selector": "selector2",
        },
    ]))

    findings = reporter.load_findings(str(tmp_path))
    spf = next(f for f in findings if "SPF exceeds" in f["title"])
    assert spf["severity"] == "medium"
    assert spf["original_severity"] == "high"
    assert spf["severity_label"] == "medium, capped from high"
    assert reporter._apply_verification_gating([spf])[0]["severity"] == "medium"

    html = reporter.render_html_report(findings, "example.invalid", str(tmp_path), "", "", "VAPT")
    markdown = reporter.render_markdown_report(
        findings, "example.invalid", str(tmp_path), "", "", "VAPT"
    )
    assert "medium, capped from high" in html
    assert "medium, capped from high" in markdown

    dkim_titles = [f["title"] for f in findings if "DKIM RSA key" in f["title"]]
    assert any("google" in title for title in dkim_titles)
    assert any("selector2" in title for title in dkim_titles)
    assert len(set(dkim_titles)) == 2


def test_403_candidate_prefix_stays_out_of_the_report(tmp_path):
    fdir = tmp_path / "auth_bypass"
    fdir.mkdir()
    (fdir / "403_bypass_hits.txt").write_text(
        "[403-BYPASS-CANDIDATE] https://api.example  403->204  technique=OPTIONS\n"
    )
    findings = reporter.load_findings(str(tmp_path))
    assert findings == []


def test_phase_manifest_distinguishes_never_invoked_from_timeout(tmp_path):
    assert pm.invocation_outcome(None) == pm.PHASE_NEVER_INVOKED
    assert pm.derive_status(exit_code=-9) == pm.PHASE_ABORTED
    pm.record_phase(str(tmp_path), "SCAN", exit_code=-9)
    rec = pm.read_manifest(str(tmp_path))["phases"][0]
    assert rec["outcome"] == "timeout"
    assert rec["exit_code"] == -9
    assert rec["signal"] == 9
    assert rec["timed_out"] is True
    assert rec["status"] == pm.PHASE_ABORTED
    assert rec["outcome"] != pm.PHASE_NEVER_INVOKED


def test_scanner_does_not_precreate_unrun_class_dirs():
    source = Path(__file__).resolve().parent.parent.joinpath("scanner.sh").read_text()
    start = source.index('mkdir -p "$FINDINGS_DIR"/')
    mkdir_line = source[start:source.index("\n", start)]
    for name in ("idor", "jwt", "ssrf", "graphql"):
        assert name not in mkdir_line
    assert "FINDINGS_DIR/upload/status.json" in source

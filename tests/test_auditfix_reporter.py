"""Regression tests for v10.0.2 reporter.py audit fixes (clientd.com run).

Covers:
1. Collapsed unconfirmed-CVE INFO item gets an explicit per-severity CVSS (0.0)
   instead of inheriting the misconfig template's hardcoded 5.3.
2. That item's rich detail (matched CVE IDs + "validate before reporting"
   warning) is surfaced in the report (folded into poc, since the renderer
   uses poc-before-detail precedence).
3. email_auth (and other) findings render their per-area "Fix:" remediation
   instead of always using the single template's generic DMARC advice.
4. A "Recon / Host & Port Inventory" chapter is rendered from live/httpx +
   ports/nmap artefacts, listing hosts/ports even with no mapped finding.
5. A "Tooling & Coverage Limitations" chapter renders coverage.json when
   present and degrades gracefully when absent.
"""
import json
import os
import re

import reporter


# ---------------------------------------------------------------------------
# Fix 3 helper — per-finding remediation resolution
# ---------------------------------------------------------------------------
def test_finding_remediation_prefers_fix_clause_from_notes():
    tmpl = {"remediation": "GENERIC DMARC TEMPLATE ADVICE"}
    f = {
        "vtype": "email_auth",
        "notes": ("The domain does not publish an _mta-sts TXT record.\n\n"
                  "Fix: If you want stronger SMTP transport hardening, publish "
                  "MTA-STS and pair it with TLS-RPT."),
    }
    out = reporter._finding_remediation(f, tmpl)
    assert "MTA-STS" in out
    assert "GENERIC DMARC TEMPLATE ADVICE" not in out


def test_finding_remediation_explicit_key_wins():
    tmpl = {"remediation": "TEMPLATE"}
    f = {"remediation": "EXPLICIT FIX", "notes": "Fix: from notes"}
    assert reporter._finding_remediation(f, tmpl) == "EXPLICIT FIX"


def test_finding_remediation_falls_back_to_template():
    tmpl = {"remediation": "TEMPLATE FALLBACK"}
    f = {"vtype": "email_auth", "notes": "no fix marker here"}
    assert reporter._finding_remediation(f, tmpl) == "TEMPLATE FALLBACK"


# ---------------------------------------------------------------------------
# Fixes 1 + 2 — collapsed unconfirmed-CVE INFO item
# ---------------------------------------------------------------------------
def _write_unconfirmed_cves(tmp_path):
    cves_dir = tmp_path / "findings" / "t.example" / "sessions" / "s1" / "cves"
    cves_dir.mkdir(parents=True)
    (cves_dir / "cve_database_matches.json").write_text(json.dumps({
        "target": "t.example",
        "cves_found": [
            # No matched_version / confirmed -> collapsed into the INFO item.
            {"cve_id": "CVE-1999-0001", "product": "php", "cvss_score": "10.0"},
            {"cve_id": "CVE-2014-0002", "product": "bootstrap", "cvss_score": "7.5"},
        ],
    }))
    return str(cves_dir.parent)


def test_collapsed_cve_item_has_info_cvss_not_template_5_3(tmp_path):
    findings_dir = _write_unconfirmed_cves(tmp_path)
    findings = reporter.load_findings(findings_dir)
    collapsed = [f for f in findings
                 if "Unconfirmed tech-stack CVE" in f.get("title", "")]
    assert len(collapsed) == 1
    item = collapsed[0]
    assert item["severity"] == "info"
    # Must carry an explicit per-severity CVSS so it doesn't fall back to the
    # misconfig template's hardcoded MEDIUM-band 5.3.
    assert item["cvss"] == reporter.CVSS_DEFAULT["info"] == "0.0"


def test_collapsed_cve_item_renders_0_0_not_5_3_in_html(tmp_path):
    findings_dir = _write_unconfirmed_cves(tmp_path)
    findings = reporter.load_findings(findings_dir)
    html = reporter.render_html_report(
        findings, "t.example", findings_dir, "Acme", "Tester", "VAPT")
    # Locate the collapsed finding's detail block and assert its CVSS line.
    # The misconfig template default is 5.3; that must NOT be what renders.
    idx = html.find("Unconfirmed tech-stack CVE")
    assert idx != -1
    # Look at the detail card header that follows the summary row. The CVSS
    # value for an INFO context item must be 0.0, never 5.3.
    detail_idx = html.find("Unconfirmed tech-stack CVE", idx + 1)
    window = html[detail_idx:detail_idx + 1200] if detail_idx != -1 else html[idx:idx + 1200]
    assert "CVSS: 0.0" in window
    assert "CVSS: 5.3" not in window


def test_collapsed_cve_item_surfaces_detail_and_warning(tmp_path):
    findings_dir = _write_unconfirmed_cves(tmp_path)
    findings = reporter.load_findings(findings_dir)
    item = next(f for f in findings
                if "Unconfirmed tech-stack CVE" in f.get("title", ""))
    # The rich detail (example CVE list + validate-before-reporting warning)
    # must be inside poc, because renderers surface poc before detail.
    assert "CVE-1999-0001" in item["poc"]
    assert "must not be reported as-is" in item["poc"]
    # And it actually reaches the HTML PoC block.
    html = reporter.render_html_report(
        findings, "t.example", findings_dir, "", "", "VAPT")
    assert "CVE-1999-0001 (php)" in html
    assert "must not be reported as-is" in html


# ---------------------------------------------------------------------------
# Fix 3 (end to end) — email_auth per-area Fix appears in rendered report
# ---------------------------------------------------------------------------
def test_email_auth_per_area_fix_rendered(tmp_path):
    sess = tmp_path / "findings" / "t.example" / "sessions" / "s1"
    ea = sess / "email_auth"
    ea.mkdir(parents=True)
    (ea / "findings.json").write_text(json.dumps([
        {
            "severity": "low", "vuln_class": "email_dnssec", "area": "dnssec",
            "result": "confirmed",
            "title": "No DNSSEC DS record found",
            "notes": ("The domain does not appear to have a DS record published "
                      "at the parent zone.\n\nFix: Enable DNSSEC if the registrar "
                      "and DNS provider support it to harden DNS integrity."),
            "endpoint": "dns:dnssec:t.example",
        },
    ]))
    findings = reporter.load_findings(str(sess))
    dnssec = next(f for f in findings if f["vtype"] == "email_auth")
    html = reporter.render_html_report(
        findings, "t.example", str(sess), "", "", "VAPT")
    md = reporter.render_markdown_report(
        findings, "t.example", str(sess), "", "", "VAPT")
    # Per-area DNSSEC fix must render, not the generic DMARC template advice.
    assert "Enable DNSSEC" in html
    assert "Enable DNSSEC" in md
    generic = reporter.VULN_TEMPLATES["email_auth"]["remediation"]
    # The generic DMARC advice should not be the *Remediation* text for DNSSEC.
    assert f"Remediation</h4>\n    <p style=\"margin:0 0 10px\">{generic}" not in html


# ---------------------------------------------------------------------------
# Fix 4 — Recon / Host & Port Inventory chapter
# ---------------------------------------------------------------------------
def _write_recon(tmp_path):
    recon = tmp_path / "recon" / "t.example" / "sessions" / "s1"
    live = recon / "live"
    ports = recon / "ports"
    live.mkdir(parents=True)
    ports.mkdir(parents=True)
    (live / "httpx_full.txt").write_text(
        "https://t.example [200] [6243] [Home Page] [148.72.90.65] "
        "[IIS:10.0,Microsoft ASP.NET]\n"
        "http://mssql.t.example [404] [315] [Not Found] [148.72.90.65] "
        "[Microsoft HTTPAPI:2.0]\n")
    (live / "urls.txt").write_text(
        "https://t.example\nhttp://mssql.t.example\n")
    (live / "ips.txt").write_text("148.72.90.65\n")
    (ports / "open_ports.txt").write_text(
        "21/open\n443/open\n80/open\n8443/open\n990/open\n")
    (ports / "nmap_greppable.txt").write_text(
        "Host: 148.72.90.65 ()\tPorts: "
        "21/open/tcp//ftp//Microsoft ftpd/, "
        "990/open/tcp//ssl|ftp//Microsoft ftpd/, "
        "8443/open/tcp//ssl|https-alt?///\n")
    return str(recon)


def test_recon_inventory_lists_hosts_and_ports(tmp_path):
    recon_dir = _write_recon(tmp_path)
    out = reporter._render_recon_inventory_html(recon_dir, "t.example")
    assert "Recon / Host &amp; Port Inventory" in out
    # mssql host (no finding) is still listed.
    assert "mssql.t.example" in out
    # FTP 21/990 and 8443 ports appear.
    assert "21/open" in out
    assert "990/open" in out
    assert "8443/open" in out
    # nmap service detail folded in for FTP.
    assert "Microsoft ftpd" in out
    # IP surfaced.
    assert "148.72.90.65" in out


def test_recon_inventory_graceful_when_absent(tmp_path):
    # v10.0.2 round-2 (grok #7 / fix H): when there are no hosts AND no ports,
    # the chapter degrades SILENTLY (returns "") to match the coverage chapter's
    # contract — no noisy "inventory unavailable" block with raw filesystem paths.
    empty = tmp_path / "recon" / "t.example" / "sessions" / "empty"
    empty.mkdir(parents=True)
    out = reporter._render_recon_inventory_html(str(empty), "t.example")
    assert out == "", "empty recon inventory must render nothing, not a noisy chapter"


def test_recon_inventory_in_full_html(tmp_path):
    recon_dir = _write_recon(tmp_path)
    html = reporter.render_html_report([], "t.example", recon_dir, "", "", "VAPT")
    assert "mssql.t.example" in html
    assert "8443/open" in html
    assert 'id="recon-inventory"' in html


# ---------------------------------------------------------------------------
# Fix 5 — Tooling & Coverage Limitations chapter
# ---------------------------------------------------------------------------
def test_coverage_limitations_rendered_when_present(tmp_path):
    sess = tmp_path / "findings" / "t.example" / "sessions" / "s1"
    sess.mkdir(parents=True)
    (sess / "coverage.json").write_text(json.dumps([
        {"tool": "nuclei", "reason": "Rate-limited by WAF; CVE sweep partial."},
        {"tool": "sqlmap", "reason": "Skipped — no parameterised endpoints."},
    ]))
    out = reporter._render_coverage_limitations_html(str(sess))
    assert "Tooling &amp; Coverage Limitations" in out
    assert "nuclei" in out
    assert "Rate-limited by WAF" in out
    assert "sqlmap" in out


def test_coverage_limitations_graceful_when_absent(tmp_path):
    sess = tmp_path / "findings" / "t.example" / "sessions" / "none"
    sess.mkdir(parents=True)
    # No coverage.json -> empty string (no chapter, no noise).
    assert reporter._render_coverage_limitations_html(str(sess)) == ""


def test_coverage_limitations_graceful_on_malformed(tmp_path):
    sess = tmp_path / "findings" / "t.example" / "sessions" / "bad"
    sess.mkdir(parents=True)
    (sess / "coverage.json").write_text("{not valid json")
    assert reporter._render_coverage_limitations_html(str(sess)) == ""


def test_resolve_dirs_handles_relative_paths():
    # Relative findings path (no leading slash) must still map to recon/.
    recon, findings = reporter._resolve_recon_findings_dirs(
        "findings/t.example/sessions/s1")
    assert recon == "recon/t.example/sessions/s1"
    assert findings == "findings/t.example/sessions/s1"
    # Relative recon path maps to findings/.
    recon2, findings2 = reporter._resolve_recon_findings_dirs(
        "recon/t.example/sessions/s1")
    assert recon2 == "recon/t.example/sessions/s1"
    assert findings2 == "findings/t.example/sessions/s1"
    # Absolute path still works.
    r3, f3 = reporter._resolve_recon_findings_dirs(
        "/x/findings/t.example/sessions/s1")
    assert r3 == "/x/recon/t.example/sessions/s1"


def test_coverage_limitations_resolves_from_recon_dir(tmp_path):
    # Renderer is called with the recon dir; coverage.json lives under findings.
    base = tmp_path / "x"
    recon = base / "recon" / "t.example" / "sessions" / "s1"
    findings = base / "findings" / "t.example" / "sessions" / "s1"
    recon.mkdir(parents=True)
    findings.mkdir(parents=True)
    (findings / "coverage.json").write_text(json.dumps(
        [{"tool": "amass", "reason": "API key absent."}]))
    out = reporter._render_coverage_limitations_html(str(recon))
    assert "amass" in out
    assert "API key absent" in out

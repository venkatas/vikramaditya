"""Regression tests for v10.0.3 reporter.py audit-fix-2 (retro: codex + grok).

These cover two correctness regressions an earlier fix batch introduced /
left incomplete in the new Recon-Inventory + Coverage chapters:

F (MED — chapters dead in production):
    process_findings_dir() threads the *generated report* dir
    (``reports/<t>/sessions/<id>``) into render_*_report, but
    _resolve_recon_findings_dirs() only understood ``recon/`` and
    ``findings/`` segments. A ``reports/`` path matched neither, so both
    chapters looked under reports/.../live, reports/.../ports, and
    reports/.../coverage.json (all non-existent) and rendered empty in every
    REAL report. The prior unit tests hid this by passing a recon/findings
    dir straight into the renderer. The decisive test here drives the full
    process_findings_dir() path and proves the chapters populate from a
    reports/ dir.

H (LOW — leaked filesystem paths):
    _render_recon_inventory_html always emitted a full H2 + "inventory
    unavailable" block with raw filesystem paths when live/ and ports/ were
    empty — unlike the coverage chapter which silently returns ''. It must
    now return '' when there is nothing to show.
"""
import json
import os

import reporter


# ---------------------------------------------------------------------------
# Fix F (unit) — _resolve_recon_findings_dirs maps reports/ -> recon/+findings/
# ---------------------------------------------------------------------------
def test_resolve_dirs_maps_reports_to_recon_and_findings_relative():
    recon, findings = reporter._resolve_recon_findings_dirs(
        "reports/t.example/sessions/s1")
    assert recon == "recon/t.example/sessions/s1"
    assert findings == "findings/t.example/sessions/s1"


def test_resolve_dirs_maps_reports_to_recon_and_findings_absolute():
    recon, findings = reporter._resolve_recon_findings_dirs(
        "/base/reports/t.example/sessions/s1")
    assert recon == "/base/recon/t.example/sessions/s1"
    assert findings == "/base/findings/t.example/sessions/s1"


def test_resolve_dirs_reports_only_swaps_first_segment():
    # A literal "reports" deeper in the path (e.g. a target literally named
    # "reports") must be preserved; only the leading tree segment is swapped.
    recon, findings = reporter._resolve_recon_findings_dirs(
        "/base/reports/reports/sessions/s1")
    assert recon == "/base/recon/reports/sessions/s1"
    assert findings == "/base/findings/reports/sessions/s1"


def test_resolve_dirs_recon_and_findings_still_work():
    # Don't regress the existing two layouts.
    r1, f1 = reporter._resolve_recon_findings_dirs("recon/t/sessions/s1")
    assert (r1, f1) == ("recon/t/sessions/s1", "findings/t/sessions/s1")
    r2, f2 = reporter._resolve_recon_findings_dirs("/x/findings/t/sessions/s1")
    assert r2 == "/x/recon/t/sessions/s1"
    assert f2 == "/x/findings/t/sessions/s1"


# ---------------------------------------------------------------------------
# Fix F (end-to-end) — chapters populate from a reports/ dir via
# process_findings_dir(), the REAL production entry point.
# ---------------------------------------------------------------------------
def _build_session_tree(base):
    """Create sibling recon/, findings/, reports/ trees sharing one session id,
    matching the production layout under BASE_DIR."""
    target, sess = "t.example", "s1"
    recon = base / "recon" / target / "sessions" / sess
    findings = base / "findings" / target / "sessions" / sess
    reports = base / "reports" / target / "sessions" / sess
    live = recon / "live"
    ports = recon / "ports"
    live.mkdir(parents=True)
    ports.mkdir(parents=True)
    findings.mkdir(parents=True)
    reports.mkdir(parents=True)

    (live / "httpx_full.txt").write_text(
        "https://t.example [200] [6243] [Home Page] [148.72.90.65] "
        "[IIS:10.0,Microsoft ASP.NET]\n"
        "http://mssql.t.example [404] [315] [Not Found] [148.72.90.65] "
        "[Microsoft HTTPAPI:2.0]\n")
    (live / "ips.txt").write_text("148.72.90.65\n")
    (ports / "open_ports.txt").write_text("21/open\n8443/open\n")
    (ports / "nmap_greppable.txt").write_text(
        "Host: 148.72.90.65 ()\tPorts: 21/open/tcp//ftp//Microsoft ftpd/\n")
    (findings / "coverage.json").write_text(json.dumps(
        [{"tool": "nuclei", "reason": "Rate-limited by WAF; CVE sweep partial."}]))
    return target, sess, str(findings), str(reports)


def test_process_findings_dir_populates_chapters_from_reports_dir(tmp_path, monkeypatch):
    """The decisive regression: drive the production path and prove the
    Recon-Inventory + Coverage chapters render real data sourced from the
    sibling recon/ and findings/ trees — even though the renderer is handed a
    reports/ dir. Before the fix both chapters came out empty."""
    base = tmp_path / "base"
    target, sess, findings_dir, reports_dir = _build_session_tree(base)
    # Force resolve_target_and_report_dir() to return our reports/ session dir
    # (this is exactly the value it computes in production: REPORTS_DIR/<t>/
    # sessions/<id>). Using the env hook keeps the test independent of BASE_DIR.
    monkeypatch.setenv("REPORTS_OUT_DIR", reports_dir)

    n, found, out_report_dir, html, md = reporter.process_findings_dir(
        findings_dir, client="Acme", consultant="Tester")

    # Sanity: we really went through the reports/ dir, not a recon/findings one.
    assert out_report_dir == reports_dir
    assert "reports" in out_report_dir.split(os.sep)

    # Recon-Inventory chapter populated from the SIBLING recon/ tree.
    assert 'id="recon-inventory"' in html
    assert "mssql.t.example" in html       # host with no mapped finding
    assert "8443/open" in html             # open port
    assert "Microsoft ftpd" in html        # nmap service detail
    assert "148.72.90.65" in html          # resolved IP

    # Coverage chapter populated from the SIBLING findings/ tree.
    assert 'id="coverage-limitations"' in html
    assert "nuclei" in html
    assert "Rate-limited by WAF" in html

    # And it must NOT have looked under reports/ (which has no live/ or
    # coverage.json) — i.e. the "inventory unavailable" degraded note and the
    # raw reports/ path must be absent.
    assert "inventory unavailable" not in html


def test_process_findings_dir_recon_resolution_independent_of_findings_layout(
        tmp_path, monkeypatch):
    """Even when no recon artefacts exist, the reports/ mapping must resolve to
    recon/ (not reports/) so the chapter is correctly OMITTED (Fix H), and the
    coverage chapter still resolves to findings/."""
    base = tmp_path / "base"
    target, sess = "t.example", "s1"
    findings = base / "findings" / target / "sessions" / sess
    reports = base / "reports" / target / "sessions" / sess
    findings.mkdir(parents=True)
    reports.mkdir(parents=True)
    # recon/ tree is intentionally absent -> no host/port artefacts.
    (findings / "coverage.json").write_text(json.dumps(
        [{"tool": "sqlmap", "reason": "No parameterised endpoints."}]))
    monkeypatch.setenv("REPORTS_OUT_DIR", str(reports))

    _, _, _, html, _ = reporter.process_findings_dir(str(findings))

    # Coverage still resolves through findings/.
    assert "sqlmap" in html
    # Recon-Inventory chapter omitted entirely (Fix H), no leaked path note.
    assert "inventory unavailable" not in html
    assert 'id="recon-inventory"' not in html


# ---------------------------------------------------------------------------
# Fix H — empty recon inventory renders NOTHING (no H2, no leaked paths).
# ---------------------------------------------------------------------------
def test_recon_inventory_empty_returns_empty_string(tmp_path):
    empty = tmp_path / "recon" / "t.example" / "sessions" / "empty"
    empty.mkdir(parents=True)
    out = reporter._render_recon_inventory_html(str(empty), "t.example")
    assert out == ""


def test_recon_inventory_empty_leaks_no_filesystem_path(tmp_path):
    empty = tmp_path / "recon" / "t.example" / "sessions" / "empty"
    empty.mkdir(parents=True)
    out = reporter._render_recon_inventory_html(str(empty), "t.example")
    # The old buggy block embedded the raw live/ and ports/ paths and an H2.
    assert "inventory unavailable" not in out
    assert "Recon / Host &amp; Port Inventory" not in out
    assert str(empty) not in out


def test_recon_inventory_still_renders_when_present(tmp_path):
    # Don't regress the populated case.
    recon = tmp_path / "recon" / "t.example" / "sessions" / "s1"
    (recon / "live").mkdir(parents=True)
    (recon / "ports").mkdir(parents=True)
    (recon / "live" / "httpx_full.txt").write_text(
        "https://t.example [200] [10] [Home] [1.2.3.4] [nginx]\n")
    (recon / "ports" / "open_ports.txt").write_text("443/open\n")
    out = reporter._render_recon_inventory_html(str(recon), "t.example")
    assert "Recon / Host &amp; Port Inventory" in out
    assert "443/open" in out

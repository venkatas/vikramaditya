"""Regression tests for v7.4.5 — empty-findings diagnostic section.

Before v7.4.5, ``reporter.py`` rendered a completely blank "No findings"
page for any session where the scanner found nothing. Operators on the
receiving end (see github issue #2, Harry53) reasonably assumed the tool
was broken. That drove three consecutive fix rounds chasing empty-report
issues that were actually scope / target-shape mismatches.

v7.4.5 always emits a Scan Diagnostics appendix: recon counts, per-subdir
payload line counts, and context-appropriate next-step hints. The report
now tells the operator *what was scanned* and *why the findings list may
look thin*, not just "No findings."

Tests pin:
- Diagnostics collector reads recon + findings artefacts correctly.
- Hints are generated for each of the three target-shape patterns
  (API-only, default Swagger UI, scope-locked apex).
- HTML renderer emits the section regardless of findings count.
- Both path layouts (passing findings/ vs recon/) resolve the other side.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporter import _collect_scan_diagnostics, _render_scan_diagnostics_html


# ---------------------------------------------------------------------------
# Helpers to build fake session layouts
# ---------------------------------------------------------------------------


def _seed_recon(tmp_path, *, live=0, urls=0, params=0, js=0,
                 specs=0, ops=0, subs=0, ports=0):
    """Create a fake recon dir with the requested artefact counts."""
    for sub in ("live", "urls", "subdomains", "ports", "api_specs", "js"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)

    def _write(path, count):
        with open(path, "w") as fh:
            for i in range(count):
                fh.write(f"line{i}\n")

    _write(tmp_path / "live" / "urls.txt", live)
    _write(tmp_path / "urls" / "all.txt", urls)
    _write(tmp_path / "urls" / "with_params.txt", params)
    _write(tmp_path / "urls" / "js_files.txt", js)
    _write(tmp_path / "api_specs" / "spec_urls.txt", specs)
    _write(tmp_path / "api_specs" / "all_operations.txt", ops)
    _write(tmp_path / "subdomains" / "all.txt", subs)
    _write(tmp_path / "ports" / "open_ports.txt", ports)
    return tmp_path


# ---------------------------------------------------------------------------
# Collector behaviour
# ---------------------------------------------------------------------------


class TestDiagnosticsCollector:
    def test_reads_recon_counts_correctly(self, tmp_path) -> None:
        _seed_recon(tmp_path, live=5, urls=100, params=20, js=3,
                     specs=1, ops=12, subs=1, ports=2)
        diag = _collect_scan_diagnostics(str(tmp_path), "target.com")
        assert diag["live_hosts"] == 5
        assert diag["total_urls"] == 100
        assert diag["params_urls"] == 20
        assert diag["js_files"] == 3
        assert diag["api_specs"] == 1
        assert diag["api_operations"] == 12
        assert diag["subdomains"] == 1
        assert diag["ports_open"] == 2

    def test_missing_recon_files_do_not_crash(self, tmp_path) -> None:
        """Brand-new session with nothing populated must return zeros."""
        diag = _collect_scan_diagnostics(str(tmp_path), "target.com")
        assert diag["live_hosts"] == 0
        assert diag["total_urls"] == 0
        assert diag["hints"] is not None  # list, even if empty

    def test_findings_path_resolves_to_recon_path(self, tmp_path) -> None:
        """Operator passes findings/<target>/… — collector must find recon/ sibling."""
        findings = tmp_path / "findings" / "x.com" / "sessions" / "sess01"
        recon = tmp_path / "recon" / "x.com" / "sessions" / "sess01"
        _seed_recon(recon, live=3, urls=50)
        findings.mkdir(parents=True)
        (findings / "xss").mkdir()
        (findings / "xss" / "dalfox.txt").write_text("HIGH https://x/?q=1\n")

        diag = _collect_scan_diagnostics(str(findings), "x.com")
        # Recon counts come from the sibling recon/ path.
        assert diag["live_hosts"] == 3
        assert diag["total_urls"] == 50
        # Finding payloads come from the findings/ path.
        assert diag["subdir_payload_counts"].get("xss") == 1

    def test_hidden_subdirs_are_ignored(self, tmp_path) -> None:
        """v7.4.6 regression — .tmp / .cache / .git must not appear as finding classes."""
        findings = tmp_path / "findings" / "x.com" / "sessions" / "sess01"
        recon = tmp_path / "recon" / "x.com" / "sessions" / "sess01"
        _seed_recon(recon)
        findings.mkdir(parents=True)
        for hidden in (".tmp", ".cache", ".git"):
            (findings / hidden).mkdir()
            (findings / hidden / "junk.txt").write_text("noise\n")
        (findings / "xss").mkdir()
        (findings / "xss" / "dalfox.txt").write_text("HIGH https://x/?q=1\n")

        diag = _collect_scan_diagnostics(str(findings), "x.com")
        for hidden in (".tmp", ".cache", ".git"):
            assert hidden not in diag["subdir_payload_counts"], (
                f"hidden dir {hidden!r} leaked into finding-class table"
            )
        assert "xss" in diag["subdir_payload_counts"]


# ---------------------------------------------------------------------------
# Hint generation — three target-shape patterns
# ---------------------------------------------------------------------------


class TestHintGeneration:
    def test_api_shape_triggers_creds_hint(self, tmp_path) -> None:
        """Few URLs + few JS + 1 live host → API-shape hint."""
        _seed_recon(tmp_path, live=1, urls=5, params=0, js=0)
        diag = _collect_scan_diagnostics(str(tmp_path), "api.target.com")
        hints_blob = " ".join(diag["hints"])
        assert "creds user:pass" in hints_blob or "authenticated" in hints_blob.lower()

    def test_webapp_shape_does_not_trigger_api_hint(self, tmp_path) -> None:
        """Normal webapp — many URLs, several JS files — skip API hint."""
        _seed_recon(tmp_path, live=10, urls=500, params=80, js=25)
        diag = _collect_scan_diagnostics(str(tmp_path), "www.target.com")
        hints_blob = " ".join(diag["hints"])
        assert "authenticated REST API" not in hints_blob

    def test_no_api_specs_with_urls_triggers_manual_path_hint(self, tmp_path) -> None:
        """Some URLs crawled but no specs — hint about common docs paths."""
        _seed_recon(tmp_path, live=5, urls=100, params=30, js=10, specs=0)
        diag = _collect_scan_diagnostics(str(tmp_path), "target.com")
        hints_blob = " ".join(diag["hints"])
        assert "api-docs" in hints_blob or "swagger" in hints_blob.lower()

    def test_zero_subdomains_triggers_scope_hint(self, tmp_path) -> None:
        """Apex-only scan with --scope-lock → suggest expanding."""
        _seed_recon(tmp_path, live=1, urls=10, params=2, js=1, subs=1)
        diag = _collect_scan_diagnostics(str(tmp_path), "target.com")
        hints_blob = " ".join(diag["hints"])
        assert "scope-lock" in hints_blob or "subdomains" in hints_blob.lower()


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------


class TestHTMLRenderer:
    def test_renders_even_on_empty_recon(self) -> None:
        """No recon data → still produces HTML with 'No finding subdirs'."""
        html = _render_scan_diagnostics_html({
            "live_hosts": 0, "total_urls": 0, "params_urls": 0, "js_files": 0,
            "api_specs": 0, "api_operations": 0, "subdomains": 0,
            "ports_open": 0, "subdir_payload_counts": {}, "hints": [],
        })
        assert "Scan Diagnostics" in html
        assert "No finding subdirs" in html

    def test_renders_recon_counts_in_table(self) -> None:
        html = _render_scan_diagnostics_html({
            "live_hosts": 5, "total_urls": 100, "params_urls": 20,
            "js_files": 3, "api_specs": 1, "api_operations": 12,
            "subdomains": 8, "ports_open": 2,
            "subdir_payload_counts": {"sqli": 2, "xss": 5},
            "hints": ["Re-run with --creds user:pass"],
        })
        for marker in ("5", "100", "20", "3", "12", "8", "2"):
            assert marker in html, f"count {marker} missing from rendered table"
        assert "sqli/" in html and "xss/" in html
        assert "--creds user:pass" in html

    def test_section_heading_anchor_stable(self) -> None:
        """id=scan-diagnostics anchor must stay stable for downstream links."""
        html = _render_scan_diagnostics_html({
            "subdir_payload_counts": {}, "hints": [],
        })
        assert 'id="scan-diagnostics"' in html


# ---------------------------------------------------------------------------
# End-to-end: full report renders with the new section on a 0-findings input
# ---------------------------------------------------------------------------


class TestFullReportWithDiagnostics:
    def test_empty_findings_report_is_not_blank(self, tmp_path) -> None:
        """The whole point: 0-findings report must still have content."""
        from reporter import render_html_report
        # Recon exists but no findings
        recon = tmp_path / "recon" / "harry.target" / "sessions" / "sess1"
        findings = tmp_path / "findings" / "harry.target" / "sessions" / "sess1"
        _seed_recon(recon, live=2, urls=30, specs=1, ops=5)
        findings.mkdir(parents=True)

        html = render_html_report(
            findings=[], target="harry.target", report_dir=str(findings),
            client="Acme", consultant="Harry", title="VAPT",
        )
        # Previously this would have rendered only "No findings." — now it
        # MUST include the diagnostics section with real counts.
        assert "Scan Diagnostics" in html
        assert "Recon Surface" in html
        assert "Live hosts probed" in html
        assert "30" in html  # total_urls count bubbled through
        # And it still renders the canonical "No findings" in the vuln table.
        assert "No findings." in html

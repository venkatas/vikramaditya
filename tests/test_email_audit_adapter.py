"""Tests for v7.3.0 — ``email_audit_adapter``.

Pins the adapter's contract so future audits of email_audit.py's JSON
shape don't silently break Vikramaditya's downstream reporter pipeline.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import email_audit_adapter as adapter


# ---------------------------------------------------------------------------
# Severity + vuln_class mapping
# ---------------------------------------------------------------------------


class TestSeverityMap:
    def test_critical_passes_through(self) -> None:
        """v10.6.0: 'critical' is a valid journal severity and is rendered
        natively by reporter.py — it must NOT be silently downgraded to high,
        which understated real spoofability (SPF +all / SPF /0)."""
        assert adapter._to_schema_severity("critical") == "critical"

    def test_standard_severities_preserved(self) -> None:
        assert adapter._to_schema_severity("high") == "high"
        assert adapter._to_schema_severity("medium") == "medium"
        assert adapter._to_schema_severity("low") == "low"

    def test_info_and_notice_normalised(self) -> None:
        # v7.4.1: schema wants the full word "informational", not "info".
        assert adapter._to_schema_severity("info") == "informational"
        assert adapter._to_schema_severity("notice") == "informational"
        assert adapter._to_schema_severity("informational") == "informational"

    def test_unknown_falls_back_to_informational(self) -> None:
        assert adapter._to_schema_severity("chartreuse") == "informational"

    def test_none_input_safe(self) -> None:
        assert adapter._to_schema_severity(None) == "informational"


class TestVulnClassMap:
    @pytest.mark.parametrize("area,expected", [
        ("spf", "email_spf"),
        ("dmarc", "email_dmarc"),
        ("dkim", "email_dkim"),
        ("mx", "email_mx"),
        ("mta_sts", "email_mta_sts"),
        ("bimi", "email_bimi"),
        ("dnssec", "email_dnssec"),
        ("tls_rpt", "email_tls_rpt"),
    ])
    def test_standard_areas(self, area, expected) -> None:
        assert adapter._to_vuln_class(area) == expected

    def test_unknown_area_falls_back_to_prefixed(self) -> None:
        assert adapter._to_vuln_class("future_check") == "email_future_check"


# ---------------------------------------------------------------------------
# to_finding_entries
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_audit_report():
    return {
        "summary": {"target": "target.com", "target_type": "domain"},
        "checks": {
            "spf": {
                "status": "issues",
                "issues": [{
                    "severity": "high",
                    "title": "Missing SPF record",
                    "detail": "No v=spf1 TXT record published.",
                    "recommendation": "Publish a strict SPF record ending in -all.",
                }],
            },
            "dmarc": {
                "status": "issues",
                "issues": [{
                    "severity": "medium",
                    "title": "DMARC policy is monitor-only",
                    "detail": "v=DMARC1; p=none observed.",
                    "recommendation": "Move to p=quarantine then p=reject.",
                }],
            },
            "dkim": {
                "status": "ok",
                "issues": [],
            },
            "dnssec": {
                "status": "issues",
                "issues": [{
                    "severity": "critical",
                    "title": "Unsigned zone",
                    "detail": "No DS record found in parent zone.",
                    "recommendation": "Enable DNSSEC + publish DS.",
                }],
            },
        },
        "cross_findings": [{
            "severity": "high",
            "title": "Unauthenticated email path (SPF+DMARC permissive)",
            "detail": "SPF ~all + DMARC p=none leaves the org spoofable by any remote sender.",
        }],
    }


class TestToFindingEntries:
    def test_one_entry_per_issue(self, sample_audit_report) -> None:
        findings = adapter.to_finding_entries(sample_audit_report, "target.com")
        # 1 spf + 1 dmarc + 0 dkim + 1 dnssec + 1 cross = 4 total
        assert len(findings) == 4

    def test_spf_entry_shape(self, sample_audit_report) -> None:
        findings = adapter.to_finding_entries(sample_audit_report, "target.com")
        spf = next(f for f in findings if f["area"] == "spf")
        assert spf["target"] == "target.com"
        assert spf["action"] == "recon"
        assert spf["vuln_class"] == "email_spf"
        assert spf["severity"] == "high"
        assert spf["endpoint"] == "dns:spf:target.com"
        assert spf["result"] == "confirmed"
        assert "email_auth" in spf["tags"]
        assert "spf" in spf["tags"]
        assert "subspace_sentinel" in spf["tags"]
        assert spf["title"] == "Missing SPF record"
        assert "Publish a strict SPF record" in spf["notes"]

    def test_notes_prefix_fix_when_detail_present(self, sample_audit_report) -> None:
        findings = adapter.to_finding_entries(sample_audit_report, "target.com")
        dmarc = next(f for f in findings if f["area"] == "dmarc")
        # Both detail and recommendation present → joined with "Fix:" separator.
        assert "Fix:" in dmarc["notes"]
        assert "p=none" in dmarc["notes"]

    def test_critical_preserved_in_finding(self, sample_audit_report) -> None:
        findings = adapter.to_finding_entries(sample_audit_report, "target.com")
        dnssec = next(f for f in findings if f["area"] == "dnssec")
        assert dnssec["severity"] == "critical"  # passed through, not downgraded

    def test_cross_finding_emitted_as_posture(self, sample_audit_report) -> None:
        findings = adapter.to_finding_entries(sample_audit_report, "target.com")
        cross = next(f for f in findings if f["area"] == "cross")
        assert cross["vuln_class"] == "email_posture"
        assert cross["severity"] == "high"
        assert cross["endpoint"] == "dns:posture:target.com"
        assert "cross_finding" in cross["tags"]

    def test_empty_audit_returns_empty_list(self) -> None:
        assert adapter.to_finding_entries({}, "x.com") == []
        assert adapter.to_finding_entries({"checks": {}}, "x.com") == []
        assert adapter.to_finding_entries({"checks": None}, "x.com") == []

    def test_non_dict_input_returns_empty_list(self) -> None:
        assert adapter.to_finding_entries(["not", "a", "dict"], "x.com") == []
        assert adapter.to_finding_entries("garbage", "x.com") == []


class TestBulkModeFanout:
    """v10.6.0 regression — build_bulk_report() returns a {"mode":
    "bulk-analysis", "reports": [<per-domain report>, ...]} shape with NO
    top-level "checks" key. Before the fix, to_finding_entries() read only
    audit_report["checks"] (empty) and every per-domain SPF/DMARC/DKIM issue
    under report["reports"][*] was invisible — a multi-target audit produced
    ZERO findings through the adapter."""

    def _bulk_report(self):
        # Two synthetic per-domain reports, each a normal build_report() shape.
        def _domain_report(domain, title, sev):
            return {
                "summary": {"target": domain, "target_type": "domain", "domain": domain},
                "checks": {
                    "spf": {
                        "status": "issues",
                        "issues": [{
                            "severity": sev,
                            "title": title,
                            "detail": "synthetic detail",
                            "recommendation": "synthetic fix",
                        }],
                    },
                },
            }

        return {
            "mode": "bulk-analysis",
            "summary": {"targets_scanned": 2, "overall_risk": "high"},
            "domains": [],
            "top_findings": [],
            # portfolio_issues carry per-issue area=spf, NOT a cross area
            "issues": [
                {"severity": "high", "title": "Missing SPF record", "area": "SPF", "domain": "acme.invalid"},
                {"severity": "medium", "title": "SPF too permissive", "area": "SPF", "domain": "beta.invalid"},
            ],
            "reports": [
                _domain_report("acme.invalid", "Missing SPF record", "high"),
                _domain_report("beta.invalid", "SPF too permissive", "medium"),
            ],
            "ai_analysis": None,
        }

    def test_bulk_report_yields_per_domain_findings(self) -> None:
        findings = adapter.to_finding_entries(self._bulk_report(), "portfolio")
        # one SPF issue per domain report = 2 findings (was 0 before the fix)
        assert len(findings) == 2

    def test_bulk_findings_carry_own_target(self) -> None:
        findings = adapter.to_finding_entries(self._bulk_report(), "portfolio")
        targets = {f["target"] for f in findings}
        assert targets == {"acme.invalid", "beta.invalid"}

    def test_bulk_findings_preserve_severity_and_title(self) -> None:
        findings = adapter.to_finding_entries(self._bulk_report(), "portfolio")
        by_title = {f["title"]: f for f in findings}
        assert by_title["Missing SPF record"]["severity"] == "high"
        assert by_title["SPF too permissive"]["severity"] == "medium"

    def test_reports_key_without_mode_still_fans_out(self) -> None:
        report = self._bulk_report()
        report.pop("mode")
        findings = adapter.to_finding_entries(report, "portfolio")
        assert len(findings) == 2


class TestCrossFindingsFromFlatIssues:
    """v10.6.0 regression — build_report() does NOT emit a top-level
    "cross_findings" key; it folds derive_cross_findings() into the FLAT
    report["issues"] list tagged area="Cross-check". The adapter must read
    that list, or the HIGH "spoofable" verdict is silently dropped before it
    reaches the reporter/journal."""

    def _report_like_build_report(self):
        # Mirrors email_audit.build_report() output shape: no "cross_findings"
        # key, cross items live in the flat top-level "issues" list with
        # area="Cross-check" (as asdict(Issue) produces them).
        return {
            "summary": {"target": "acme.invalid", "target_type": "domain"},
            "checks": {
                "spf": {"status": "issues", "issues": []},
                "dmarc": {"status": "issues", "issues": []},
            },
            "issues": [
                {
                    "severity": "high",
                    "area": "Cross-check",
                    "title": "High spoofing and impersonation exposure",
                    "detail": "DMARC not enforcing and SPF missing or weak.",
                    "recommendation": "Tighten SPF and move DMARC to reject.",
                },
                {
                    "severity": "low",
                    "area": "Cross-check",
                    "title": "No SMTP transport security policy or reporting",
                    "detail": "Domain accepts mail but no MTA-STS/TLS-RPT.",
                    "recommendation": "Deploy MTA-STS and TLS-RPT.",
                },
            ],
            "remediation_plan": [],
            "ai_analysis": None,
        }

    def test_high_cross_finding_reaches_findings(self) -> None:
        findings = adapter.to_finding_entries(
            self._report_like_build_report(), "acme.invalid"
        )
        cross = [f for f in findings if f["area"] == "cross"]
        assert len(cross) == 2
        high = next(f for f in cross if f["severity"] == "high")
        assert high["title"] == "High spoofing and impersonation exposure"
        assert high["vuln_class"] == "email_posture"
        assert high["endpoint"] == "dns:posture:acme.invalid"
        assert "DMARC not enforcing" in high["notes"]

    def test_low_cross_finding_reaches_findings(self) -> None:
        findings = adapter.to_finding_entries(
            self._report_like_build_report(), "acme.invalid"
        )
        cross = [f for f in findings if f["area"] == "cross"]
        assert any(f["severity"] == "low" for f in cross)

    def test_explicit_cross_findings_key_still_wins(self) -> None:
        # Forward-compat: if a future build_report adds a top-level
        # "cross_findings" key, that takes precedence over flat-issue scraping.
        report = self._report_like_build_report()
        report["cross_findings"] = [{
            "severity": "high",
            "title": "Explicit cross verdict",
            "detail": "from explicit key",
        }]
        findings = adapter.to_finding_entries(report, "acme.invalid")
        cross = [f for f in findings if f["area"] == "cross"]
        assert len(cross) == 1
        assert cross[0]["title"] == "Explicit cross verdict"

    def test_non_cross_flat_issues_not_misclassified(self) -> None:
        # A flat issue from a real check area must NOT be picked up by the
        # cross-finding scrape (only area in {cross, cross_check}).
        report = self._report_like_build_report()
        report["issues"].append({
            "severity": "high", "area": "SPF",
            "title": "SPF ends in +all", "detail": "spoofable",
        })
        findings = adapter.to_finding_entries(report, "acme.invalid")
        cross = [f for f in findings if f["area"] == "cross"]
        assert len(cross) == 2  # SPF issue NOT scraped as a cross-finding


class TestLoadAndConvert:
    def test_roundtrip_from_saved_json(self, tmp_path, sample_audit_report) -> None:
        p = tmp_path / "audit.json"
        p.write_text(json.dumps(sample_audit_report))
        findings = adapter.load_and_convert(str(p), "target.com")
        assert len(findings) == 4
        assert all(f["target"] == "target.com" for f in findings)

    def test_missing_file_returns_empty_list(self, tmp_path) -> None:
        assert adapter.load_and_convert(str(tmp_path / "nope.json"), "x.com") == []

    def test_malformed_json_returns_empty_list(self, tmp_path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not valid json")
        assert adapter.load_and_convert(str(p), "x.com") == []


class TestSeverityHistogram:
    def test_counts_per_severity(self) -> None:
        findings = [
            {"severity": "high"}, {"severity": "high"}, {"severity": "medium"},
            {"severity": "low"}, {"severity": "informational"},
        ]
        hist = adapter.severity_histogram(findings)
        assert hist == {"high": 2, "medium": 1, "low": 1, "informational": 1}

    def test_empty_iterable(self) -> None:
        assert adapter.severity_histogram([]) == {}


# ---------------------------------------------------------------------------
# Public re-exports reachable
# ---------------------------------------------------------------------------


class TestReExports:
    def test_audit_functions_reachable(self) -> None:
        """Callers should import via the adapter, not the monolith."""
        for name in ("audit_spf", "audit_dmarc", "audit_dkim", "audit_mx",
                     "audit_mta_sts", "audit_bimi", "audit_dnssec",
                     "audit_tls_rpt"):
            assert hasattr(adapter, name), f"adapter missing re-export: {name}"
            assert callable(getattr(adapter, name))

    def test_dns_client_reachable(self) -> None:
        assert hasattr(adapter, "DNSClient")

    def test_message_analysis_reachable(self) -> None:
        assert hasattr(adapter, "build_message_analysis_report")


# ---------------------------------------------------------------------------
# agents/email-auditor.md present
# ---------------------------------------------------------------------------


class TestAgentDocShipped:
    def test_agent_file_exists(self) -> None:
        path = os.path.normpath(os.path.join(
            os.path.dirname(__file__), "..", "agents", "email-auditor.md"))
        assert os.path.isfile(path), "agents/email-auditor.md must ship with v7.3.0"

    def test_agent_doc_has_required_sections(self) -> None:
        path = os.path.normpath(os.path.join(
            os.path.dirname(__file__), "..", "agents", "email-auditor.md"))
        body = open(path).read()
        for marker in ("When to invoke", "SPF", "DMARC", "DKIM", "Bulk audit",
                        "cross-finding", "bimi"):
            assert marker.lower() in body.lower(), \
                f"agent doc missing section mentioning: {marker}"

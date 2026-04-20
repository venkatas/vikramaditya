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
    def test_critical_downgrades_to_high(self) -> None:
        """subspace 'critical' = config gap, not RCE — map to high."""
        assert adapter._to_schema_severity("critical") == "high"

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

    def test_critical_downgrades_to_high_in_finding(self, sample_audit_report) -> None:
        findings = adapter.to_finding_entries(sample_audit_report, "target.com")
        dnssec = next(f for f in findings if f["area"] == "dnssec")
        assert dnssec["severity"] == "high"  # was 'critical' in input

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

#!/usr/bin/env python3
"""
Tests for finding_schema.py — verification-method enum + evidence-based severity.

Covers:
  • the VerificationMethod enum surface (9 types + UNVERIFIED)
  • is_proven() strength buckets (strong / weak / context / unproven)
  • EVIDENCE_KEYWORDS shape + classify_evidence() keyword matching
  • adjust_severity() auto-downgrade matrix
  • should_report() gating of UNVERIFIED medium-or-higher findings
"""

import os
import sys

import pytest

# Vikramaditya flat layout — modules live at repo root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import finding_schema as fs
from finding_schema import (
    VerificationMethod,
    is_proven,
    classify_evidence,
    adjust_severity,
    should_report,
    EVIDENCE_KEYWORDS,
)


# ── VerificationMethod enum ───────────────────────────────────────────────────

EXPECTED_METHODS = {
    "exploited",
    "time_based",
    "data_extracted",
    "callback_received",
    "error_based",
    "blind_confirmed",
    "reflected",
    "authenticated",
    "manual_verified",
    "unverified",
}


def test_enum_has_all_ten_members():
    values = {m.value for m in VerificationMethod}
    assert values == EXPECTED_METHODS


def test_enum_has_unverified_sentinel():
    assert VerificationMethod.UNVERIFIED.value == "unverified"


def test_enum_member_value_is_lowercase_string():
    for m in VerificationMethod:
        assert m.value == m.value.lower()
        assert isinstance(m.value, str)


def test_from_string_round_trips_known_values():
    assert VerificationMethod.from_string("exploited") is VerificationMethod.EXPLOITED
    assert VerificationMethod.from_string("TIME_BASED") is VerificationMethod.TIME_BASED
    assert VerificationMethod.from_string("  reflected ") is VerificationMethod.REFLECTED


def test_from_string_unknown_falls_back_to_unverified():
    assert VerificationMethod.from_string("garbage") is VerificationMethod.UNVERIFIED
    assert VerificationMethod.from_string("") is VerificationMethod.UNVERIFIED
    assert VerificationMethod.from_string(None) is VerificationMethod.UNVERIFIED


# ── is_proven() strength buckets ──────────────────────────────────────────────

STRONG = ["exploited", "data_extracted", "callback_received", "time_based"]
WEAK = ["reflected", "error_based", "blind_confirmed"]
CONTEXT = ["authenticated", "manual_verified"]


@pytest.mark.parametrize("method", STRONG)
def test_strong_methods_are_proven(method):
    assert is_proven(method) is True
    assert is_proven(VerificationMethod.from_string(method)) is True


@pytest.mark.parametrize("method", WEAK)
def test_weak_methods_are_not_strongly_proven(method):
    # Weak verification is evidence but does NOT count as strongly proven.
    assert is_proven(method) is False


def test_unverified_is_not_proven():
    assert is_proven("unverified") is False
    assert is_proven(VerificationMethod.UNVERIFIED) is False


def test_proof_strength_three_tier_labels():
    assert fs.proof_strength(VerificationMethod.EXPLOITED) == "strong"
    assert fs.proof_strength(VerificationMethod.REFLECTED) == "weak"
    assert fs.proof_strength(VerificationMethod.AUTHENTICATED) == "context"
    assert fs.proof_strength(VerificationMethod.MANUAL_VERIFIED) == "context"
    assert fs.proof_strength(VerificationMethod.UNVERIFIED) == "unproven"


# ── EVIDENCE_KEYWORDS shape ───────────────────────────────────────────────────

REQUIRED_VULN_TYPES = {
    "sqli", "xss", "rce", "ssrf", "lfi", "idor", "ssti", "xxe",
    "auth_bypass", "open_redirect", "csrf", "cors", "jwt",
    "takeover", "exposure",
}


def test_evidence_keywords_cover_required_types():
    missing = REQUIRED_VULN_TYPES - set(EVIDENCE_KEYWORDS)
    assert not missing, f"missing vuln types: {missing}"


def test_evidence_keywords_has_at_least_fifteen_types():
    assert len(EVIDENCE_KEYWORDS) >= 15


def test_each_evidence_entry_has_severity_buckets():
    for vuln_type, buckets in EVIDENCE_KEYWORDS.items():
        assert set(buckets) == {"critical", "high", "medium"}, vuln_type
        for sev, kws in buckets.items():
            assert isinstance(kws, (list, tuple))
            assert all(isinstance(k, str) and k for k in kws)


# ── classify_evidence() ───────────────────────────────────────────────────────

def test_classify_sqli_critical_on_db_dump():
    out = "union select dumped the entire users table with password hashes"
    assert classify_evidence(out, "sqli") == "critical"


def test_classify_sqli_medium_when_only_error_seen():
    out = "you have an error in your sql syntax near"
    assert classify_evidence(out, "sqli") == "medium"


def test_classify_rce_critical_on_shell():
    out = "uid=0(root) gid=0(root) reverse shell established"
    assert classify_evidence(out, "rce") == "critical"


def test_classify_ssrf_critical_on_cloud_metadata():
    out = "fetched 169.254.169.254 latest/meta-data/iam/security-credentials aws key"
    assert classify_evidence(out, "ssrf") == "critical"


def test_classify_xss_when_payload_reflected():
    out = "the <script>alert(document.cookie)</script> payload reflected in the response"
    assert classify_evidence(out, "xss") in ("high", "medium")


def test_classify_returns_none_when_no_keyword_matches():
    assert classify_evidence("totally benign output", "sqli") is None


def test_classify_unknown_vuln_type_returns_none():
    assert classify_evidence("union select dump", "no_such_type") is None


def test_classify_is_case_insensitive():
    assert classify_evidence("UID=0(ROOT) SHELL", "rce") == "critical"


# ── adjust_severity() downgrade matrix ────────────────────────────────────────

def test_unverified_critical_downgrades_to_high():
    assert adjust_severity("critical", VerificationMethod.UNVERIFIED) == "high"


def test_unverified_high_downgrades_to_medium():
    assert adjust_severity("high", "unverified") == "medium"


def test_weak_method_downgrades_critical_one_notch():
    # reflected is "weak" — a critical claim on weak proof drops to high.
    assert adjust_severity("critical", VerificationMethod.REFLECTED) == "high"


def test_weak_method_downgrades_high_one_notch():
    assert adjust_severity("high", "error_based") == "medium"


def test_proven_method_keeps_severity():
    assert adjust_severity("critical", VerificationMethod.EXPLOITED) == "critical"
    assert adjust_severity("high", "data_extracted") == "high"
    assert adjust_severity("critical", "time_based") == "critical"


def test_medium_and_below_not_downgraded_even_when_unverified():
    # Only critical/high get auto-downgraded; medium/low/info are left intact.
    assert adjust_severity("medium", VerificationMethod.UNVERIFIED) == "medium"
    assert adjust_severity("low", "unverified") == "low"
    assert adjust_severity("info", "unverified") == "info"


def test_context_methods_keep_severity():
    # authenticated / manual_verified are context, not a downgrade trigger.
    assert adjust_severity("critical", VerificationMethod.AUTHENTICATED) == "critical"
    assert adjust_severity("high", "manual_verified") == "high"


def test_adjust_severity_is_case_insensitive_on_label():
    assert adjust_severity("CRITICAL", VerificationMethod.UNVERIFIED) == "high"


# ── should_report() gating ────────────────────────────────────────────────────

def test_unverified_critical_is_rejected():
    assert should_report("critical", VerificationMethod.UNVERIFIED) is False


def test_unverified_high_is_rejected():
    assert should_report("high", "unverified") is False


def test_unverified_medium_is_rejected():
    assert should_report("medium", VerificationMethod.UNVERIFIED) is False


def test_unverified_low_is_allowed():
    # Below medium does not require verification to surface (info/low context).
    assert should_report("low", VerificationMethod.UNVERIFIED) is True
    assert should_report("info", "unverified") is True


def test_weak_verification_allows_medium():
    # At least weak verification clears the medium+ gate.
    assert should_report("medium", VerificationMethod.REFLECTED) is True
    assert should_report("high", "error_based") is True


def test_proven_verification_allows_critical():
    assert should_report("critical", VerificationMethod.EXPLOITED) is True


def test_context_verification_allows_medium_plus():
    assert should_report("high", VerificationMethod.AUTHENTICATED) is True
    assert should_report("medium", "manual_verified") is True

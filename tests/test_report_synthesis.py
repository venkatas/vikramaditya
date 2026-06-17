"""Tests for report_synthesis.py — weighted risk scoring + framework mapping.

Mirrors the behaviour of the xalgorix Go reference (internal/reporting/
risk.go, severity.go, mappings.go) ported to Python:

  • risk_score()      — top-5 CVSS average + crit/high penalty, clamped 0-10,
                        with severity-band CVSS defaults and label thresholds.
  • rollup_severities() — case-insensitive per-severity counts.
  • infer_mappings()  — keyword → OWASP/CWE/PTES inference.
  • exec_summary()    — short narrative combining score + rollup.

All data is synthetic (example.com only).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report_synthesis as rs  # noqa: E402


# ─── risk_score: math ─────────────────────────────────────────────────────────

def test_risk_score_empty_is_informational():
    score, label = rs.risk_score([])
    assert score == 0.0
    assert label == "INFORMATIONAL"


def test_risk_score_single_critical_explicit_cvss():
    # One finding, explicit CVSS 9.8. Top-5 avg over one item = 9.8.
    # Penalty: 1 critical -> 0.15. Total 9.95, clamped at 10? 9.95 < 10.
    score, label = rs.risk_score([{"severity": "critical", "cvss": 9.8}])
    assert round(score, 2) == 9.95
    assert label == "CRITICAL"


def test_risk_score_derives_cvss_from_severity_when_absent():
    # No cvss key -> derive: critical=9.5. avg=9.5, penalty=0.15 -> 9.65.
    score, label = rs.risk_score([{"severity": "critical"}])
    assert round(score, 2) == 9.65
    assert label == "CRITICAL"


def test_risk_score_top5_average_ignores_tail():
    # Six highs (derived 7.5 each) + many lows. Top-5 are all 7.5 -> avg 7.5.
    findings = [{"severity": "high"} for _ in range(6)]
    findings += [{"severity": "low"} for _ in range(10)]
    score, label = rs.risk_score(findings)
    # avg of top-5 = 7.5; penalty: 6 high * 0.05 = 0.30 -> 7.8
    assert round(score, 2) == 7.80
    assert label == "HIGH"


def test_risk_score_penalty_is_capped_at_1_5():
    # 100 criticals: avg of top-5 derived CVSS = 9.5; penalty would be
    # 100*0.15=15 but capped at 1.5 -> 9.5+1.5=11 clamped to 10.
    findings = [{"severity": "critical"} for _ in range(100)]
    score, label = rs.risk_score(findings)
    assert score == 10.0
    assert label == "CRITICAL"


def test_risk_score_clamped_to_10():
    findings = [{"severity": "critical", "cvss": 10.0} for _ in range(20)]
    score, _ = rs.risk_score(findings)
    assert score <= 10.0
    assert score == 10.0


def test_risk_score_mixed_medium_low():
    # medium=5.0 derived, low=2.5 derived. Two mediums, two lows.
    # top-5 = [5,5,2.5,2.5] (only 4 items) avg = 15/4 = 3.75.
    # penalty: no crit/high -> 0. score 3.75 -> LOW.
    findings = [
        {"severity": "medium"}, {"severity": "medium"},
        {"severity": "low"}, {"severity": "low"},
    ]
    score, label = rs.risk_score(findings)
    assert round(score, 2) == 3.75
    assert label == "LOW"


# ─── risk_score: label thresholds ─────────────────────────────────────────────

def test_label_thresholds_boundaries():
    assert rs.risk_label(9.0) == "CRITICAL"
    assert rs.risk_label(8.99) == "HIGH"
    assert rs.risk_label(7.0) == "HIGH"
    assert rs.risk_label(6.99) == "MEDIUM"
    assert rs.risk_label(4.0) == "MEDIUM"
    assert rs.risk_label(3.99) == "LOW"
    assert rs.risk_label(0.1) == "LOW"
    assert rs.risk_label(0.0) == "INFORMATIONAL"


# ─── rollup_severities ────────────────────────────────────────────────────────

def test_rollup_empty():
    got = rs.rollup_severities([])
    assert got == {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "informational": 0, "total": 0,
    }


def test_rollup_case_insensitive_and_unknown_to_info():
    findings = [
        {"severity": "critical"}, {"severity": "Critical"},
        {"severity": "high"}, {"severity": "HIGH"}, {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"}, {"severity": "low"},
        {"severity": "informational"},  # explicit info
        {"severity": ""},               # empty -> info
        {"severity": "weird-label"},    # unknown -> info
    ]
    got = rs.rollup_severities(findings)
    assert got["critical"] == 2
    assert got["high"] == 3
    assert got["medium"] == 1
    assert got["low"] == 2
    assert got["informational"] == 3
    assert got["total"] == 11
    # invariant: named buckets sum to total
    assert (got["critical"] + got["high"] + got["medium"]
            + got["low"] + got["informational"]) == got["total"]


def test_rollup_total_equals_len():
    findings = [{"severity": s} for s in
                ["critical", "high", "medium", "low", ""]]
    got = rs.rollup_severities(findings)
    assert got["total"] == len(findings) == 5


# ─── infer_mappings ───────────────────────────────────────────────────────────

def test_infer_sqli():
    m = rs.infer_mappings("SQL Injection in login form")
    assert m["cwe"] == "CWE-89"
    assert m["owasp"].startswith("A03")
    assert "Injection" in m["owasp"]
    assert m["ptes"] == "Exploitation"


def test_infer_xss():
    m = rs.infer_mappings("Reflected Cross-Site Scripting")
    assert m["cwe"] == "CWE-79"
    assert m["owasp"].startswith("A03")


def test_infer_idor():
    m = rs.infer_mappings("IDOR — insecure direct object reference")
    assert m["cwe"] == "CWE-639"
    assert m["owasp"].startswith("A01")
    assert "Broken Access Control" in m["owasp"]


def test_infer_ssrf():
    m = rs.infer_mappings("Server-Side Request Forgery on /fetch")
    assert m["cwe"] == "CWE-918"
    assert m["owasp"].startswith("A10")


def test_infer_auth_bypass():
    m = rs.infer_mappings("Authentication bypass via header")
    assert m["cwe"] == "CWE-287"
    assert m["owasp"].startswith("A07")


def test_infer_short_token_sqli():
    # bare acronym should still match
    m = rs.infer_mappings("sqli")
    assert m["cwe"] == "CWE-89"


def test_infer_file_upload():
    m = rs.infer_mappings("Unrestricted file upload leads to webshell")
    assert m["cwe"] == "CWE-434"
    assert m["owasp"].startswith("A04")


def test_infer_no_match_returns_empty():
    assert rs.infer_mappings("Some informational banner grab") == {}
    assert rs.infer_mappings("") == {}


def test_infer_takes_type_keyword():
    # callers may pass a type string rather than a prose title
    m = rs.infer_mappings("ssti")
    assert m["cwe"] == "CWE-1336"
    assert m["owasp"].startswith("A03")


# ─── exec_summary ─────────────────────────────────────────────────────────────

def test_exec_summary_mentions_score_label_and_counts():
    findings = [
        {"severity": "critical", "cvss": 9.8, "title": "SQL Injection"},
        {"severity": "high", "title": "Reflected XSS"},
        {"severity": "low", "title": "Missing security header"},
    ]
    summary = rs.exec_summary(findings)
    assert isinstance(summary, str)
    assert summary  # non-empty
    # references the computed risk label (mixed crit/high/low → MEDIUM here)
    score, label = rs.risk_score(findings)
    assert label in summary
    assert label == "MEDIUM"  # documents the scoring math for this fixture
    # references the total finding count
    assert "3" in summary
    # mentions at least one severity word from the rollup breakdown
    assert "critical" in summary.lower()


def test_exec_summary_empty_findings():
    summary = rs.exec_summary([])
    assert isinstance(summary, str)
    assert summary
    # clean-bill-of-health narrative
    assert "INFORMATIONAL" in summary or "no " in summary.lower()


def test_info_only_scores_zero_informational():
    import report_synthesis as rs
    score, label = rs.risk_score([{"severity": "info"}])
    assert score == 0.0 and label == "INFORMATIONAL"
    score2, label2 = rs.risk_score([{"severity": "informational"}, {"severity": "info"}])
    assert score2 == 0.0 and label2 == "INFORMATIONAL"

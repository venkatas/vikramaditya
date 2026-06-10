"""Behavioral regression tests for prioritize.py IIS version-gate.

A previous fix pass introduced a dangerous regression: the IIS-6 version gate
capped the WHOLE host score via ``max_score = min(max_score, 4)``. That demoted
a host such as ``IIS:10.0,Log4j`` from CRITICAL (Log4Shell, score 10) down to
MEDIUM 4 — SUPPRESSING the Log4Shell finding.

The gate must neutralize ONLY the IIS-6-only CVE (CVE-2017-7269) on non-IIS-6
hosts and recompute the score from the REMAINING tech/CVE matches. It must never
cap the score contributed by other technologies.

These tests assert real scoring behavior (no mocks).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import prioritize  # noqa: E402


def _score(line):
    result = prioritize.score_host(line)
    assert result is not None
    return result


# --- The core regression: co-located CRITICAL CVEs must survive the IIS gate ---

def test_iis10_plus_log4j_stays_critical_and_keeps_log4shell():
    """IIS 10.0 + Log4j -> the IIS-6 CVE is dropped, but Log4Shell remains and
    keeps the host CRITICAL (>=9). This is the exact bug the previous pass
    introduced (whole-host cap to 4)."""
    line = (
        "https://app.example.com [200] [6243] [Home] [148.72.90.65] "
        "[IIS:10.0,Microsoft ASP.NET,Log4j]"
    )
    result = _score(line)
    joined = " ".join(result["cves"])

    # Log4Shell finding must be RETAINED.
    assert "CVE-2021-44228" in joined or "Log4Shell" in joined, joined
    # Score must remain CRITICAL — not demoted to MEDIUM 4 by the IIS gate.
    assert result["score"] >= 9, result
    assert result["score"] >= prioritize.CRITICAL_SCORE, result
    assert result["priority"] == "CRITICAL", result
    # The IIS-6-only CVE must still be suppressed on a modern IIS 10 host.
    assert "CVE-2017-7269" not in joined, joined


def test_iis10_plus_log4shell_keyword_stays_critical():
    """The explicit ``log4shell`` keyword (score 10) must also survive."""
    line = "https://x.example.com [200] [10] [t] [1.2.3.4] [Microsoft-IIS/10.0,log4shell]"
    result = _score(line)
    joined = " ".join(result["cves"])
    assert result["score"] >= 9, result
    assert result["priority"] == "CRITICAL", result
    assert "CVE-2017-7269" not in joined, joined


def test_iis10_plus_confluence_keeps_high_severity():
    """A score-9 non-IIS tech (Confluence) co-located with IIS 10 must stay
    CRITICAL — the IIS gate must not cap it."""
    line = "https://c.example.com [200] [10] [t] [1.2.3.4] [IIS:10.0,Confluence]"
    result = _score(line)
    assert result["score"] >= 9, result
    assert result["priority"] == "CRITICAL", result


# --- IIS 6.0 still surfaces its CVE ---

def test_iis6_still_emits_cve_2017_7269():
    line = (
        "http://legacy.example.com [200] [123] [Old App] [10.0.0.5] "
        "[IIS:6.0,Microsoft ASP.NET]"
    )
    result = _score(line)
    joined = " ".join(result["cves"])
    assert "CVE-2017-7269" in joined, joined
    # Mapped score 5 -> at least MEDIUM.
    assert result["score"] >= prioritize.MEDIUM_SCORE, result


def test_iis6_plus_log4j_keeps_both():
    """IIS 6 + Log4j: BOTH the IIS-6 CVE and Log4Shell survive; host CRITICAL."""
    line = "http://l.example.com [200] [10] [t] [10.0.0.6] [IIS:6.0,Log4j]"
    result = _score(line)
    joined = " ".join(result["cves"])
    assert "CVE-2017-7269" in joined, joined
    assert "CVE-2021-44228" in joined or "Log4Shell" in joined, joined
    assert result["score"] >= 9, result


# --- IIS 10 alone must NOT surface the IIS-6-only CVE ---

def test_iis10_alone_does_not_surface_cve_2017_7269():
    line = "https://h.example.com [200] [10] [t] [1.2.3.4] [IIS:10.0]"
    result = _score(line)
    joined = " ".join(result["cves"])
    assert "CVE-2017-7269" not in joined, joined
    assert result["priority"] != "CRITICAL", result
    # IIS 10 alone has no other justified score -> not even MEDIUM off IIS-6.
    assert result["score"] < prioritize.MEDIUM_SCORE, result
    # Softer version-appropriate note present.
    assert "10.0" in joined and "IIS 6.0" in joined, joined


def test_iis_slash_format_version_gated():
    line = "https://h.example.com [200] [10] [t] [1.2.3.4] [Microsoft-IIS/10.0]"
    result = _score(line)
    assert "CVE-2017-7269" not in " ".join(result["cves"]), result


def test_iis_no_version_softened_not_critical():
    line = "https://h.example.com [200] [10] [t] [1.2.3.4] [IIS]"
    result = _score(line)
    joined = " ".join(result["cves"])
    assert "CVE-2017-7269" not in joined, joined
    assert result["priority"] != "CRITICAL", result


# --- The IIS gate must not undo unrelated cap gates (no false elevation) ---

def test_iis10_plus_unvalidated_spring_stays_capped():
    """Spring without version/evidence is capped to 6 by its own gate. The IIS
    gate must NOT re-elevate it past that cap when recomputing the score."""
    line = "https://s.example.com [200] [10] [t] [1.2.3.4] [IIS:10.0,Spring]"
    result = _score(line)
    # Spring gate caps the whole host at 6 (pre-existing behavior). The IIS gate
    # recomputes from max_score_floor which mirrors that cap -> must not exceed 6.
    assert result["score"] <= 6, result
    assert result["priority"] != "CRITICAL", result


def test_iis10_with_evidence_backed_f5_stays_high():
    """F5 with management-surface evidence is raised to 9 by its gate; IIS gate
    must preserve that floor."""
    line = "https://f.example.com [200] [10] [t] [1.2.3.4] [IIS:10.0,F5]"
    result = prioritize.score_host(line, extra_hints=["evidence:f5-mgmt"])
    assert result is not None
    assert result["score"] >= 9, result
    assert result["priority"] == "CRITICAL", result


# --- Non-IIS hosts are completely unaffected by the change ---

def test_non_iis_log4j_unchanged():
    line = "https://n.example.com [200] [10] [t] [1.2.3.4] [Log4j]"
    result = _score(line)
    assert result["score"] >= 9, result
    assert result["priority"] == "CRITICAL", result

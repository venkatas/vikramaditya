"""Regression tests for the v9.23 brain.py audit fixes (clientd.com run).

Covers the pure-Python helpers — no LLM/Ollama dependency:

  1. _build_report_evidence includes email_auth/findings.json so the brain sees
     the same findings the reporter ingests (no more NO_REPORTS vs 10 findings).
  2. _collect_candidate_findings reads ONLY confirmed sqlmap artifacts, not the
     candidates.txt / target.txt INPUT files (no bogus '[sqlmap]' findings).
  3. _extract_shell_from_markdown extracts ONLY the fenced code block so trailing
     prose can't leak into scan_plan.sh.
  4. _append_live_host_grounding never lets recon prose claim "none" when httpx
     confirmed live hosts.
  5. _q6_consistency_note flags Q6 reasoning<->answer polarity flips.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain import Brain  # noqa: E402


def _bare_brain():
    """Instantiate Brain without touching the LLM provider (__init__ connects)."""
    return Brain.__new__(Brain)


# ---------------------------------------------------------------------------
# Fix 1 — email_auth/findings.json is part of the brain's evidence set
# ---------------------------------------------------------------------------

def test_build_report_evidence_includes_email_auth(tmp_path):
    findings = tmp_path / "findings"
    ea = findings / "email_auth"
    ea.mkdir(parents=True)
    (ea / "findings.json").write_text(
        '[{"severity": "medium", "title": "No DMARC record published",'
        ' "endpoint": "dns:dmarc:example.com",'
        ' "notes": "Publish a DMARC policy."}]'
    )
    evidence = _bare_brain()._build_report_evidence(str(findings))
    assert "Email Authentication Posture" in evidence
    assert "No DMARC record published" in evidence
    # Non-empty evidence is exactly what flips has_report_evidence True so the
    # brain runs the report pipeline instead of short-circuiting to NO_REPORTS.
    assert evidence.strip()


def test_build_report_evidence_empty_when_nothing(tmp_path):
    findings = tmp_path / "findings"
    findings.mkdir()
    assert _bare_brain()._build_report_evidence(str(findings)).strip() == ""


def test_build_report_evidence_tolerates_bad_email_json(tmp_path):
    findings = tmp_path / "findings"
    ea = findings / "email_auth"
    ea.mkdir(parents=True)
    (ea / "findings.json").write_text("{ not valid json ]")
    # Must not raise; just yields no email section.
    out = _bare_brain()._build_report_evidence(str(findings))
    assert "Email Authentication Posture" not in out


# ---------------------------------------------------------------------------
# Fix 2 — sqlmap candidate-finding harvest reads only confirmed artifacts
# ---------------------------------------------------------------------------

def test_sqlmap_candidates_not_harvested(tmp_path):
    findings = tmp_path / "findings"
    sqlmap = findings / "sqlmap"
    sqlmap.mkdir(parents=True)
    # INPUT artifacts that must NOT become findings:
    (sqlmap / "candidates.txt").write_text(
        "https://www.example.com/WebResource.axd?d=FUZZ&t=FUZZ\n"
        "https://www.example.com/WebResource.axd?d=abc123&t=638\n"
    )
    (sqlmap / "target.txt").write_text("https://www.example.com/login\n")
    # A confirmed-result artifact (header-only here = no confirmed rows):
    (sqlmap / "sqlmap_results.txt").write_text(
        "Target URL,Place,Parameter,Technique(s),Note(s)\n"
    )
    cands = _bare_brain()._collect_candidate_findings(str(findings))
    sqlmap_lines = [line for cat, line in cands if cat == "sqlmap"]
    # None of the candidate/target URLs may leak in as sqlmap findings.
    assert not any("WebResource.axd" in line for line in sqlmap_lines)
    assert not any("/login" in line for line in sqlmap_lines)


def test_sqlmap_confirmed_results_still_harvested(tmp_path):
    findings = tmp_path / "findings"
    sqlmap = findings / "sqlmap"
    sqlmap.mkdir(parents=True)
    (sqlmap / "candidates.txt").write_text("https://x.example.com/?q=FUZZ\n")
    # results-*.csv is a confirmed artifact the engine emits.
    (sqlmap / "results-target.csv").write_text(
        "Target URL,Place,Parameter\n"
        "https://confirmed.example.com/api?id=1,GET,id\n"
    )
    cands = _bare_brain()._collect_candidate_findings(str(findings))
    sqlmap_lines = [line for cat, line in cands if cat == "sqlmap"]
    # Extract exact hostnames (avoids imprecise URL-substring matching — CodeQL
    # py/incomplete-url-substring-sanitization — and tightens the assertion).
    sqlmap_hosts = {
        m.group(1)
        for line in sqlmap_lines
        for m in [re.search(r"https?://([^/\s,'\"]+)", line)]
        if m
    }
    assert any(h == "confirmed.example.com" for h in sqlmap_hosts)
    assert all(h != "x.example.com" for h in sqlmap_hosts)


# ---------------------------------------------------------------------------
# Fix 3 — scan_plan fence extraction strips trailing prose
# ---------------------------------------------------------------------------

def test_extract_shell_strips_trailing_prose():
    text = (
        "Here is your plan:\n"
        "```bash\n"
        "#!/bin/bash\n"
        "nuclei -u https://example.com\n"
        "```\n"
        "I hope this helps! Let me know if you need more commands.\n"
    )
    code = Brain._extract_shell_from_markdown(text)
    assert "nuclei -u https://example.com" in code
    assert "I hope this helps" not in code
    assert "Here is your plan" not in code
    assert "```" not in code


def test_extract_shell_no_fence_passthrough():
    text = "#!/bin/bash\nnuclei -u https://example.com\n"
    code = Brain._extract_shell_from_markdown(text)
    assert code.strip() == text.strip()


def test_extract_shell_first_block_only():
    text = (
        "```sh\n"
        "echo first\n"
        "```\n"
        "and some prose\n"
        "```\n"
        "echo second\n"
        "```\n"
    )
    code = Brain._extract_shell_from_markdown(text)
    assert "echo first" in code
    assert "and some prose" not in code
    assert "echo second" not in code


# ---------------------------------------------------------------------------
# Fix 4 — live-host grounding correction
# ---------------------------------------------------------------------------

def test_live_host_grounding_corrects_denial():
    analysis = "Staging Subdomains: None identified at this stage."
    out = Brain._append_live_host_grounding(
        analysis, ["mssql.example.com", "www.example.com"]
    )
    assert re.search(r"\bmssql\.example\.com\b", out)
    assert "Correction" in out


def test_live_host_grounding_appends_when_no_denial():
    analysis = "Three live hosts were enumerated and look promising."
    out = Brain._append_live_host_grounding(analysis, ["mssql.example.com"])
    assert re.search(r"\bmssql\.example\.com\b", out)
    assert "Confirmed Live Hosts" in out


def test_live_host_grounding_noop_when_empty():
    analysis = "No subdomains identified."
    out = Brain._append_live_host_grounding(analysis, [])
    assert out == analysis


# ---------------------------------------------------------------------------
# Fix 5 — Q6 polarity consistency check
# ---------------------------------------------------------------------------

def test_q6_flags_no_against_not_listed_reasoning():
    gate = (
        "Q5: YES\n- unique\n"
        "Q6: NO\n- SQL injection is not listed as an always-rejected issue.\n"
        "Q7: YES\n- a triager would agree\n"
    )
    note = Brain._q6_consistency_note(gate)
    assert note
    assert "should be YES" in note


def test_q6_consistent_yes_no_note():
    gate = (
        "Q6: YES\n- The finding does not match any always-rejected criteria.\n"
        "Q7: YES\n"
    )
    assert Brain._q6_consistency_note(gate) == ""


def test_q6_flags_yes_against_listed_reasoning():
    gate = (
        "Q6: YES\n- Missing SPF is on the always-rejected list.\n"
        "Q7: NO\n"
    )
    note = Brain._q6_consistency_note(gate)
    assert note
    assert "should be NO" in note


def test_q6_no_q6_returns_empty():
    assert Brain._q6_consistency_note("Q1: YES\nQ2: NO\n") == ""


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))

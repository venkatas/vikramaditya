#!/usr/bin/env python3
"""Regression tests for idor.py audit fixes (SYNTHETIC data only).

Covers:
  1. check() must only flag a confirmed IDOR when B's data MATCHES A's data
     (no more "any non-null B response = HIGH finding" false positives).
  2. test_collaboration_idor() must not crash on a non-numeric report_id; it
     should skip the numeric draft enumeration gracefully.
"""

import importlib

import idor


def setup_function(_):
    # Each test starts with a clean findings list.
    idor.FINDINGS.clear()


# ── Finding 1: check() gates on is_same_data ─────────────────────────────────

def test_check_flags_when_b_matches_a():
    """True cross-user leak: B receives exactly the same private data as A."""
    resp_a = {"data": {"report": {"title": "secret-report"}}}
    resp_b = {"data": {"report": {"title": "secret-report"}}}
    idor.check("report.title", resp_a, resp_b, "HIGH")
    assert len(idor.FINDINGS) == 1
    assert idor.FINDINGS[0]["severity"] == "HIGH"


def test_check_no_flag_when_b_data_differs_from_a():
    """B got non-null data, but it differs from A — must NOT auto-confirm.

    This is the public/shared-data false-positive class the audit flagged.
    """
    resp_a = {"data": {"report": {"title": "a-private-title"}}}
    resp_b = {"data": {"report": {"title": "public-disclosed-title"}}}
    idor.check("report.title", resp_a, resp_b, "HIGH")
    assert idor.FINDINGS == []


def test_check_no_flag_when_b_null():
    resp_a = {"data": {"report": {"title": "secret"}}}
    resp_b = {"data": {"report": None}}
    idor.check("report.title", resp_a, resp_b, "HIGH")
    assert idor.FINDINGS == []


def test_check_no_flag_when_b_errors():
    resp_a = {"data": {"report": {"title": "secret"}}}
    resp_b = {"data": {"report": {"title": "secret"}}, "errors": [{"message": "denied"}]}
    idor.check("report.title", resp_a, resp_b, "HIGH")
    assert idor.FINDINGS == []


def test_check_no_flag_on_http_error():
    resp_a = {"data": {"report": {"title": "secret"}}}
    resp_b = {"_http_error": 403, "_body": "forbidden"}
    idor.check("report.title", resp_a, resp_b, "HIGH")
    assert idor.FINDINGS == []


# ── Finding 2: non-numeric report_id no longer crashes ───────────────────────

def test_collaboration_idor_non_numeric_report_id(monkeypatch, capsys):
    """A base64 GID / non-decimal report_id must not raise ValueError."""
    # Stub network so the test stays fully offline.
    monkeypatch.setattr(idor, "gql", lambda *a, **k: {"data": {"node": None}})
    monkeypatch.setattr(idor, "sleep", lambda: None)

    # Must not raise.
    idor.test_collaboration_idor("tok-a", "tok-b", "gid://hackerone/Report/abc")

    out = capsys.readouterr().out
    assert "SKIP" in out  # draft enumeration was skipped, not crashed


def test_collaboration_idor_numeric_report_id_runs_enumeration(monkeypatch):
    """Numeric report_id still drives the draft enumeration loop."""
    calls = []

    def fake_gql(token, query, variables=None):
        calls.append(query)
        return {"data": {"node": None}}

    monkeypatch.setattr(idor, "gql", fake_gql)
    monkeypatch.setattr(idor, "sleep", lambda: None)

    idor.test_collaboration_idor("tok-a", "tok-b", "1000")
    # 5 draft offsets + ReportIntent + collaborators query (a & b) => loop ran.
    assert any("ReportDraft" in q for q in calls)


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))

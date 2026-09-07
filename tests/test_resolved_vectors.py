#!/usr/bin/env python3
"""Unit tests for resolved_vectors ledger (synthetic *.example.invalid)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import resolved_vectors as rv  # noqa: E402


def test_upsert_and_load(tmp_path):
    path = str(tmp_path / "resolved_vectors.json")
    v = rv.upsert_vector(
        path,
        target="app.example.invalid",
        vector="sqlmap:/id",
        status="attempted",
        tested_by="brain",
    )
    assert v["id"]
    assert v["status"] == "attempted"
    loaded = rv.load_ledger(path)
    assert len(loaded) == 1
    assert loaded[0]["target"] == "app.example.invalid"


def test_record_attempt_and_skip_resolved(tmp_path):
    path = str(tmp_path / "ledger.json")
    rv.record_attempt(
        path,
        "app.example.invalid",
        "sqlmap:/search",
        technique="sqlmap",
        outcome="failed",
        detail="not injectable",
    )
    assert rv.is_resolved(path, "app.example.invalid", "sqlmap:/search") is False
    skip, reason = rv.should_skip(path, "app.example.invalid", "sqlmap:/search")
    assert skip is False

    rv.upsert_vector(
        path,
        target="app.example.invalid",
        vector="sqlmap:/search",
        status="resolved",
    )
    assert rv.is_resolved(path, "app.example.invalid", "sqlmap:/search") is True
    skip, reason = rv.should_skip(path, "app.example.invalid", "sqlmap:/search")
    assert skip is True
    assert "resolved" in reason.lower()


def test_should_skip_confirmed(tmp_path):
    path = str(tmp_path / "l.json")
    rv.upsert_vector(
        path,
        target="api.example.invalid",
        vector="nuclei:cve-2021-41773",
        status="confirmed",
    )
    skip, reason = rv.should_skip(path, "api.example.invalid", "nuclei:cve-2021-41773")
    assert skip is True
    assert "confirmed" in reason.lower()


def test_blocked_with_future_revisit(tmp_path):
    path = str(tmp_path / "l.json")
    rv.upsert_vector(
        path,
        target="t.example.invalid",
        vector="ffuf:/admin",
        status="blocked",
        revisit_when="2099-01-01T00:00:00Z",
    )
    skip, reason = rv.should_skip(path, "t.example.invalid", "ffuf:/admin")
    assert skip is True
    assert "revisit" in reason.lower() or "blocked" in reason.lower()


def test_blocked_revisit_elapsed(tmp_path):
    path = str(tmp_path / "l.json")
    rv.upsert_vector(
        path,
        target="t.example.invalid",
        vector="ffuf:/backup",
        status="blocked",
        revisit_when="2000-01-01T00:00:00Z",
    )
    skip, reason = rv.should_skip(path, "t.example.invalid", "ffuf:/backup")
    assert skip is False


def test_format_context(tmp_path):
    path = str(tmp_path / "l.json")
    rv.upsert_vector(path, target="a.example.invalid", vector="sqlmap:/x", status="resolved")
    rv.record_attempt(path, "b.example.invalid", "ffuf:/y", "ffuf", "failed", "404")
    ctx = rv.format_context(path, max=30)
    assert "RESOLVED-VECTOR LEDGER" in ctx
    assert "a.example.invalid" in ctx


def test_noop_missing_path():
    assert rv.load_ledger(None) == []
    assert rv.is_resolved(None, "x", "y") is False
    skip, reason = rv.should_skip(None, "x", "y")
    assert skip is False
    assert rv.format_context(None) == ""
    assert rv.record_attempt(None, "x", "y", "t", "failed") is None


def test_infer_vector_key_sqlmap():
    code = 'sqlmap -u "https://app.example.invalid/id?x=1" -p x --batch'
    out = rv.infer_vector_key(code)
    assert out is not None
    target, vector = out
    assert "app.example.invalid" in target
    assert "sqlmap" in vector


def test_infer_vector_key_plain_curl_skipped():
    code = 'curl -s https://app.example.invalid/ | head'
    assert rv.infer_vector_key(code) is None


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))

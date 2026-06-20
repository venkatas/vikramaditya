"""Regression: intel.py must pass untrusted values to HackerOne's GraphQL
endpoint as variables, never interpolated into the query document text.

A target-controlled tech token (e.g. derived from a quote-bearing Server
header) previously terminated the GraphQL string literal, breaking parsing
and silently dropping HackerOne hacktivity intel for that tech.

Synthetic data only.
"""
import json

import intel


def _capture_fetch_url(captured):
    def _fake(url, headers=None, data=None):
        captured["url"] = url
        captured["body"] = json.loads(data.decode()) if data else None
        # Return a well-formed-but-empty hacktivity payload.
        return {"data": {"hacktivity_items": {"nodes": []}}}
    return _fake


def test_keyword_passed_as_variable_not_interpolated(monkeypatch):
    captured = {}
    monkeypatch.setattr(intel, "fetch_url", _capture_fetch_url(captured))

    # Quote/backslash-bearing token that would break naive interpolation.
    evil_kw = 'nginx" x \\ injected'
    intel.fetch_hackerone_hacktivity(evil_kw)

    body = captured["body"]
    assert body is not None
    # The untrusted value lives in variables, not in the document text.
    assert body["variables"]["kw"] == evil_kw
    assert "$kw" in body["query"]
    # The raw value must NOT appear inside the GraphQL document string.
    assert evil_kw not in body["query"]


def test_keyword_query_is_valid_json_with_special_chars(monkeypatch):
    captured = {}
    monkeypatch.setattr(intel, "fetch_url", _capture_fetch_url(captured))

    # Should not raise and should produce []; the function returns [] for an
    # empty node list regardless of the (now-safe) keyword.
    results = intel.fetch_hackerone_hacktivity('acme":{} x')
    assert results == []
    assert captured["body"]["variables"]["kw"] == 'acme":{} x'

"""Regression test: validate.py must send HackerOne GraphQL queries with typed
variables, not raw f-string interpolation of operator-supplied handle/keyword.

A quote-containing value must NOT break out of the query string literal — it
must travel inside the JSON `variables` payload instead. Synthetic data only.
"""
import json
import importlib

validate = importlib.import_module("validate")


class _FakeResp:
    """Context-manager stand-in for urllib.request.urlopen()."""

    def __init__(self, captured, payload):
        self._captured = captured
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return json.dumps(self._payload).encode()


def _patch_urlopen(monkeypatch, captured, payload):
    def fake_urlopen(req, *args, **kwargs):
        # req.data is the JSON body we POST to the GraphQL endpoint.
        captured["body"] = json.loads(req.data.decode())
        return _FakeResp(captured, payload)

    monkeypatch.setattr(validate.urllib.request, "urlopen", fake_urlopen)


def test_check_h1_dups_uses_variables(monkeypatch):
    captured = {}
    _patch_urlopen(monkeypatch, captured, {"data": {"hacktivity_items": {"nodes": []}}})

    # A breakout attempt: embedded double-quote + GraphQL syntax.
    evil_handle = 'acme") { __typename } #'
    evil_kw = 'idor" }} injection'
    validate.check_h1_dups(evil_handle, evil_kw)

    body = captured["body"]
    # Operator values must travel as variables, not be baked into the query text.
    assert body["variables"]["h"] == evil_handle
    assert body["variables"]["kw"] == evil_kw
    assert evil_handle not in body["query"]
    assert evil_kw not in body["query"]
    # Query declares typed variables.
    assert "$h" in body["query"] and "$kw" in body["query"]


def test_gate2_scope_uses_variables(monkeypatch):
    captured = {}
    _patch_urlopen(monkeypatch, captured, {"data": {"team": {"policy_scopes": {"edges": []}}}})

    # Stub the interactive prompts so the gate runs non-interactively.
    monkeypatch.setattr(validate, "ask_yn", lambda *a, **k: True)

    evil_handle = 'acme") { __typename } #'
    validate.gate2_in_scope(evil_handle)

    body = captured["body"]
    assert body["variables"]["h"] == evil_handle
    assert evil_handle not in body["query"]
    assert "$h" in body["query"]

"""The JWT forgery-confirmation function must be REACHABLE from the audit.

friends full-tool review F7: jwt_kid_injection.confirm_replay (a careful 3-way
baseline diff) was implemented and unit-tested but NEVER called from hunt.py's
JWT audit — so an RS256->HS256 / kid forgery was generated and then only logged
as 'replay manually to confirm', yielding no finding even when the server
actually accepted the forged token. confirm_replay_any bounds the replay over
candidate endpoints and fails closed, so hunt.py can auto-confirm.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import jwt_kid_injection as jk  # noqa: E402


def test_returns_first_confirmed_endpoint(monkeypatch):
    def _fake(client, endpoint, forged, original):
        ok = endpoint == "https://t.example.invalid/api/me"
        return jk.ReplayResult(confirmed=ok, detail="accepted" if ok else "no")

    monkeypatch.setattr(jk, "confirm_replay", _fake)
    res = jk.confirm_replay_any(
        None,
        ["https://t.example.invalid/", "https://t.example.invalid/api/me",
         "https://t.example.invalid/other"],
        "forged.jwt", "original.jwt")
    assert res == ("https://t.example.invalid/api/me", "accepted")


def test_returns_none_when_nothing_confirms(monkeypatch):
    monkeypatch.setattr(jk, "confirm_replay",
                        lambda *a, **k: jk.ReplayResult(confirmed=False))
    assert jk.confirm_replay_any(None, ["a", "b"], "f", "o") is None


def test_skips_endpoint_whose_replay_errors(monkeypatch):
    def _fake(client, endpoint, forged, original):
        if endpoint == "bad":
            raise RuntimeError("connection reset")
        return jk.ReplayResult(confirmed=(endpoint == "good"), detail="y")

    monkeypatch.setattr(jk, "confirm_replay", _fake)
    assert jk.confirm_replay_any(None, ["bad", "good"], "f", "o") == ("good", "y")


def test_bounded_by_cap(monkeypatch):
    calls = []

    def _fake(client, endpoint, forged, original):
        calls.append(endpoint)
        return jk.ReplayResult(confirmed=False)

    monkeypatch.setattr(jk, "confirm_replay", _fake)
    jk.confirm_replay_any(None, [f"e{i}" for i in range(100)], "f", "o", cap=15)
    assert len(calls) == 15, "replay must be bounded by cap"

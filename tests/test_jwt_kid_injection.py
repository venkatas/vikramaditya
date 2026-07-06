"""jwt_kid_injection — extends hunt.py's run_jwt_audit() (which already does
alg=none + RS256->HS256 via jwt_tool locally + wordlist cracking). This module
adds: real JWKS-sourced key material (iterating every key in keys[], not just
the first/cached one), kid-header injection, and a 3-way baseline-diff replay
confirmation that jwt_tool's local success alone does not provide.
"""
import base64
import json

import jwt as pyjwt

import jwt_kid_injection as jki


def _make_rs256_token(kid="key-1"):
    # A syntactically valid-looking RS256 header/payload with the given kid;
    # we never verify with a real private key in tests — only header/payload
    # shape and our own re-signing logic is under test.
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    payload = {"sub": "alice", "role": "user"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.fakesig"


class _FakeResponse:
    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json = json_body or {}
        self.headers = {}

    def json(self):
        return self._json


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def get(self, url, **kwargs):
        return self._response

    def post(self, url, **kwargs):
        return self._response


def test_discover_jwks_returns_all_keys_from_keys_array():
    jwks_body = {"keys": [{"kid": "key-1", "kty": "RSA", "n": "abc", "e": "AQAB"},
                          {"kid": "key-2", "kty": "RSA", "n": "def", "e": "AQAB"}]}
    client = _FakeClient(_FakeResponse(200, jwks_body))
    keys = jki.discover_jwks(client, "https://issuer.example.com")
    assert len(keys) == 2
    assert {k["kid"] for k in keys} == {"key-1", "key-2"}


def test_discover_jwks_empty_on_404():
    client = _FakeClient(_FakeResponse(404))
    assert jki.discover_jwks(client, "https://issuer.example.com") == []


def test_try_rs256_to_hs256_matches_kid_and_forges_hs256_token():
    token = _make_rs256_token(kid="key-1")
    jwks_keys = [{"kid": "key-1", "kty": "RSA", "n": "sGl4...", "e": "AQAB"}]
    forged = jki.try_rs256_to_hs256(token, jwks_keys)
    assert forged is not None
    header = json.loads(base64.urlsafe_b64decode(forged.split(".")[0] + "=="))
    assert header["alg"] == "HS256"


def test_try_rs256_to_hs256_returns_none_when_kid_not_in_jwks():
    token = _make_rs256_token(kid="unknown-key")
    jwks_keys = [{"kid": "key-1", "kty": "RSA", "n": "sGl4...", "e": "AQAB"}]
    assert jki.try_rs256_to_hs256(token, jwks_keys) is None


def test_build_kid_injection_candidates_includes_path_traversal_and_sqli():
    token = _make_rs256_token(kid="keys/prod.pem")
    candidates = jki.build_kid_injection_candidates(token)
    assert any("../../../../dev/null" in c for c in candidates)
    assert any("UNION SELECT" in c for c in candidates)
    assert len(candidates) >= 2


def test_confirm_replay_true_only_when_forged_diverges_from_both_baselines():
    class _Client:
        def __init__(self):
            self._call = 0
        def get(self, url, headers=None, **kwargs):
            self._call += 1
            token = headers.get("Authorization", "")
            if "forged" in token:
                return _FakeResponse(200, {"sub": "alice", "role": "admin"})
            if "original" in token:
                return _FakeResponse(200, {"sub": "alice", "role": "user"})
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is True


def test_confirm_replay_false_when_forged_matches_unauthenticated_baseline():
    class _Client:
        def get(self, url, headers=None, **kwargs):
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is False

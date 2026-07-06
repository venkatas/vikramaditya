"""jwt_kid_injection — extends hunt.py's run_jwt_audit() (which already does
alg=none + RS256->HS256 via jwt_tool locally + wordlist cracking). This module
adds: real JWKS-sourced key material (iterating every key in keys[], not just
the first/cached one), kid-header injection, and a 3-way baseline-diff replay
confirmation that jwt_tool's local success alone does not provide.
"""
import base64
import hashlib
import hmac
import json

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import HMACAlgorithm

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


def _b64url_uint(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _real_rsa_jwk_and_expected_pem(kid="key-1"):
    """Generate a REAL 2048-bit RSA keypair, build the JWK dict a real JWKS
    endpoint would publish for its public key (kty/n/e), and independently
    compute the PEM/SubjectPublicKeyInfo serialization that a genuinely
    vulnerable verifier would hold in memory as "the public key" — this is
    the value that must be used as the HMAC secret for the RS256->HS256
    confusion attack to actually work against a real target."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }
    expected_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return jwk, expected_pem


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
    # Regression test for the Critical bug: an earlier version used the raw,
    # still-base64url-ENCODED `n` field text as the HMAC secret, which does
    # NOT match the PEM/SubjectPublicKeyInfo bytes a real verifier holds —
    # meaning the forged signature would be rejected by any genuinely
    # vulnerable target. This test uses a REAL 2048-bit RSA keypair and
    # actually VERIFIES the forged token's signature against the real
    # derived secret, not just the header shape.
    jwk, expected_pem = _real_rsa_jwk_and_expected_pem(kid="key-1")
    token = _make_rs256_token(kid="key-1")
    forged = jki.try_rs256_to_hs256(token, [jwk])
    assert forged is not None

    header_b64, payload_b64, signature_b64 = forged.split(".")
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    assert header["alg"] == "HS256"

    # The critical assertion: the forged token must verify as a genuine
    # HS256 signature under the PEM/SubjectPublicKeyInfo serialization of the
    # REAL RSA public key — i.e. exactly the bytes a naive RS256->HS256
    # confusion-vulnerable verifier would use as its HMAC key.
    #
    # Note: we verify via jwt.algorithms.HMACAlgorithm.verify() (PyJWT's own
    # HMAC-verification primitive) rather than the top-level pyjwt.decode(),
    # because modern PyJWT's decode() *itself* now refuses to use a
    # PEM-shaped key as an HMAC secret (jwt.algorithms.HMACAlgorithm.
    # prepare_key raises InvalidKeyError on PEM/SSH-formatted keys) — a
    # defense-in-depth guard against this exact confusion attack. That guard
    # lives only in prepare_key(), which decode() calls but verify() does
    # not, so verify() still reflects what a verifier lacking this hardening
    # (e.g. older library versions, or non-Python stacks) would accept.
    signing_input = f"{header_b64}.{payload_b64}".encode()
    actual_signature = base64.urlsafe_b64decode(signature_b64 + "==")
    hmac_alg = HMACAlgorithm(HMACAlgorithm.SHA256)
    assert hmac_alg.verify(signing_input, expected_pem, actual_signature) is True

    # Cross-check with a plain hmac recomputation too, independent of PyJWT.
    expected_signature = hmac.new(expected_pem, signing_input, hashlib.sha256).digest()
    assert hmac.compare_digest(actual_signature, expected_signature)

    # And prove the OLD (buggy) secret derivation would NOT have produced
    # this same signature — using the raw, still-encoded `n` string as the
    # secret (the Critical bug) yields a completely different signature.
    wrong_secret = jwk["n"].encode()
    wrong_signature = hmac.new(wrong_secret, signing_input, hashlib.sha256).digest()
    assert wrong_signature != actual_signature
    assert hmac_alg.verify(signing_input, wrong_secret, actual_signature) is False


def test_try_rs256_to_hs256_returns_none_when_jwk_cannot_be_parsed_as_rsa_key():
    # If the matching JWK is malformed (e.g. missing kty/n/e), the function
    # must fail gracefully (None), not raise, consistent with the rest of
    # this module's error handling.
    token = _make_rs256_token(kid="key-1")
    jwks_keys = [{"kid": "key-1"}]
    assert jki.try_rs256_to_hs256(token, jwks_keys) is None


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


def test_confirm_replay_false_when_forged_2xx_but_body_is_error_shaped():
    # Adversarial case the reviewer found: the forged token gets HTTP 200,
    # but the body is an error envelope (e.g. a catch-all handler that always
    # returns 2xx). The original token's response is a genuine 200 with real
    # claims, and unauth is 401. A status-code-only check would wrongly
    # report confirmed=True here; the body must be inspected.
    class _Client:
        def get(self, url, headers=None, **kwargs):
            token = (headers or {}).get("Authorization", "")
            if "forged" in token:
                return _FakeResponse(200, {"error": "invalid token", "code": "AUTH_FAILED"})
            if "original" in token:
                return _FakeResponse(200, {"sub": "alice", "role": "user"})
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is False
    assert "error" in result.detail.lower() or "shaped" in result.detail.lower()


def test_confirm_replay_false_when_forged_2xx_body_has_error_like_code_field():
    # Same class of bug, different marker shape: no top-level "error" key, but
    # a "code" field whose value is error-like ("denied"/"fail"/etc).
    class _Client:
        def get(self, url, headers=None, **kwargs):
            token = (headers or {}).get("Authorization", "")
            if "forged" in token:
                return _FakeResponse(200, {"code": "ACCESS_DENIED", "message": "nope"})
            if "original" in token:
                return _FakeResponse(200, {"sub": "alice", "role": "user"})
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is False


def test_confirm_replay_false_when_unauthenticated_baseline_already_2xx():
    # Adversarial case the reviewer found: unauth is ALSO 2xx (e.g. 200) and
    # forged is a numerically-different 2xx (e.g. 201). The old exact
    # status-code-equality check ("forged != unauth") let this through as
    # confirmed=True, even though an endpoint that already accepts
    # unauthenticated requests proves nothing about the forged token at all.
    class _Client:
        def get(self, url, headers=None, **kwargs):
            token = (headers or {}).get("Authorization", "")
            if "forged" in token:
                return _FakeResponse(201, {"sub": "alice", "role": "admin"})
            if "original" in token:
                return _FakeResponse(200, {"sub": "alice", "role": "user"})
            return _FakeResponse(200, {"public": "data"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is False
    assert "unauthenticated" in result.detail.lower()


def test_confirm_replay_false_when_forged_matches_unauthenticated_baseline():
    class _Client:
        def get(self, url, headers=None, **kwargs):
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is False


def test_confirm_replay_false_when_both_original_and_forged_coincidentally_500():
    # Adversarial case: the original token's request 500s for some unrelated
    # reason (flaky endpoint / expired original token / server hiccup), and
    # the forged token's request ALSO 500s for a completely unrelated reason.
    # A naive "forged.status_code == original.status_code" check would treat
    # this as "forged token accepted with original-token-shaped response" —
    # a genuine false positive, since neither response demonstrates anything
    # about authentication. This must now report confirmed=False.
    class _Client:
        def get(self, url, headers=None, **kwargs):
            token = (headers or {}).get("Authorization", "")
            if "forged" in token:
                return _FakeResponse(500, {"error": "internal server error"})
            if "original" in token:
                return _FakeResponse(500, {"error": "internal server error"})
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is False
    assert "baseline" in result.detail
    # Must not be reported via the old "accepted" success detail.
    assert "accepted" not in result.detail


def test_confirm_replay_false_when_original_baseline_itself_is_non_2xx():
    # Even if forged happens to land on a 2xx and diverges from unauth, an
    # original-token baseline that isn't a genuine success (non-2xx) can
    # never validate anything about the forged token.
    class _Client:
        def get(self, url, headers=None, **kwargs):
            token = (headers or {}).get("Authorization", "")
            if "forged" in token:
                return _FakeResponse(200, {"sub": "alice", "role": "admin"})
            if "original" in token:
                return _FakeResponse(403, {"error": "forbidden"})
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is False


def test_confirm_replay_true_when_original_is_genuine_2xx_and_forged_replays_success():
    # The real attack-success case must still work: a genuinely successful
    # (2xx) original-token baseline, and a forged token that independently
    # lands in the 2xx range while diverging from the unauthenticated
    # baseline, is a confirmed forgery.
    class _Client:
        def get(self, url, headers=None, **kwargs):
            token = (headers or {}).get("Authorization", "")
            if "forged" in token:
                return _FakeResponse(201, {"sub": "alice", "role": "admin"})
            if "original" in token:
                return _FakeResponse(200, {"sub": "alice", "role": "user"})
            return _FakeResponse(401, {"error": "unauthorized"})

    client = _Client()
    result = jki.confirm_replay(client, "https://api.example.com/whoami",
                                 forged_token="forged.tok.en", original_token="original.tok.en")
    assert result.confirmed is True

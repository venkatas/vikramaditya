#!/usr/bin/env python3
"""
Regression test for auth_api_tester.test_endpoint JWT-mutation gating.

Guards against fabricated critical/high JWT findings (the v10.6 audit item):
  1. JWT mutation checks (expired / tampered / alg=none) must NOT fire on a
     fully-public endpoint (no_auth already returns 200) — every token, mutated
     or not, trivially yields 200 there, which is not evidence of skipped JWT
     validation.
  2. JWT mutation checks must NOT fire for OPAQUE (non-JWT) bearers, because the
     mutation helpers return the token UNCHANGED for non-JWTs and would re-send
     the still-valid token against a server that has no JWT at all.
  3. A genuine JWT-validation bypass on a NON-public endpoint must still be
     reported.

All data is SYNTHETIC (example.invalid host, placeholder tokens).
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_api_tester import test_endpoint as run_endpoint  # noqa: E402  (aliased so pytest doesn't collect it as a test)


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


# A real-shaped (but synthetic) JWT: header.payload.signature
SYNTHETIC_JWT = f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64({'sub': 'acme', 'exp': 9999999999})}.c2lnbmF0dXJl"
# An opaque bearer (not a JWT)
OPAQUE_TOKEN = "opaque-placeholder-bearer-0000"


class FakeSession:
    """Duck-typed AuthSession: returns canned statuses keyed by the token sent.

    `status_for(token)` decides the HTTP status so tests can model a public
    endpoint (always 200) vs. a properly-protected one (200 only for the
    valid token).
    """

    base_url = "https://api.example.invalid"

    def __init__(self, status_for):
        self._status_for = status_for
        self._valid_token = None

    def set_token(self, token):
        self._valid_token = token

    def request(self, method, path, token=None, json_body=None):
        # When token is None, AuthSession would use its stored auth state
        # (the valid baseline). Model that here.
        effective = self._valid_token if token is None else token
        status = self._status_for(effective)
        return {"status": status, "url": f"{self.base_url}/{path}"}


def _types(findings):
    return {f["type"] for f in findings}


def test_public_endpoint_no_fabricated_jwt_findings():
    # Public endpoint: EVERYTHING returns 200 regardless of token.
    sess = FakeSession(lambda tok: 200)
    sess.set_token(SYNTHETIC_JWT)
    result = run_endpoint(sess, {"path": "public/", "method": "POST", "body": {}}, SYNTHETIC_JWT)
    types = _types(result["findings"])
    # The genuine no-auth finding is fine.
    assert "broken_authentication" in types
    # But NONE of the JWT mutation findings may appear on a public endpoint.
    assert "no_expiry_validation" not in types
    assert "no_signature_validation" not in types
    assert "jwt_alg_none_bypass" not in types


def test_opaque_token_no_fabricated_jwt_findings():
    # Protected endpoint, but the supplied token is opaque (not a JWT).
    # 200 only for the exact opaque token (mutations leave it unchanged, so a
    # naive impl would still send the valid token and get 200 -> false finding).
    def status_for(tok):
        return 200 if tok == OPAQUE_TOKEN else 401
    sess = FakeSession(status_for)
    sess.set_token(OPAQUE_TOKEN)
    result = run_endpoint(sess, {"path": "protected/", "method": "POST", "body": {}}, OPAQUE_TOKEN)
    types = _types(result["findings"])
    assert "no_expiry_validation" not in types
    assert "no_signature_validation" not in types
    assert "jwt_alg_none_bypass" not in types


def test_genuine_jwt_bypass_on_protected_endpoint_is_reported():
    # Protected endpoint that (broken server) accepts ANY token including
    # mutated JWTs, but rejects no-auth. This is a REAL bypass and must fire.
    def status_for(tok):
        return 401 if tok == "" else 200
    sess = FakeSession(status_for)
    sess.set_token(SYNTHETIC_JWT)
    result = run_endpoint(sess, {"path": "protected/", "method": "POST", "body": {}}, SYNTHETIC_JWT)
    types = _types(result["findings"])
    # Not public -> no broken_authentication
    assert "broken_authentication" not in types
    # Genuine JWT-validation bypasses must be reported.
    assert "no_expiry_validation" in types
    assert "no_signature_validation" in types
    assert "jwt_alg_none_bypass" in types


if __name__ == "__main__":
    test_public_endpoint_no_fabricated_jwt_findings()
    test_opaque_token_no_fabricated_jwt_findings()
    test_genuine_jwt_bypass_on_protected_endpoint_is_reported()
    print("All auth_api_tester JWT-gating tests passed.")

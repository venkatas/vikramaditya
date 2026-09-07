#!/usr/bin/env python3
"""jwt_analyze.py — deterministic static JWT weakness analyzer.

Stdlib + hmac only (no PyJWT). Clean-room idea attribution:
  s0ld13rr/pentestcode (MIT) — JWT static-check patterns.

Usage:
  python3 jwt_analyze.py <token>
  python3 jwt_analyze.py --file path
  python3 jwt_analyze.py --json <token>

This is STATIC analysis of the token bytes. High-confidence findings
(alg:none / empty alg, HMAC verified against a common secret) are marked
high_confidence=true. Other claims (missing exp, admin-ish roles, jku/x5u)
are weaknesses that need live verification before confirming Critical.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
from typing import Any

# Common / weak HMAC secrets (synthetic dictionary — not client secrets).
WEAK_HMAC_SECRETS: tuple[bytes, ...] = (
    b"secret",
    b"Secret",
    b"SECRET",
    b"password",
    b"Password",
    b"123456",
    b"1234567890",
    b"qwerty",
    b"jwt",
    b"jwtsecret",
    b"jwt-secret",
    b"jwt_secret",
    b"hs256",
    b"HS256",
    b"changeme",
    b"changeit",
    b"key",
    b"private",
    b"supersecret",
    b"your-256-bit-secret",
    b"your-512-bit-secret",
    b"mysecret",
    b"token",
    b"auth",
    b"api",
    b"apikey",
    b"api-key",
    b"",
    b"null",
    b"undefined",
    b"test",
    b"testing",
    b"admin",
    b"root",
    b"default",
)

ADMIN_CLAIM_KEYS = frozenset({
    "admin", "is_admin", "isAdmin", "role", "roles", "scope", "scopes",
    "permissions", "groups", "authorities", "privilege", "privileges",
})
ADMIN_VALUE_HINTS = frozenset({
    "admin", "administrator", "root", "superuser", "super_admin",
    "superadmin", "sudo", "*", "all", "write", "delete",
})

JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b"
)


def b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def split_jwt(token: str) -> tuple[str, str, str]:
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT: need at least header.payload")
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return parts[0], parts[1], ".".join(parts[2:])  # rare multi-dot; keep rest as sig


def parse_json_segment(segment: str) -> dict[str, Any]:
    try:
        data = json.loads(b64url_decode(segment))
    except Exception as exc:  # noqa: BLE001 — surface parse errors as findings
        raise ValueError(f"segment is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("segment JSON must be an object")
    return data


def _hmac_digest(alg: str, key: bytes, signing_input: bytes) -> bytes | None:
    alg_u = (alg or "").upper()
    if alg_u in ("HS256", "HMAC-SHA256", "HMACSHA256"):
        return hmac.new(key, signing_input, hashlib.sha256).digest()
    if alg_u in ("HS384", "HMAC-SHA384"):
        return hmac.new(key, signing_input, hashlib.sha384).digest()
    if alg_u in ("HS512", "HMAC-SHA512"):
        return hmac.new(key, signing_input, hashlib.sha512).digest()
    return None


def _sig_matches(expected: bytes, provided_b64: str) -> bool:
    try:
        provided = b64url_decode(provided_b64)
    except Exception:
        return False
    return hmac.compare_digest(expected, provided)


def _adminish_hits(claims: dict[str, Any]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for key, value in claims.items():
        key_l = str(key).lower()
        if key not in ADMIN_CLAIM_KEYS and key_l not in {k.lower() for k in ADMIN_CLAIM_KEYS}:
            # still scan values for role-like strings in known keys only
            continue
        values: list[str]
        if isinstance(value, list):
            values = [str(v) for v in value]
        elif isinstance(value, bool):
            values = ["true" if value else "false"]
        else:
            values = [str(value)]
        for v in values:
            vl = v.lower()
            if value is True or vl in ADMIN_VALUE_HINTS or "admin" in vl:
                hits.append({"claim": key, "value": value})
                break
    return hits


def analyze_token(token: str) -> dict[str, Any]:
    """Return structured static-analysis result for one JWT string."""
    token = token.strip().strip('"').strip("'")
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    result: dict[str, Any] = {
        "ok": False,
        "token_prefix": token[:16] + ("…" if len(token) > 16 else ""),
        "header": {},
        "payload": {},
        "weaknesses": [],
        "notes": [
            "STATIC ANALYSIS ONLY — do not auto-confirm Critical without live proof "
            "except high_confidence items (alg:none / verified weak HMAC secret)."
        ],
        "attribution": "idea: s0ld13rr/pentestcode (MIT) — clean-room Python",
    }

    try:
        header_b64, payload_b64, sig_b64 = split_jwt(token)
        header = parse_json_segment(header_b64)
        payload = parse_json_segment(payload_b64)
    except ValueError as exc:
        result["weaknesses"].append({
            "id": "parse_error",
            "severity": "info",
            "high_confidence": False,
            "title": "JWT parse failed",
            "detail": str(exc),
        })
        return result

    result["ok"] = True
    result["header"] = header
    result["payload"] = payload
    alg = header.get("alg", None)
    alg_s = "" if alg is None else str(alg)

    # alg:none / empty
    if alg is None or alg_s.strip() == "" or alg_s.lower() == "none":
        result["weaknesses"].append({
            "id": "alg_none",
            "severity": "high",
            "high_confidence": True,
            "title": "alg is none/empty",
            "detail": (
                f"header.alg={alg!r}. Tokens accepting alg:none skip signature "
                "verification on vulnerable libraries (high-confidence static finding)."
            ),
        })

    # jku / x5u — attacker-controlled JWKS/cert URL
    for claim in ("jku", "x5u"):
        if claim in header and header.get(claim):
            result["weaknesses"].append({
                "id": f"header_{claim}",
                "severity": "high",
                "high_confidence": False,
                "title": f"header contains {claim}",
                "detail": (
                    f"{claim}={header.get(claim)!r}. If the verifier fetches this URL "
                    "without allowlisting, an attacker can point it at a malicious JWKS/cert. "
                    "Needs live confirmation against the target verifier."
                ),
            })

    # Missing standard time/issuer claims
    for claim, sev in (("exp", "medium"), ("iat", "low"), ("iss", "low")):
        if claim not in payload:
            result["weaknesses"].append({
                "id": f"missing_{claim}",
                "severity": sev,
                "high_confidence": False,
                "title": f"payload missing '{claim}'",
                "detail": (
                    f"No '{claim}' claim. Missing exp enables indefinite token reuse if "
                    "the server does not enforce server-side expiry."
                    if claim == "exp"
                    else f"No '{claim}' claim — often weakens replay/issuer binding checks."
                ),
            })

    # Weak / common HMAC secrets
    alg_u = alg_s.upper()
    if alg_u.startswith("HS") or alg_u in ("HMAC-SHA256", "HMACSHA256", "HMAC-SHA384", "HMAC-SHA512"):
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        matched: str | None = None
        for secret in WEAK_HMAC_SECRETS:
            digest = _hmac_digest(alg_u, secret, signing_input)
            if digest is None:
                break
            if _sig_matches(digest, sig_b64):
                matched = secret.decode("utf-8", "replace") if secret else "(empty string)"
                break
        if matched is not None:
            result["weaknesses"].append({
                "id": "weak_hmac_secret",
                "severity": "critical",
                "high_confidence": True,
                "title": "HMAC signature matches a common/weak secret",
                "detail": (
                    f"alg={alg_s} verified with dictionary secret {matched!r}. "
                    "High-confidence: signature check succeeded locally."
                ),
            })
        elif not sig_b64:
            result["weaknesses"].append({
                "id": "missing_signature",
                "severity": "high",
                "high_confidence": True,
                "title": "HMAC alg but empty signature segment",
                "detail": "Token declares an HMAC alg but has no signature bytes.",
            })

    # Admin-ish claims
    for hit in _adminish_hits(payload):
        result["weaknesses"].append({
            "id": "adminish_claim",
            "severity": "medium",
            "high_confidence": False,
            "title": f"admin-ish claim: {hit['claim']}={hit['value']!r}",
            "detail": (
                "Static claim looks privileged. Confirm the verifier trusts this claim "
                "and that it is attacker-controllable (forgery / alg confusion / weak secret)."
            ),
        })

    # kid quirks (informational)
    kid = header.get("kid")
    if isinstance(kid, str) and any(x in kid for x in ("../", "file:", "http://", "https://", "|", ";")):
        result["weaknesses"].append({
            "id": "suspicious_kid",
            "severity": "medium",
            "high_confidence": False,
            "title": "suspicious kid value",
            "detail": f"kid={kid!r} looks like path/URL/injection — test JWKS path traversal / SQLi in kid.",
        })

    return result


def format_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("=== jwt_analyze (static) ===")
    lines.append(f"ok={result.get('ok')} token={result.get('token_prefix')}")
    if result.get("header"):
        lines.append(f"header: {json.dumps(result['header'], sort_keys=True)}")
    if result.get("payload"):
        # Avoid dumping huge payloads
        payload = result["payload"]
        shown = {k: payload[k] for k in list(payload)[:30]}
        lines.append(f"payload: {json.dumps(shown, sort_keys=True, default=str)}")
    weaknesses = result.get("weaknesses") or []
    if not weaknesses:
        lines.append("weaknesses: (none detected by static checks)")
    else:
        lines.append(f"weaknesses ({len(weaknesses)}):")
        for w in weaknesses:
            hc = "high-confidence" if w.get("high_confidence") else "needs-live-verify"
            lines.append(
                f"  [{w.get('severity', '?').upper()}/{hc}] {w.get('id')}: {w.get('title')}"
            )
            detail = (w.get("detail") or "").strip()
            if detail:
                lines.append(f"           {detail}")
    for note in result.get("notes") or []:
        lines.append(f"note: {note}")
    lines.append(f"credit: {result.get('attribution')}")
    return "\n".join(lines) + "\n"


def extract_jwts(text: str) -> list[str]:
    return list(dict.fromkeys(JWT_RE.findall(text or "")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static JWT weakness analyzer (stdlib+hmac)")
    parser.add_argument("token", nargs="?", help="JWT string (or use --file)")
    parser.add_argument("--file", "-f", help="Read token from file")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
    elif args.token:
        raw = args.token
    else:
        parser.error("provide a token argument or --file")

    # If the file/arg contains multiple JWTs, analyze the first and note extras.
    found = extract_jwts(raw)
    token = found[0] if found else raw.strip()
    result = analyze_token(token)
    if len(found) > 1:
        result.setdefault("notes", []).append(
            f"input contained {len(found)} JWT-shaped strings; analyzed the first"
        )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        sys.stdout.write(format_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

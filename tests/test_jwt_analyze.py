"""Unit tests for jwt_analyze — synthetic tokens only (no real client JWTs)."""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
from pathlib import Path

import pytest

import jwt_analyze
from jwt_analyze import analyze_token, b64url_encode, extract_jwts, format_text, main


ROOT = Path(__file__).resolve().parents[1]


def _make_hs256(payload: dict, secret: bytes = b"secret", header: dict | None = None) -> str:
    hdr = header or {"alg": "HS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def _make_unsigned(payload: dict, alg: str = "none") -> str:
    h = b64url_encode(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def test_weak_hmac_secret_high_confidence():
    tok = _make_hs256({"sub": "user1", "iat": 1})
    result = analyze_token(tok)
    weak = [w for w in result["weaknesses"] if w["id"] == "weak_hmac_secret"]
    assert weak, result["weaknesses"]
    assert weak[0]["high_confidence"] is True
    assert weak[0]["severity"] == "critical"


def test_alg_none_high_confidence():
    tok = _make_unsigned({"sub": "x"})
    result = analyze_token(tok)
    none = [w for w in result["weaknesses"] if w["id"] == "alg_none"]
    assert none
    assert none[0]["high_confidence"] is True
    assert none[0]["severity"] == "high"


def test_missing_exp_iat_iss():
    tok = _make_hs256({"sub": "u"}, secret=b"not-in-dictionary-zz")
    result = analyze_token(tok)
    ids = {w["id"] for w in result["weaknesses"]}
    assert "missing_exp" in ids
    assert "missing_iat" in ids
    assert "missing_iss" in ids
    # unknown secret → no weak_hmac hit
    assert "weak_hmac_secret" not in ids


def test_jku_x5u_and_admin_claim():
    hdr = {
        "alg": "HS256",
        "typ": "JWT",
        "jku": "https://evil.example/jwks.json",
        "x5u": "https://evil.example/cert.pem",
    }
    tok = _make_hs256({"sub": "u", "role": "admin", "exp": 9999999999}, header=hdr)
    result = analyze_token(tok)
    ids = {w["id"] for w in result["weaknesses"]}
    assert "header_jku" in ids
    assert "header_x5u" in ids
    assert "adminish_claim" in ids
    # jku/x5u / adminish are NOT auto high-confidence
    for w in result["weaknesses"]:
        if w["id"] in {"header_jku", "header_x5u", "adminish_claim"}:
            assert w["high_confidence"] is False


def test_format_text_and_json_cli(tmp_path):
    tok = _make_unsigned({"sub": "cli"})
    text = format_text(analyze_token(tok))
    assert "alg_none" in text or "alg is none" in text
    assert "STATIC ANALYSIS" in text.upper() or "static" in text.lower()

    f = tmp_path / "tok.txt"
    f.write_text(tok)
    rc = main(["--json", "--file", str(f)])
    assert rc == 0


def test_extract_jwts_from_noise():
    tok = _make_hs256({"sub": "a"})
    blob = f"Authorization: Bearer {tok}\nother junk"
    found = extract_jwts(blob)
    assert tok in found


def test_cli_subprocess_smoke():
    tok = _make_hs256({"sub": "smoke"})
    proc = subprocess.run(
        [sys.executable, str(ROOT / "jwt_analyze.py"), tok],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        check=False,
    )
    assert proc.returncode == 0
    assert "weak_hmac_secret" in proc.stdout or "weak" in proc.stdout.lower()

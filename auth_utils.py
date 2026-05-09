#!/usr/bin/env python3
from __future__ import annotations
"""
Shared utilities for authenticated API testing modules.

Provides: RateLimiter, JWTHelper, AuthSession, FindingSaver, totp_code.
No PyJWT / pyotp dependency — JWT and TOTP are stdlib-only.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

# v9.x — Semgrep ERROR finding (requests verify=False). Default to strict TLS
# verification; allow opt-out via VAPT_INSECURE_SSL=1 for engagements that
# legitimately target self-signed staging hosts.
VERIFY_TLS = os.environ.get("VAPT_INSECURE_SSL", "0") != "1"


# ── TOTP (RFC 6238) — stdlib only ─────────────────────────────────────────────
def totp_code(
    secret: str,
    step: int | None = None,
    period: int = 30,
    digits: int = 6,
) -> str:
    """Generate an RFC-6238 TOTP code for a base32-encoded shared secret.

    Used by Vikramaditya to log in to MFA-protected applications (e.g.
    clientk) during authorised VAPT, where the client provides a
    test-account TOTP secret. The scanner must not disable MFA on the
    target — it must mint a valid code.

    Parameters
    ----------
    secret : str
        Base32 secret as exported by the authenticator app. Whitespace is
        stripped and the value is uppercased before decoding so values
        copy/pasted with spaces ("JBSW Y3DP EHPK 3PXP") still work.
    step : int | None
        Override the time-step counter (mostly used in tests). When
        ``None`` (the default) the current Unix time is used.
    period : int
        Time step in seconds. RFC 6238 default is 30.
    digits : int
        Number of digits in the produced code. RFC 6238 default is 6.

    Returns
    -------
    str
        Zero-padded ``digits``-character numeric string.

    Notes
    -----
    Caller should treat the returned value as one-time and short-lived.
    This function intentionally does **not** brute-force adjacent windows
    — that belongs in a dedicated MFA-replay tool, not in scan paths.
    """
    if not secret:
        raise ValueError("totp_code: secret is required")

    cleaned = "".join(secret.split()).upper()
    # Right-pad to a multiple of 8 with base32 padding so partial-length
    # secrets from QR scans still decode.
    padding = (-len(cleaned)) % 8
    cleaned += "=" * padding
    try:
        key = base64.b32decode(cleaned, casefold=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("totp_code: secret is not valid base32") from exc

    counter = int(time.time() // period) if step is None else int(step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    code = truncated % (10 ** digits)
    return str(code).zfill(digits)


class RateLimiter:
    """Enforces max requests per second."""

    def __init__(self, max_rps: float = 10.0):
        self._interval = 1.0 / max_rps if max_rps > 0 else 0
        self._last = 0.0

    def wait(self) -> float:
        now = time.monotonic()
        elapsed = now - self._last
        wait_time = max(0.0, self._interval - elapsed)
        if wait_time > 0:
            time.sleep(wait_time)
        self._last = time.monotonic()
        return wait_time


class JWTHelper:
    """Manual JWT manipulation without PyJWT."""

    @staticmethod
    def _b64_decode(data: str) -> bytes:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @classmethod
    def decode_payload(cls, token: str) -> dict:
        """Decode JWT payload without verification."""
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        try:
            return json.loads(cls._b64_decode(parts[1]))
        except Exception:
            return {}

    @classmethod
    def decode_header(cls, token: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        try:
            return json.loads(cls._b64_decode(parts[0]))
        except Exception:
            return {}

    @classmethod
    def tamper_signature(cls, token: str) -> str:
        """Flip last character of signature to invalidate it."""
        parts = token.split(".")
        if len(parts) != 3:
            return token
        sig = parts[2]
        if not sig:
            return token
        last = sig[-1]
        flipped = "A" if last != "A" else "B"
        return f"{parts[0]}.{parts[1]}.{sig[:-1]}{flipped}"

    @classmethod
    def expire_token(cls, token: str) -> str:
        """Re-encode token with exp set to past (unsigned — tests server validation)."""
        parts = token.split(".")
        if len(parts) != 3:
            return token
        try:
            payload = json.loads(cls._b64_decode(parts[1]))
            payload["exp"] = 1000000000  # 2001-09-08 — expired
            new_payload = cls._b64_encode(json.dumps(payload, separators=(",", ":")).encode())
            return f"{parts[0]}.{new_payload}.{parts[2]}"
        except Exception:
            return token

    @classmethod
    def set_alg_none(cls, token: str) -> str:
        """Create alg=none token (tests server ignores algorithm)."""
        parts = token.split(".")
        if len(parts) != 3:
            return token
        try:
            header = json.loads(cls._b64_decode(parts[0]))
            header["alg"] = "none"
            new_header = cls._b64_encode(json.dumps(header, separators=(",", ":")).encode())
            return f"{new_header}.{parts[1]}."
        except Exception:
            return token


class AuthSession:
    """Manages authenticated HTTP sessions with auto-login and token refresh."""

    def __init__(self, base_url: str, rate_limiter: RateLimiter = None):
        import requests as _req
        self._session = _req.Session()
        self._session.verify = False
        self.base_url = base_url.rstrip("/")
        self._limiter = rate_limiter or RateLimiter(10.0)
        self._creds = None
        self._login_url = None
        self.token = None
        # Suppress InsecureRequestWarning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def set_token(self, token: str):
        self.token = token
        self._session.headers["Authorization"] = f"Bearer {token}"

    def auto_login(
        self,
        login_path: str,
        username: str,
        password: str,
        totp_secret: str = "",
        totp_code_value: str = "",
        login_surface: str = "workspace",
        admin_path: str = "",
    ) -> str:
        """Login and extract a bearer token from response body or cookies.

        Supports MFA-protected apps such as clientk. When the supplied
        ``login_path`` is the clientk contract (``auth/login``), the
        clientk JSON shape is tried first:

            {
              "email":         <username>,
              "password":      <password>,
              "totp":          <generated_or_supplied_code>,
              "loginSurface":  workspace | superadmin,
              "adminPath":     <only sent for superadmin tests>
            }

        For all other endpoints the legacy generic-shape fallbacks (JSON
        + form-data, ``email``/``username`` keys) are tried in turn,
        with the TOTP code injected when present.

        Parameters
        ----------
        totp_secret
            Base32 secret. When non-empty and ``totp_code_value`` is empty,
            ``totp_code()`` is called to mint the current code.
        totp_code_value
            Pre-minted 6-digit TOTP code (overrides ``totp_secret``).
        login_surface
            clientk workspace selector. Defaults to ``workspace``;
            callers must explicitly request ``superadmin`` to test the
            admin surface.
        admin_path
            clientk admin path, only sent when ``login_surface`` is
            ``superadmin``.

        Returns
        -------
        str
            The bearer token or ``"cookie-auth"`` sentinel. Empty string
            on hard failure.

        Raises
        ------
        RuntimeError
            When the server replies with ``requiresTotp=true`` and no
            usable TOTP was supplied / generated. We fail loudly rather
            than silently fall back, to avoid masking misconfigured
            engagements.
        """
        self._login_url = login_path
        self._creds = (username, password)
        url = f"{self.base_url}/{login_path.lstrip('/')}"

        # Mint the TOTP code once for this login attempt, if a secret was
        # supplied and no code was passed in directly. Codes are not logged.
        code = totp_code_value
        if not code and totp_secret:
            try:
                code = totp_code(totp_secret)
            except ValueError as exc:
                raise RuntimeError(f"auto_login: cannot derive TOTP code: {exc}") from exc

        # clientk path — explicit JSON contract for /auth/login.
        is_clientk_path = login_path.strip("/").lower() == "auth/login"
        payload_attempts: list[dict] = []
        if is_clientk_path:
            evid_body: dict = {
                "email": username,
                "password": password,
                "loginSurface": login_surface or "workspace",
            }
            if code:
                evid_body["totp"] = code
            if (login_surface or "").lower() == "superadmin":
                # Only include adminPath when a superadmin test is explicitly requested.
                evid_body["adminPath"] = admin_path or ""
            payload_attempts.append({"json": evid_body})

        # Generic fallback shapes — also include totp when minted.
        generic_email_json = {"email": username, "password": password}
        generic_email_form = {"email": username, "password": password}
        generic_user_json = {"username": username, "password": password}
        if code:
            generic_email_json["totp"] = code
            generic_email_form["totp"] = code
            generic_user_json["totp"] = code
        payload_attempts.extend([
            {"json": generic_email_json},
            {"data": generic_email_form},
            {"json": generic_user_json},
        ])

        last_requires_totp = False
        last_error: str = ""

        for payload_kwargs in payload_attempts:
            self._limiter.wait()
            try:
                resp = self._session.post(url, timeout=15, **payload_kwargs)
            except Exception as exc:  # noqa: BLE001 — generic transport guard
                last_error = type(exc).__name__
                continue

            try:
                body = resp.json()
            except Exception:
                body = {}

            # Server explicitly asked for TOTP and we don't have one — surface it.
            if isinstance(body, dict) and body.get("requiresTotp") is True and not code:
                last_requires_totp = True
                continue

            # clientk / generic: response body token (JWT or opaque).
            token = ""
            if isinstance(body, dict):
                data = body.get("data") if isinstance(body.get("data"), dict) else {}
                token = (
                    body.get("token")
                    or body.get("access_token")
                    or data.get("token")
                    or data.get("access_token")
                    or ""
                )
            if token:
                self.set_token(token)
                return token

            # JWT-shaped cookie fallback.
            for cookie_name in ("cf_at", "access_token", "jwt", "token", "session"):
                cookie_val = resp.cookies.get(cookie_name) or self._session.cookies.get(cookie_name)
                if cookie_val and cookie_val.count(".") == 2:
                    self.token = cookie_val
                    return cookie_val

            # Cookie-auth fallback when the server replied 2xx without a token.
            if resp.status_code in (200, 201) or (isinstance(body, dict) and body.get("status") is True):
                if self._session.cookies:
                    self.token = "cookie-auth"
                    return "cookie-auth"

        if last_requires_totp:
            # Don't swallow MFA enforcement — caller must supply secret/code.
            raise RuntimeError(
                "auto_login: server requires TOTP (requiresTotp=true) but no "
                "totp_secret/totp_code was supplied. Pass --totp-secret or "
                "--totp-code (or --auth-token to skip password login)."
            )
        return ""

    def request(self, method: str, path: str, token: str = None,
                json_body: dict = None, data: dict = None,
                headers: dict = None, timeout: int = 15) -> dict:
        """Make an HTTP request with rate limiting.

        Token handling:
        - token=None: use session's current auth state (cookies + headers)
        - token="": strip all auth (no cookies, no Authorization header)
        - token="<jwt>": send as both Bearer header AND cf_at cookie
        """
        self._limiter.wait()
        url = f"{self.base_url}/{path.lstrip('/')}"
        hdrs = dict(self._session.headers)
        cookies = dict(self._session.cookies)

        if token is not None:
            if token == "":
                # No auth: strip everything
                hdrs.pop("Authorization", None)
                cookies = {}
            elif token == "cookie-auth":
                # Cookie-based auth: use session cookies as-is
                hdrs.pop("Authorization", None)
            else:
                # Token auth: send as both Bearer header and cf_at cookie
                hdrs["Authorization"] = f"Bearer {token}"
                cookies["cf_at"] = token
        if headers:
            hdrs.update(headers)
        try:
            if token == "":
                # No auth: use a bare request (no session cookies)
                import requests as _bare_req
                resp = _bare_req.request(
                    method, url, json=json_body, data=data,
                    headers=hdrs, timeout=timeout, allow_redirects=False,
                    verify=VERIFY_TLS,
                )
            elif token is not None and token != "cookie-auth":
                # Explicit token: bare request with ONLY this token (no session cookies)
                import requests as _bare_req
                resp = _bare_req.request(
                    method, url, json=json_body, data=data,
                    headers=hdrs, cookies={"cf_at": token},
                    timeout=timeout, allow_redirects=False,
                    verify=VERIFY_TLS,
                )
            else:
                # Default: use session as-is (carries login cookies)
                resp = self._session.request(
                    method, url, json=json_body, data=data,
                    headers=hdrs, timeout=timeout, allow_redirects=False,
                )
            try:
                body = resp.json()
            except Exception:
                body = resp.text[:2000]
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": body,
                "url": url,
                "method": method,
            }
        except Exception as e:
            return {"status": 0, "headers": {}, "body": str(e), "url": url, "method": method}


class FindingSaver:
    """Saves findings as JSON files."""

    def __init__(self, findings_dir: str, category: str):
        self.dir = os.path.join(findings_dir, category)
        os.makedirs(self.dir, exist_ok=True)
        self._findings = []

    def save(self, finding: dict):
        self._findings.append(finding)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        idx = len(self._findings)
        path = os.path.join(self.dir, f"finding_{ts}_{idx:04d}.json")
        with open(path, "w") as f:
            json.dump(finding, f, indent=2, default=str)

    def save_txt(self, finding: dict):
        """Also append one-liner to a summary text file for reporter.py."""
        txt_path = os.path.join(self.dir, "findings.txt")
        sev = finding.get("severity", "medium").upper()
        url = finding.get("url", "N/A")
        detail = finding.get("detail", finding.get("type", ""))
        with open(txt_path, "a") as f:
            f.write(f"[{sev}] {detail} {url}\n")

    def save_summary(self):
        path = os.path.join(self.dir, "summary.json")
        with open(path, "w") as f:
            json.dump({"total": len(self._findings), "findings": self._findings}, f, indent=2, default=str)

    @property
    def count(self):
        return len(self._findings)

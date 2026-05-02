#!/usr/bin/env python3
from __future__ import annotations
"""
Shared utilities for authenticated API testing modules.

Provides: RateLimiter, JWTHelper, AuthSession, FindingSaver.
No PyJWT dependency — JWT decode/tamper is manual base64.
"""

import base64
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

# v9.x — Semgrep ERROR finding (requests verify=False). Default to strict TLS
# verification; allow opt-out via VAPT_INSECURE_SSL=1 for engagements that
# legitimately target self-signed staging hosts.
VERIFY_TLS = os.environ.get("VAPT_INSECURE_SSL", "0") != "1"


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

    def auto_login(self, login_path: str, username: str, password: str) -> str:
        """Login and extract JWT token from response body or cookies.

        Tries JSON body first, then form-data. Checks response body for token,
        then cookies (cf_at, access_token, token, jwt).
        """
        self._login_url = login_path
        self._creds = (username, password)
        url = f"{self.base_url}/{login_path.lstrip('/')}"
        self._limiter.wait()

        # Try JSON first, then form-data
        for payload_kwargs in [
            {"json": {"email": username, "password": password}},
            {"data": {"email": username, "password": password}},
            {"json": {"username": username, "password": password}},
        ]:
            try:
                resp = self._session.post(url, timeout=15, **payload_kwargs)
                # Check response body for token
                try:
                    body = resp.json()
                except Exception:
                    body = {}
                token = (body.get("token") or body.get("access_token")
                         or (body.get("data") or {}).get("token")
                         or (body.get("data") or {}).get("access_token") or "")
                if token:
                    self.set_token(token)
                    return token

                # Check cookies for JWT (common patterns: cf_at, access_token, jwt, token)
                for cookie_name in ("cf_at", "access_token", "jwt", "token", "session"):
                    cookie_val = resp.cookies.get(cookie_name) or self._session.cookies.get(cookie_name)
                    if cookie_val and cookie_val.count(".") == 2:  # JWT format: header.payload.sig
                        self.token = cookie_val
                        # Keep cookies in session (already stored by requests.Session)
                        return cookie_val

                # If we got a success response but no token, cookies may handle auth
                if body.get("status") is True or resp.status_code in (200, 201):
                    # Check if session cookies were set
                    if self._session.cookies:
                        self.token = "cookie-auth"
                        return "cookie-auth"
            except Exception:
                continue
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

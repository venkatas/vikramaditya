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
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# v9.x — Semgrep ERROR finding (requests verify=False). Default to strict TLS
# verification; allow opt-out via VAPT_INSECURE_SSL=1 for engagements that
# legitimately target self-signed staging hosts.
VERIFY_TLS = os.environ.get("VAPT_INSECURE_SSL", "0") != "1"


class ReauthRequired(RuntimeError):
    """Raised when the server signals the grant is dead (invalid_grant / refresh
    token expired or revoked) and only a fresh interactive login can recover.

    A subclass of RuntimeError so existing ``except RuntimeError`` callers still
    catch it, while new code can catch it specifically to re-prompt the operator
    instead of limping on unauthenticated for the rest of a long engagement.
    """


# Server responses that mean "this grant is permanently dead — re-auth needed",
# as opposed to an ordinary wrong-password failure we should just report.
_GRANT_DEAD_SIGNALS = (
    "invalid_grant", "invalid grant", "token expired", "token_expired",
    "refresh token", "refresh_token expired", "grant expired",
    "expired token", "revoked",
)


# ── TOTP (RFC 6238) — stdlib only ─────────────────────────────────────────────
def totp_code(
    secret: str,
    step: int | None = None,
    period: int = 30,
    digits: int = 6,
) -> str:
    """Generate an RFC-6238 TOTP code for a base32-encoded shared secret.

    Used by Vikramaditya to log in to MFA-protected target applications
    during authorised VAPT, where the client provides a test-account
    TOTP secret. The scanner must not disable MFA on the target — it
    must mint a valid code.

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
        # Guards the read-compute-write of self._last so the limiter stays
        # correct if a single instance is ever shared across threads
        # (e.g. driven from a ThreadPoolExecutor). Without it, concurrent
        # callers could read the same stale _last and fire simultaneously,
        # briefly exceeding the configured per-second cap.
        self._lock = threading.Lock()

    def wait(self) -> float:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            wait_time = max(0.0, self._interval - elapsed)
            # Reserve this caller's slot before releasing the lock so a
            # concurrent caller computes its wait relative to ours, instead
            # of racing on a stale timestamp. Sleep happens outside the lock.
            self._last = now + wait_time
        if wait_time > 0:
            time.sleep(wait_time)
        return wait_time


class JWTHelper:
    """Manual JWT manipulation without PyJWT."""

    @staticmethod
    def is_jwt(token: str) -> bool:
        """
        Return True if ``token`` looks like a JWT (three dot-separated
        base64url segments where the header and payload decode to JSON
        objects). Returns False for opaque bearers, empty strings, the
        ``cookie-auth`` sentinel, etc. Used by scanners that want to
        skip JWT-specific checks (alg/exp inspection, alg=none flips,
        signature tampering) on non-JWT tokens.
        """
        if not isinstance(token, str) or token.count(".") != 2:
            return False
        head, payload, sig = token.split(".")
        if not head or not payload or not sig:
            return False
        try:
            header_obj = json.loads(JWTHelper._b64_decode(head))
            payload_obj = json.loads(JWTHelper._b64_decode(payload))
        except Exception:
            return False
        return isinstance(header_obj, dict) and isinstance(payload_obj, dict)

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
        # Cookie name carrying the auth token for explicit-token requests. Defaults to
        # 'cf_at' but is overwritten in auto_login() with whichever cookie the server
        # actually set the JWT in (cf_at/access_token/jwt/token/session), so cookie-only
        # (non-Bearer) apps are sent the token under the RIGHT cookie name — otherwise an
        # explicit-token request would carry an unrecognised 'cf_at' and falsely 401.
        self._auth_cookie_name = "cf_at"
        # Expiry deadline (unix seconds) decoded from a JWT `exp` claim, or None
        # for opaque bearers / cookie-auth. Lets callers proactively re-auth.
        self.token_expires_at: int | None = None
        # Sticky flag: the server told us the grant is dead and a fresh
        # interactive login is required (see ReauthRequired).
        self.requires_reauth = False
        # Suppress InsecureRequestWarning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def set_token(self, token: str):
        self.token = token
        self._session.headers["Authorization"] = f"Bearer {token}"
        # Track expiry from the JWT exp claim so the caller can refresh before
        # a request 401s mid-scan. Opaque tokens leave it None (= unknown). We do
        # NOT gate on is_jwt() — that requires a non-empty signature, which would
        # skip alg=none tokens (empty 3rd segment). Any 3-segment token whose
        # payload decodes is enough to read exp. exp may be a number OR a numeric
        # string depending on the IdP.
        self.token_expires_at = None
        try:
            if isinstance(token, str) and token.count(".") == 2:
                exp = JWTHelper.decode_payload(token).get("exp")
                if isinstance(exp, bool):
                    pass  # JSON true/false is not an expiry
                elif isinstance(exp, (int, float)):
                    self.token_expires_at = int(exp)
                elif isinstance(exp, str):
                    self.token_expires_at = int(float(exp.strip()))
        except Exception:
            self.token_expires_at = None

    def is_token_expired(self, skew: int = 0) -> bool:
        """True if the current JWT's exp is at/past now (+skew seconds).

        Unknown expiry (opaque token / cookie-auth) returns False — we only
        report expiry we can actually prove from a decoded `exp` claim.
        """
        if self.token_expires_at is None:
            return False
        return (time.time() + skew) >= self.token_expires_at

    @staticmethod
    def _grant_is_dead(status: int, body) -> bool:
        """Detect an invalid_grant / expired-or-revoked-refresh signal in a
        login/refresh response so we can surface ReauthRequired instead of
        silently failing.

        Gated on a client-auth FAILURE status (400/401/403): a 2xx success body
        that merely mentions "revoked"/"expired" (e.g. "your old token was revoked,
        here is a new one") must NOT force a re-auth. The structured OAuth `error`
        field is the authoritative signal; a text scan is the fallback for servers
        that return the reason in prose or form-encoding."""
        try:
            code = int(status)
        except Exception:
            code = 0
        if code not in (400, 401, 403):
            return False
        if isinstance(body, dict):
            err = str(body.get("error", "")).strip().lower()
            if err in ("invalid_grant", "invalid_token", "token_expired", "invalid_refresh_token"):
                return True
        try:
            text = json.dumps(body, default=str).lower() if isinstance(body, (dict, list)) else str(body).lower()
        except Exception:
            text = str(body).lower()
        return any(sig in text for sig in _GRANT_DEAD_SIGNALS)

    def auto_login(
        self,
        login_path: str,
        username: str,
        password: str,
        totp_secret: str = "",
        totp_code_value: str = "",
        extra_fields: dict | None = None,
    ) -> str:
        """Login and extract a bearer token from response body or cookies.

        Supports MFA-protected target applications. The scanner mints a
        TOTP code at login time (RFC 6238) so MFA does **not** have to
        be disabled on the target.

        Login body shapes attempted, in order:

        1. ``{"email": …, "password": …}`` (JSON) — with ``totp`` injected
           when a code was minted, and any caller-supplied ``extra_fields``
           merged in.
        2. The same fields as form-data.
        3. ``{"username": …, "password": …}`` (JSON) — JSON variant for
           targets that key off ``username`` instead of ``email``.

        ``extra_fields`` is a free-form dict that lets callers supply
        application-specific metadata the target's login endpoint
        requires (e.g. a workspace / surface selector, an admin path,
        a tenant id). Vikramaditya stays application-agnostic — the
        operator decides what extra fields the target needs.

        Parameters
        ----------
        totp_secret
            Base32 secret. When non-empty and ``totp_code_value`` is empty,
            ``totp_code()`` is called to mint the current code.
        totp_code_value
            Pre-minted 6-digit TOTP code (overrides ``totp_secret``).
        extra_fields
            Optional mapping of additional JSON body fields to merge into
            the login request. Caller-supplied; not interpreted here.

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

        extra = dict(extra_fields) if extra_fields else {}

        # Build the standard candidate payloads. Caller-supplied extra_fields
        # are merged into every JSON-shaped attempt so app-specific metadata
        # (workspace selector, tenant id, admin path, …) reaches the server.
        def _with(base: dict) -> dict:
            merged = dict(base)
            if code:
                merged["totp"] = code
            merged.update(extra)
            return merged

        payload_attempts: list[dict] = [
            {"json": _with({"email": username, "password": password})},
            {"data": _with({"email": username, "password": password})},
            {"json": _with({"username": username, "password": password})},
        ]

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
                # Non-JSON (form-encoded / plain-text) error bodies must still be
                # scannable for an invalid_grant signal — keep the raw text rather
                # than discarding it as {}. Downstream dict-shaped checks guard with
                # isinstance(body, dict), so a string here is safe.
                try:
                    body = resp.text
                except Exception:
                    body = {}

            # Grant is dead (invalid_grant / expired-or-revoked refresh): a fresh
            # interactive login is the only recovery — fail loudly so the caller
            # can re-prompt instead of limping on unauthenticated. This is a
            # grant-level error, identical across payload shapes, so raise now.
            if self._grant_is_dead(getattr(resp, "status_code", 0), body):
                self.requires_reauth = True
                raise ReauthRequired(
                    "auto_login: server reports the grant is dead "
                    "(invalid_grant / refresh token expired or revoked). "
                    "A fresh interactive login is required."
                )

            # Server explicitly asked for TOTP and we don't have one — surface it.
            if isinstance(body, dict) and body.get("requiresTotp") is True and not code:
                last_requires_totp = True
                continue

            # Response body token (JWT or opaque).
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
                    # Remember which cookie the server uses so explicit-token requests
                    # send the token under the SAME name (not a hardcoded 'cf_at').
                    self._auth_cookie_name = cookie_name
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
                # Token auth: send as both Bearer header and the auth cookie. The
                # cookie name is whatever auto_login() observed the server set the JWT
                # in (default 'cf_at'), so cookie-only apps aren't falsely 401'd.
                hdrs["Authorization"] = f"Bearer {token}"
                cookies[self._auth_cookie_name] = token
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
                    headers=hdrs, cookies={self._auth_cookie_name: token},
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
        # Microsecond resolution + pid + uuid removes the realistic collision
        # window between two same-category savers writing within one UTC second.
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        idx = len(self._findings)
        suffix = uuid.uuid4().hex[:6]
        # "x" (exclusive create) converts any residual collision into a loud
        # FileExistsError instead of silently truncating/clobbering a finding.
        for _ in range(5):
            path = os.path.join(
                self.dir,
                f"finding_{ts}_{os.getpid()}_{idx:04d}_{suffix}.json",
            )
            try:
                with open(path, "x") as f:
                    json.dump(finding, f, indent=2, default=str)
                return
            except FileExistsError:
                # Astronomically unlikely; regenerate the random suffix rather
                # than overwrite an existing finding file.
                suffix = uuid.uuid4().hex[:6]
        raise FileExistsError(
            f"FindingSaver.save: could not allocate a unique path in {self.dir}"
        )

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

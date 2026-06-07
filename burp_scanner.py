#!/usr/bin/env python3
"""Burp Suite Professional active-scan integration (REST API v0.1).

Wires Burp's crawl-and-audit engine into Vikramaditya so a target can be actively
scanned by Burp and its issues folded into the same Burp Suite-style report as
every other engine.

The REST API must be enabled in Burp: Settings -> Suite -> REST API ->
"Service running", note the port (default 1337) and the API key. The API key is
part of the URL PATH, so the full base URL is a secret — it is read from the
``BURP_API_KEY`` env var (never hardcoded) and redacted in all output.

Usage (standalone):
    export BURP_API_KEY=...                       # from Burp's REST API settings
    python3 burp_scanner.py --target https://app.example.com \
        --output findings/app.example.com/burp \
        --creds "user@example.com:pass" --scope-lock

Programmatic (from the orchestrator):
    from burp_scanner import run_burp_scan, burp_reachable
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from html import unescape
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover - requests is a hard dep of the suite
    requests = None

# ── Colours / logging ─────────────────────────────────────────────────────────
G = "\033[0;32m"; R = "\033[0;31m"; Y = "\033[1;33m"; C = "\033[0;36m"
M = "\033[0;35m"; B = "\033[1m"; D = "\033[0;90m"; N = "\033[0m"


def log(level: str, msg: str):
    cols = {"ok": G, "err": R, "warn": Y, "info": C, "burp": M, "phase": "\033[0;34m"}
    sym = {"ok": "+", "err": "-", "warn": "!", "info": "*", "burp": "🐛", "phase": "»"}
    print(f"  {cols.get(level,'')}[{sym.get(level,'*')}]{N} {msg}", flush=True)


# ── Config (env-driven, no hardcoded secrets) ─────────────────────────────────
DEFAULT_API_URL = os.environ.get("BURP_API_URL", "http://127.0.0.1:1337")
# Named configs are install-specific and an unknown name 400s on desktop Burp, so
# there is NO hardcoded default — empty means "let Burp use its built-in default".
# Override per run via $BURP_SCAN_CONFIG or --config (must be a config that exists).
DEFAULT_CONFIG = os.environ.get("BURP_SCAN_CONFIG", "")
# Overall wait budget + poll cadence (seconds).
SCAN_TIMEOUT = int(os.environ.get("BURP_SCAN_TIMEOUT", "1800"))
POLL_INTERVAL = int(os.environ.get("BURP_POLL_INTERVAL", "15"))

# Burp severity -> reporter severity. Burp's top severity is "high" (no critical),
# and it labels informational issues "Information"/"info". Clamp anything unknown.
_SEV_MAP = {
    "high": "high", "medium": "medium", "low": "low",
    "info": "info", "information": "info", "informational": "info",
}

# Best-effort Burp issue-name -> reporter vtype, so the template supplies the
# right CWE / ATT&CK / impact / remediation columns. Falls back to "misconfig".
_VTYPE_RULES = [
    (r"sql injection", "sqli"),
    (r"cross-site scripting|\bxss\b", "xss"),
    (r"os command injection|command injection", "rce"),
    (r"server-side template injection|\bssti\b", "ssti"),
    (r"file path traversal|directory traversal|local file|\blfi\b", "lfi"),
    (r"server-side request forgery|\bssrf\b", "ssrf"),
    (r"xml external entity|\bxxe\b", "misconfig"),
    (r"cross-origin resource sharing|\bcors\b", "cors"),
    (r"open redirect", "open_redirect"),
    (r"cross-site request forgery|\bcsrf\b", "csrf"),
    (r"deserial", "deserialization"),
    (r"jwt|json web token", "jwt"),
    (r"\bidor\b|insecure direct object", "idor"),
    (r"insecure|misconfigur|disclosure|header|verbose|version", "misconfig"),
]


def _vtype_for(name: str) -> str:
    n = (name or "").lower()
    for pat, vt in _VTYPE_RULES:
        if re.search(pat, n):
            return vt
    return "misconfig"


def _strip_html(s: str) -> str:
    """Burp's description_html / remediation_html are HTML — flatten to plain
    text for the report's verbatim PoC block."""
    if not s:
        return ""
    s = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", s)
    s = re.sub(r"(?i)</\s*(p|li|div|h[1-6])\s*>", "\n", s)
    s = re.sub(r"(?i)<\s*li[^>]*>", "  - ", s)
    s = re.sub(r"<[^>]+>", "", s)
    return unescape(s).strip()


def _redact(text: str, api_key: str) -> str:
    return text.replace(api_key, "***") if api_key else text


# ── REST client ───────────────────────────────────────────────────────────────
class BurpClient:
    """Thin client for the Burp Suite Professional REST API (v0.1)."""

    def __init__(self, api_url: str = None, api_key: str = None):
        self.api_url = (api_url or DEFAULT_API_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("BURP_API_KEY", "")
        # The key sits in the URL path, so `base` is sensitive — never log it raw.
        self.base = f"{self.api_url}/{self.api_key}/v0.1" if self.api_key else f"{self.api_url}/v0.1"

    @property
    def safe_base(self) -> str:
        return _redact(self.base, self.api_key)

    def reachable(self) -> bool:
        """True iff the REST service answers (200) — used to skip gracefully when
        Burp is closed or the REST API is disabled."""
        if requests is None:
            return False
        try:
            r = requests.get(self.base + "/", timeout=5)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def start_scan(self, urls, creds=None, creds_b=None, scope_host=None,
                   scope_lock=False, config_name=None, name=None) -> str:
        """POST /scan. Returns the task id (from the Location header — the 201
        response body is empty). Raises on any non-201."""
        # Desktop Burp Suite Professional quirks (all verified against live Burp Pro):
        #  • the top-level "name" field is Enterprise-only → 400 "Names are not
        #    supported in the desktop product". Omit it. (`name` kept in the
        #    signature for API compatibility but intentionally unused.)
        #  • a NamedConfiguration with an unknown name → 400 "Unknown configuration".
        #    Only send one when explicitly requested; else Burp uses its built-in
        #    default config.
        #  • a scope `rule` is a literal URL PREFIX, NOT a regex — a regex rule 400s
        #    with "Not all seed URLs are in scope" because the seed URL doesn't
        #    literally start with the regex text.
        body = {"urls": list(urls)}
        # Authenticated scan — Burp drives the login with these credentials.
        logins = []
        for label, cred in (("primary", creds), ("secondary", creds_b)):
            if cred and ":" in cred:
                user, pw = cred.split(":", 1)          # split on FIRST colon
                logins.append({"label": label, "username": user, "password": pw})
        if logins:
            body["application_logins"] = logins
        # Scope — URL-PREFIX rules (both schemes). The trailing "/" is REQUIRED for
        # safety: a bare prefix "https://example.com" also matches
        # "https://example.com.evil/" (substring), which would let the scan wander
        # off-target. "https://example.com/" cannot match "example.com.evil". The
        # seed URL is normalized to carry a path (see run_burp_scan) so it still
        # satisfies Burp's in-scope check against this bounded prefix. scope_host
        # includes the port when the target has one.
        if scope_host:
            body["scope"] = {"include": [
                {"rule": f"https://{scope_host}/"},
                {"rule": f"http://{scope_host}/"},
            ]}
        # Named config only when explicitly requested (env or arg) — never a
        # hardcoded default that may not exist on this install.
        cfg = config_name or os.environ.get("BURP_SCAN_CONFIG")
        if cfg:
            body["scan_configurations"] = [{"type": "NamedConfiguration", "name": cfg}]

        r = requests.post(self.base + "/scan", json=body, timeout=30)
        if r.status_code != 201:
            raise RuntimeError(
                f"Burp POST /scan failed: HTTP {r.status_code} {r.text[:200]}")
        loc = r.headers.get("Location", "")
        task_id = loc.rstrip("/").rsplit("/", 1)[-1]
        if not task_id:
            raise RuntimeError("Burp accepted the scan but returned no task id in Location")
        return task_id

    def status(self, task_id: str) -> dict:
        r = requests.get(f"{self.base}/scan/{task_id}", timeout=20)
        r.raise_for_status()
        return r.json()

    def run(self, task_id: str, timeout: int = SCAN_TIMEOUT,
            interval: int = POLL_INTERVAL) -> list:
        """Poll until the scan reaches a terminal state (succeeded/failed) or the
        timeout, then return the deduped issue list (by serial_number)."""
        deadline = time.monotonic() + timeout
        issues = {}                      # serial_number -> issue (last write wins)
        last_progress = -1
        while True:
            data = self.status(task_id)
            st = (data.get("scan_status") or "").lower()
            # issue_events is an APPEND-ONLY stream — the same issue reappears with
            # rising confidence. Keep the latest by serial_number.
            for ev in data.get("issue_events", []):
                issue = ev.get("issue") or {}
                sn = issue.get("serial_number") or issue.get("name", "") + issue.get("path", "")
                issues[sn] = issue
            prog = (data.get("scan_metrics") or {}).get("crawl_and_audit_progress")
            if prog is not None and prog != last_progress:
                log("burp", f"scan {task_id}: {st} — {prog}% ({len(issues)} issues so far)")
                last_progress = prog
            if st in ("succeeded", "failed"):
                if st == "failed":
                    log("warn", f"Burp scan {task_id} reported status=failed "
                                f"(returning {len(issues)} issues collected so far)")
                return list(issues.values())
            if time.monotonic() >= deadline:
                log("warn", f"Burp scan {task_id} hit the {timeout}s budget at "
                            f"status={st} — returning {len(issues)} partial issues")
                return list(issues.values())
            time.sleep(interval)


# ── Normalisation -> reporter findings ────────────────────────────────────────
def normalize_issue(issue: dict) -> dict:
    """Project a Burp issue into the reporter finding shape. The rich Burp prose
    (description/remediation/CWE/confidence/evidence) is packed into the verbatim
    `poc` block, since the reporter renders impact/remediation from the vtype
    template, not per-finding fields."""
    name = issue.get("name", "Burp Suite issue")
    severity = _SEV_MAP.get(str(issue.get("severity", "info")).lower(), "info")
    confidence = issue.get("confidence", "")
    origin = issue.get("origin", "")
    path = issue.get("path", "")
    url = (origin + path) if origin else (path or "N/A")
    vtype = _vtype_for(name)

    desc = _strip_html(issue.get("description_html") or issue.get("description") or "")
    remediation = _strip_html(issue.get("remediation_html") or issue.get("remediation") or "")
    # CWE list (Burp gives vulnerability_classifications_html or a cwe list).
    cwe = ""
    vc = issue.get("vulnerability_classifications_html") or ""
    m = re.findall(r"CWE-\d+", vc + " " + json.dumps(issue.get("references", "")))
    if m:
        cwe = ", ".join(dict.fromkeys(m))

    poc_lines = [
        f"Burp Suite issue: {name}",
        f"Severity: {issue.get('severity', '?')}  |  Confidence: {confidence or '?'}",
        f"Location: {url}",
    ]
    if cwe:
        poc_lines.append(f"Classifications: {cwe}")
    if desc:
        poc_lines += ["", "Issue detail:", desc[:1500]]
    if remediation:
        poc_lines += ["", "Remediation:", remediation[:1000]]
    # First evidence request snippet, if present.
    for ev in (issue.get("evidence") or [])[:1]:
        rr = (ev.get("request_response") or {})
        req = rr.get("request", "")
        if isinstance(req, list):
            req = "".join(seg.get("data", "") for seg in req if isinstance(seg, dict))
        if req:
            poc_lines += ["", "Evidence (request excerpt):", str(req)[:600]]

    return {
        "severity": severity,
        "type": vtype,                       # reporter Method 1f maps -> vtype
        "title": f"{name} ({url})" if url != "N/A" else name,
        "url": url,
        "detail": name,
        "evidence": (desc[:300] if desc else ""),
        "poc": "\n".join(poc_lines),
        "confidence": confidence,
        "source": "burp",
    }


# ── Orchestration entry points ────────────────────────────────────────────────
def burp_reachable(api_url: str = None, api_key: str = None) -> bool:
    """Module-level reachability probe (mirrors ollama_available in the orchestrator)."""
    return BurpClient(api_url, api_key).reachable()


def run_burp_scan(target: str, output_dir: str, api_url: str = None,
                  api_key: str = None, creds: str = None, creds_b: str = None,
                  scope_lock: bool = False, config_name: str = None,
                  timeout: int = SCAN_TIMEOUT) -> list:
    """Full flow: reachability -> start -> poll -> normalize -> write
    ``<output_dir>/findings.json`` (which reporter.py Method 1f ingests) and
    return the list of normalized findings. Returns [] (and skips gracefully)
    when Burp is unreachable, so it never breaks a pipeline."""
    if requests is None:
        log("warn", "Burp scan skipped — the `requests` package is not installed")
        return []

    client = BurpClient(api_url, api_key)
    if not client.api_key:
        log("warn", "Burp scan skipped — BURP_API_KEY is not set "
                    "(Burp -> Settings -> Suite -> REST API)")
        return []
    if not client.reachable():
        log("warn", f"Burp scan skipped — REST API not reachable at {client.safe_base} "
                    "(is Burp running with the REST API service enabled?)")
        return []

    # Seed URL(s) — accept a bare host/domain or a full URL.
    if not re.match(r"^https?://", target):
        target_url = "https://" + target
    else:
        target_url = target
    parsed = urlparse(target_url)
    # netloc keeps the port (drops any creds) so the scope prefix is host:port-exact.
    netloc = parsed.netloc.split("@")[-1]
    host = netloc.split(":")[0]
    # Normalize the seed to carry a path so it satisfies the bounded "https://host/"
    # scope prefix (a bare "https://host" fails Burp's in-scope check against it).
    if not parsed.path:
        target_url = target_url.rstrip("/") + "/"

    log("burp", f"Starting Burp scan of {target_url} "
                f"(config='{config_name or DEFAULT_CONFIG or 'Burp default'}', "
                f"auth={'yes' if creds else 'no'}, scope_lock={scope_lock})")
    try:
        task_id = client.start_scan(
            [target_url], creds=creds, creds_b=creds_b,
            scope_host=netloc, scope_lock=scope_lock, config_name=config_name)
    except Exception as e:
        log("err", f"Burp scan failed to start: {_redact(str(e), client.api_key)}")
        return []

    log("ok", f"Burp scan started — task {task_id}; polling every {POLL_INTERVAL}s "
              f"(budget {timeout}s)")
    try:
        issues = client.run(task_id, timeout=timeout)
    except Exception as e:
        log("err", f"Burp scan polling error: {_redact(str(e), client.api_key)}")
        return []

    findings = [normalize_issue(i) for i in issues]
    # Real findings only in the count headline; informationals are still written.
    real = [f for f in findings if f["severity"] in ("high", "medium", "low")]

    os.makedirs(output_dir, exist_ok=True)
    out = os.path.join(output_dir, "findings.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)
    log("ok", f"Burp scan complete — {len(findings)} issue(s) "
              f"({len(real)} actionable) → {out}")
    return findings


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Burp Suite REST API active scanner")
    p.add_argument("--target", required=True, help="URL or host to scan")
    p.add_argument("--output", required=True,
                   help="findings dir to write findings.json into (e.g. findings/<t>/burp)")
    p.add_argument("--api-url", default=None, help="Burp REST base (default $BURP_API_URL or 127.0.0.1:1337)")
    p.add_argument("--api-key", default=None, help="Burp REST key (default $BURP_API_KEY)")
    p.add_argument("--creds", default=None, help="user:pass for an authenticated scan")
    p.add_argument("--creds-b", default=None, help="second account user:pass (IDOR/priv-esc)")
    p.add_argument("--scope-lock", action="store_true", help="restrict scan to the exact host")
    p.add_argument("--config", default=None, help="Burp named scan configuration")
    p.add_argument("--timeout", type=int, default=SCAN_TIMEOUT, help="overall scan budget (s)")
    return p


def main(argv=None):
    args = _build_arg_parser().parse_args(argv)
    print(f"\n{B}{M}╔══════════════════════════════════════════════════════════╗{N}")
    print(f"{B}{M}║   BURP SUITE — REST API Active Scanner                  ║{N}")
    print(f"{B}{M}╚══════════════════════════════════════════════════════════╝{N}\n")
    findings = run_burp_scan(
        target=args.target, output_dir=args.output,
        api_url=args.api_url, api_key=args.api_key,
        creds=args.creds, creds_b=args.creds_b,
        scope_lock=args.scope_lock, config_name=args.config, timeout=args.timeout)
    return 0 if findings is not None else 1


if __name__ == "__main__":
    sys.exit(main())

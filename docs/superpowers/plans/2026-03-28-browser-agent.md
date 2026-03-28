# Browser Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a real-browser vulnerability validation phase (`browser_agent.py`) to OBSIDIAN using `browser-use` + Playwright + LLM, integrated as `--browser-scan` and auto-included in `--full`.

**Architecture:** `browser_agent.py` is a self-contained module that mirrors `brain.py`'s LLM provider priority (Ollama → mlx → Claude fallback), drives 6 browser-based security tasks against external targets, and writes findings as `.txt` files into the per-session `FINDINGS_DIR/browser/` directory so `reporter.py` picks them up without extra parsing logic.

**Tech Stack:** `browser-use>=0.1.40`, `playwright>=1.44.0`, `langchain-anthropic>=0.1.0`, `langchain-ollama>=0.1.0`, Python 3.11+, async/await

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `browser_agent.py` | **Create** | All browser agent logic — LLM init, 6 task classes, BrowserAgent runner |
| `reporter.py` | **Modify** (line ~21 + ~189) | Add 3 VULN_TEMPLATES entries; add 4 `browser/` entries to SUBDIR_VTYPE |
| `hunt.py` | **Modify** (5 locations) | TOOL_REGISTRY, SKIP_ALIASES, hunt_target() signature + result dict + explicit_phase_selection + full block + phase 9 insertion, both call sites in main(), dashboard |
| `requirements.txt` | **Modify** | Add commented optional browser-use install block |
| `tests/test_browser_agent.py` | **Create** | Unit tests for all new code |

---

## Task 1: Create `browser_agent.py` — LLM init + scaffold

**Files:**
- Create: `browser_agent.py`
- Create: `tests/test_browser_agent.py`

- [ ] **Step 1: Write the failing import test**

Create `tests/test_browser_agent.py`:

```python
import importlib, os, sys

def test_import_graceful_without_deps():
    """Module must import cleanly even if browser-use is not installed."""
    for key in list(sys.modules.keys()):
        if "browser_use" in key:
            del sys.modules[key]
    mod = importlib.import_module("browser_agent")
    assert hasattr(mod, "BrowserAgent")
    assert hasattr(mod, "init_browser_llm")

def test_browser_agent_missing_deps_returns_none():
    """_force_missing=True simulates the missing-dep guard path."""
    import browser_agent
    llm = browser_agent.init_browser_llm(model_override=None, _force_missing=True)
    assert llm is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/venkatasatish/Documents/GitHub/obsidian
python3 -m pytest tests/test_browser_agent.py -v 2>&1 | head -20
```
Expected: `ModuleNotFoundError: No module named 'browser_agent'`

- [ ] **Step 3: Create `browser_agent.py` with LLM init**

```python
#!/usr/bin/env python3
"""
browser_agent.py — Real-browser vulnerability validation phase for OBSIDIAN.

Drives a Chromium browser via browser-use + Playwright + LLM against external
targets to validate JS-rendered vulnerabilities that static scanners miss.

Requires (optional install):
    pip install "browser-use>=0.1.40" playwright langchain-anthropic
    playwright install chromium

LLM priority (mirrors brain.py PROVIDER_PRIORITY):
    ollama → mlx → claude  (mlx/openai/grok without langchain wrapper fall back to ollama)

Usage (standalone):
    python3 browser_agent.py --target example.com --findings-dir /path/to/session/findings
    python3 browser_agent.py --target example.com --findings-dir /path --headed
    python3 browser_agent.py --target example.com --findings-dir /path --model claude-sonnet-4-6
"""
from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path

# ── Optional heavy deps ────────────────────────────────────────────────────────
try:
    from browser_use import Agent as BUAgent, Browser, BrowserConfig
    _browser_use_ok = True
except ImportError:
    _browser_use_ok = False
    BUAgent = None
    Browser = None
    BrowserConfig = None

# ── Colours (same as hunt.py) ──────────────────────────────────────────────────
GREEN  = "\033[0;32m"
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
NC     = "\033[0m"

OLLAMA_HOST       = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
# Same model priority list as brain.py
OLLAMA_MODEL_LIST = [
    "vapt-qwen25:latest",
    "obsidian-custom:latest",
    "vapt-model:latest",
    "deepseek-r1:32b",
    "qwen3:30b-a3b",
    "qwen2.5-coder:32b",
]
TASK_TIMEOUT = int(os.environ.get("BROWSER_TASK_TIMEOUT", "120"))


def _log(level: str, msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    c = colours.get(level, NC)
    print(f"{c}[{ts}] [{level.upper()}]{NC} {msg}")


def init_browser_llm(model_override: str | None = None, _force_missing: bool = False):
    """
    Initialise a LangChain chat model for browser-use.

    Priority mirrors brain.py PROVIDER_PRIORITY: ollama → mlx → claude.
    mlx and other providers that lack a LangChain adapter fall back to ollama,
    then claude. Returns None (with warning) if nothing is available.

    _force_missing: test hook — simulates browser-use not installed.
    """
    if _force_missing or not _browser_use_ok:
        return None

    provider = os.environ.get("BRAIN_PROVIDER", "").lower()

    # Explicit provider override
    if provider == "claude":
        return _try_claude(model_override)
    if provider == "ollama":
        return _try_ollama(model_override)
    # mlx/openai/grok have no LangChain adapter here — fall through to auto-detect
    if provider in ("mlx", "openai", "grok"):
        _log("warn",
             f"BRAIN_PROVIDER={provider} has no LangChain adapter in browser-use — "
             "falling back to Ollama then Claude")

    # Auto-detect: try ollama first (matches brain.py priority), then claude
    # mlx is tried as a proxy: if BRAIN_PROVIDER=mlx we already fell through here;
    # in pure auto-detect we skip mlx (no LangChain adapter) per the spec.
    llm = _try_ollama(model_override)
    if llm:
        return llm
    llm = _try_claude(model_override)
    if llm:
        return llm

    _log("warn", "No LLM available for browser agent — install Ollama or set ANTHROPIC_API_KEY")
    return None


def _try_ollama(model_override: str | None):
    try:
        import ollama as _ollama_lib
        from langchain_ollama import ChatOllama
        client = _ollama_lib.Client(host=OLLAMA_HOST)
        available = {m["model"] for m in client.list().get("models", [])}
        model = model_override
        if not model:
            for m in OLLAMA_MODEL_LIST:
                if m in available:
                    model = m
                    break
            if not model and available:
                model = next(iter(available))
        if not model:
            return None
        _log("info", f"Browser LLM: Ollama ({model})")
        return ChatOllama(model=model, base_url=OLLAMA_HOST)
    except Exception:
        return None


def _try_claude(model_override: str | None):
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return None
    try:
        from langchain_anthropic import ChatAnthropic
        model = model_override or "claude-sonnet-4-6"
        _log("info", f"Browser LLM: Claude ({model})")
        return ChatAnthropic(model=model, api_key=key)
    except ImportError:
        _log("warn", "langchain-anthropic not installed — pip install langchain-anthropic")
        return None
    except Exception:
        return None
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_browser_agent.py -v
```
Expected: both PASS

- [ ] **Step 5: Commit**

```bash
git add browser_agent.py tests/test_browser_agent.py
git commit -m "feat: add browser_agent.py scaffold with LLM init"
```

---

## Task 2: Add 6 `BrowserTask` classes

**Files:**
- Modify: `browser_agent.py` (append)
- Modify: `tests/test_browser_agent.py` (append)

> **Note:** `FormDiscoveryTask` output is a feed-forward artifact (plain `PAGE_URL FORM_ACTION_URL` lines) not loaded by `reporter.py`. It is written to `browser/form_discovery.txt` for use as input to future scanner phases. It is intentionally excluded from `SUBDIR_VTYPE`.
>
> **Note:** Screenshot capture is deferred to a future enhancement. The `screenshots/` directory is created but no PNG writing logic is implemented in this version.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_browser_agent.py`:

```python
def test_all_task_classes_exist():
    import browser_agent
    for cls in [
        "XSSDOMTask", "XSSReflectedBrowserTask", "CSRFTask",
        "AuthBypassTask", "OpenRedirectTask", "FormDiscoveryTask"
    ]:
        assert hasattr(browser_agent, cls), f"Missing: {cls}"

def test_task_has_required_attrs():
    import browser_agent
    task = browser_agent.XSSDOMTask("https://example.com", "/tmp/findings")
    assert hasattr(task, "prompt")
    assert hasattr(task, "vtype")
    assert hasattr(task, "severity")
    assert "example.com" in task.prompt

def test_xss_reflected_task_accepts_candidates():
    import browser_agent
    candidates = ["https://example.com/search?q=test", "https://example.com/q=x"]
    task = browser_agent.XSSReflectedBrowserTask(
        "https://example.com", "/tmp/findings", candidates=candidates
    )
    assert "search?q=test" in task.prompt

def test_form_discovery_output_file_differs():
    import browser_agent
    task = browser_agent.FormDiscoveryTask("https://example.com", "/tmp/findings")
    assert task.output_file().endswith("form_discovery.txt")
    # Must NOT be in a subdir that reporter.py would load
    assert "browser/xss" not in task.output_file()
```

- [ ] **Step 2: Run to verify they fail**

```bash
python3 -m pytest tests/test_browser_agent.py -k "task" -v
```
Expected: FAIL — `AttributeError`

- [ ] **Step 3: Append the 6 task classes to `browser_agent.py`**

```python
class BrowserTask:
    """Base class for a single browser-based security validation task."""
    vtype:    str = "misconfig"
    severity: str = "medium"

    def __init__(self, target_url: str, findings_dir: str):
        self.target_url   = target_url.rstrip("/")
        self.findings_dir = findings_dir
        self.prompt       = self._build_prompt()

    def _build_prompt(self) -> str:
        raise NotImplementedError

    def output_file(self) -> str:
        return os.path.join(self.findings_dir, "browser", f"{self.vtype}.txt")


class XSSDOMTask(BrowserTask):
    vtype    = "xss_dom"
    severity = "high"

    def _build_prompt(self) -> str:
        return (
            f"Navigate to {self.target_url}. "
            "After the page fully loads, inspect the JavaScript source for dangerous DOM sinks: "
            "document.write(), innerHTML, outerHTML, insertAdjacentHTML, eval(), setTimeout() with string args. "
            "For each sink found, determine whether user-controlled input (URL fragment, query parameter, "
            "postMessage, localStorage) reaches it without sanitisation. "
            "If you find a reachable sink, craft a PoC payload and confirm it executes. "
            "Return one finding per vulnerable URL in this EXACT format (no other text): "
            "URL [xss_dom] [high] DESCRIPTION"
        )


class XSSReflectedBrowserTask(BrowserTask):
    vtype    = "xss_dom"
    severity = "high"

    def __init__(self, target_url: str, findings_dir: str, candidates: list[str] | None = None):
        self.candidates = candidates or []
        super().__init__(target_url, findings_dir)

    def _build_prompt(self) -> str:
        candidate_block = "\n".join(self.candidates[:10]) if self.candidates else self.target_url
        return (
            "You are validating reflected XSS candidates in a real browser. "
            "For each URL below, navigate to it, wait for the page to render, then check "
            "whether the injected payload appears and EXECUTES in the live DOM "
            "(alert fires, console error, DOM mutation — not just present in raw HTML). "
            f"URLs to test:\n{candidate_block}\n"
            "Return one confirmed finding per URL in this EXACT format (no other text): "
            "URL [xss_dom] [high] DESCRIPTION"
        )


class CSRFTask(BrowserTask):
    vtype    = "csrf"
    severity = "medium"

    def _build_prompt(self) -> str:
        return (
            f"Navigate to {self.target_url}. "
            "Find all forms that perform state-changing actions (POST, PUT, DELETE). "
            "For each form check: "
            "1) Is a CSRF token present as a hidden field or request header? "
            "2) Is the SameSite cookie attribute set to Strict or Lax on session cookies? "
            "3) Does the form submit succeed if you remove or change the CSRF token value? "
            "Report any form missing CSRF protection in this EXACT format (no other text): "
            "URL [csrf] [medium] DESCRIPTION"
        )


class AuthBypassTask(BrowserTask):
    vtype    = "auth_bypass"
    severity = "high"

    def _build_prompt(self) -> str:
        return (
            f"Navigate to {self.target_url}. "
            "This is an authorised penetration test. "
            "Try to access protected routes without authentication: "
            "/admin, /dashboard, /settings, /api/admin, /manage, /internal. "
            "Also try JS-rendered login forms with default credentials: "
            "admin/admin, admin/password, admin/123456, test/test. "
            "Note any route that loads protected content without requiring login. "
            "Report each bypass in this EXACT format (no other text): "
            "URL [auth_bypass] [high] DESCRIPTION"
        )


class OpenRedirectTask(BrowserTask):
    vtype    = "open_redirect"
    severity = "medium"

    def _build_prompt(self) -> str:
        return (
            f"Navigate to {self.target_url}. "
            "Find all URL parameters that look like redirect targets: "
            "?url=, ?redirect=, ?next=, ?return=, ?goto=, ?dest=, ?target=. "
            "For each one, replace the value with https://evil.example.com and follow the redirect. "
            "If the browser ends up at evil.example.com (JS or HTTP redirect), it is vulnerable. "
            "Report each open redirect in this EXACT format (no other text): "
            "URL [open_redirect] [medium] DESCRIPTION"
        )


class FormDiscoveryTask(BrowserTask):
    """
    Discovers JS-rendered forms invisible to static crawlers.
    Output format: PAGE_URL FORM_ACTION_URL (one per line, no brackets).
    This file is NOT loaded by reporter.py — it is a feed-forward artifact
    for future scanner phases (e.g. passed back into scanner.sh URL lists).
    """
    vtype    = "form_discovery"
    severity = "info"

    def _build_prompt(self) -> str:
        return (
            f"Navigate to {self.target_url}. "
            "Wait for all JavaScript to execute and dynamic content to load. "
            "List every form and input field rendered dynamically by JavaScript "
            "(i.e. NOT present in the initial HTML source). "
            "For each, output exactly: PAGE_URL FORM_ACTION_URL"
        )

    def output_file(self) -> str:
        return os.path.join(self.findings_dir, "browser", "form_discovery.txt")
```

- [ ] **Step 4: Run all tests**

```bash
python3 -m pytest tests/test_browser_agent.py -v
```
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add browser_agent.py tests/test_browser_agent.py
git commit -m "feat: add 6 BrowserTask classes"
```

---

## Task 3: Add `BrowserAgent` runner class + CLI

**Files:**
- Modify: `browser_agent.py` (append)
- Modify: `tests/test_browser_agent.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `tests/test_browser_agent.py`:

```python
def test_browser_agent_init():
    import browser_agent
    agent = browser_agent.BrowserAgent(
        target="https://example.com",
        findings_dir="/tmp/test_findings",
        headed=False,
        model_override=None,
        session_id=None,
    )
    assert agent.target == "https://example.com"
    assert agent.findings_dir == "/tmp/test_findings"

def test_findings_dir_created_on_init(tmp_path):
    import browser_agent, os
    fd = str(tmp_path / "findings")
    browser_agent.BrowserAgent(
        target="https://x.com", findings_dir=fd, session_id=None
    )
    assert os.path.isdir(os.path.join(fd, "browser", "screenshots"))

def test_write_finding_returns_int(tmp_path):
    import browser_agent
    agent = browser_agent.BrowserAgent(
        target="https://example.com",
        findings_dir=str(tmp_path),
        session_id=None,
    )
    task = browser_agent.XSSDOMTask("https://example.com", str(tmp_path))
    result_text = (
        "https://example.com/search?q=x [xss_dom] [high] DOM XSS via innerHTML\n"
        "Some other non-finding line\n"
        "https://example.com/page [xss_dom] [high] Another finding\n"
    )
    count = agent._write_finding(task, result_text)
    assert isinstance(count, int)
    assert count == 2
```

- [ ] **Step 2: Run to verify they fail**

```bash
python3 -m pytest tests/test_browser_agent.py -k "agent_init or findings_dir or write_finding" -v
```
Expected: FAIL

- [ ] **Step 3: Append `BrowserAgent` + CLI to `browser_agent.py`**

```python
class BrowserAgent:
    """
    Orchestrates all BrowserTask instances against a single target.
    findings_dir must be the resolved per-session path (same as run_vuln_scan uses).
    """

    def __init__(
        self,
        target: str,
        findings_dir: str,
        headed: bool = False,
        model_override: str | None = None,
        session_id: str | None = None,
    ):
        self.target         = target.rstrip("/")
        self.findings_dir   = findings_dir
        self.headed         = headed
        self.model_override = model_override
        self.session_id     = session_id
        self.llm            = None

        Path(os.path.join(findings_dir, "browser", "screenshots")).mkdir(
            parents=True, exist_ok=True
        )

    def _init_llm(self) -> bool:
        self.llm = init_browser_llm(model_override=self.model_override)
        return self.llm is not None

    def _load_dalfox_candidates(self) -> list[str]:
        dalfox_file = os.path.join(self.findings_dir, "xss", "dalfox_results.txt")
        if not os.path.isfile(dalfox_file):
            return []
        lines = []
        with open(dalfox_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
        return lines[:20]

    def _write_finding(self, task: BrowserTask, result_text: str) -> int:
        """Write confirmed finding lines to task output file. Returns count written."""
        out_file = task.output_file()
        Path(out_file).parent.mkdir(parents=True, exist_ok=True)
        lines_written = 0
        with open(out_file, "a") as f:
            for line in result_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("http") and f"[{task.vtype}]" in line:
                    f.write(line + "\n")
                    lines_written += 1
        return lines_written

    async def _run_task(self, task: BrowserTask) -> int:
        if not _browser_use_ok:
            _log("warn", "browser-use not installed — skipping browser task")
            return 0
        _log("info", f"Browser task: {task.__class__.__name__} → {self.target}")
        cfg     = BrowserConfig(headless=not self.headed)
        browser = Browser(config=cfg)
        try:
            agent  = BUAgent(task=task.prompt, llm=self.llm, browser=browser)
            result = await asyncio.wait_for(agent.run(), timeout=TASK_TIMEOUT)
            count  = self._write_finding(task, str(result))
            if count:
                _log("ok", f"  {count} finding(s) — {task.__class__.__name__}")
            return count
        except asyncio.TimeoutError:
            _log("warn", f"  {task.__class__.__name__} timed out after {TASK_TIMEOUT}s")
            return 0
        except Exception as exc:
            _log("err", f"  {task.__class__.__name__} failed: {exc}")
            return 0
        finally:
            try:
                await browser.close()
            except Exception:
                pass

    def run(self) -> dict[str, int]:
        """Run all tasks. Returns {task_name: finding_count}. Safe if browser-use absent."""
        if not _browser_use_ok:
            _log("warn",
                 f"{YELLOW}[!] browser-use not installed. "
                 f"Run: pip install 'browser-use>=0.1.40' playwright langchain-anthropic "
                 f"&& playwright install chromium{NC}")
            return {}

        if not self._init_llm():
            _log("warn", "No LLM available — skipping browser phase")
            return {}

        dalfox_candidates = self._load_dalfox_candidates()
        target_url = (
            self.target if self.target.startswith("http")
            else f"https://{self.target}"
        )

        tasks = [
            XSSDOMTask(target_url, self.findings_dir),
            XSSReflectedBrowserTask(target_url, self.findings_dir, candidates=dalfox_candidates),
            CSRFTask(target_url, self.findings_dir),
            AuthBypassTask(target_url, self.findings_dir),
            OpenRedirectTask(target_url, self.findings_dir),
            FormDiscoveryTask(target_url, self.findings_dir),
        ]

        results: dict[str, int] = {}
        for task in tasks:
            name = task.__class__.__name__
            try:
                results[name] = asyncio.run(self._run_task(task))
            except Exception as exc:
                _log("err", f"Task {name} crashed: {exc}")
                results[name] = 0

        total = sum(results.values())
        _log("ok" if total else "info",
             f"Browser phase complete — {total} finding(s) across {len(tasks)} tasks")
        return results


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="OBSIDIAN Browser Agent — real-browser vuln validation"
    )
    ap.add_argument("--target",       required=True, help="Target URL or domain")
    ap.add_argument("--findings-dir", required=True, help="Per-session findings directory")
    ap.add_argument("--headed",       action="store_true", help="Show browser window")
    ap.add_argument("--model",        default=None, help="Override LLM model")
    args = ap.parse_args()

    agent = BrowserAgent(
        target=args.target,
        findings_dir=args.findings_dir,
        headed=args.headed,
        model_override=args.model,
    )
    results = agent.run()
    sys.exit(0 if results else 1)
```

- [ ] **Step 4: Run all tests**

```bash
python3 -m pytest tests/test_browser_agent.py -v
```
Expected: all PASS

- [ ] **Step 5: Smoke test the CLI**

```bash
python3 browser_agent.py --target example.com --findings-dir /tmp/test_findings 2>&1
echo "Exit: $?"
```
Expected: yellow `browser-use not installed` warning, exit 1.

- [ ] **Step 6: Commit**

```bash
git add browser_agent.py tests/test_browser_agent.py
git commit -m "feat: add BrowserAgent runner and CLI entrypoint"
```

---

## Task 4: Patch `reporter.py` — new VULN_TEMPLATES + SUBDIR_VTYPE

**Files:**
- Modify: `reporter.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_browser_agent.py`:

```python
def test_reporter_has_browser_subdirs():
    import reporter
    assert "browser/xss_dom"       in reporter.SUBDIR_VTYPE
    assert "browser/csrf"          in reporter.SUBDIR_VTYPE
    assert "browser/auth_bypass"   in reporter.SUBDIR_VTYPE
    assert "browser/open_redirect" in reporter.SUBDIR_VTYPE

def test_reporter_has_browser_vuln_templates():
    import reporter
    assert "xss_dom"      in reporter.VULN_TEMPLATES
    assert "csrf"         in reporter.VULN_TEMPLATES
    assert "auth_bypass"  in reporter.VULN_TEMPLATES
    assert "open_redirect" in reporter.VULN_TEMPLATES
```

- [ ] **Step 2: Run to verify they fail**

```bash
python3 -m pytest tests/test_browser_agent.py -k "reporter" -v
```
Expected: FAIL

- [ ] **Step 3: Add 3 new entries to `VULN_TEMPLATES` in `reporter.py`**

In `reporter.py`, the `VULN_TEMPLATES` dict starts at line ~21. After the last entry (before the closing `}`), add:

```python
    "xss_dom": {
        "title": "DOM-Based Cross-Site Scripting (XSS) on {host}",
        "severity": "high", "cvss": "7.5", "cwe": "CWE-79",
        "impact": (
            "An attacker can execute arbitrary JavaScript in the victim's browser by "
            "manipulating client-side DOM sinks (innerHTML, document.write, eval). "
            "Unlike reflected XSS, no server round-trip is required."
        ),
        "remediation": (
            "Avoid writing user-controlled data to dangerous DOM sinks. "
            "Use textContent instead of innerHTML. "
            "Implement a strict Content-Security-Policy header. "
            "Use DOMPurify for unavoidable HTML rendering."
        ),
        "references": [
            ("OWASP DOM XSS", "https://owasp.org/www-community/attacks/DOM_Based_XSS"),
        ],
    },
    "csrf": {
        "title": "Cross-Site Request Forgery (CSRF) on {host}",
        "severity": "medium", "cvss": "6.5", "cwe": "CWE-352",
        "impact": (
            "An attacker can trick an authenticated user into performing unintended state-changing "
            "actions (fund transfers, password changes, account modifications) without their knowledge."
        ),
        "remediation": (
            "Implement CSRF tokens on all state-changing forms. "
            "Set SameSite=Strict or SameSite=Lax on session cookies. "
            "Validate the Origin/Referer header server-side."
        ),
        "references": [
            ("OWASP CSRF", "https://owasp.org/www-community/attacks/csrf"),
        ],
    },
    "auth_bypass": {
        "title": "Authentication Bypass on {host}",
        "severity": "high", "cvss": "8.1", "cwe": "CWE-287",
        "impact": (
            "An attacker can access protected resources or administrative interfaces without "
            "valid credentials, potentially leading to full account takeover or data exfiltration."
        ),
        "remediation": (
            "Enforce authentication checks server-side on every protected route. "
            "Remove default credentials. "
            "Implement proper session management and route guards on SPA frameworks."
        ),
        "references": [
            ("OWASP Auth Bypass", "https://owasp.org/www-community/attacks/Forced_browsing"),
        ],
    },
    "open_redirect": {
        "title": "Open Redirect on {host}",
        "severity": "medium", "cvss": "6.1", "cwe": "CWE-601",
        "impact": (
            "An attacker can redirect victims to a malicious site by crafting a link that "
            "appears to be from the legitimate domain, enabling phishing attacks."
        ),
        "remediation": (
            "Validate redirect URLs against an allowlist of permitted destinations. "
            "Avoid using user-controlled input directly in redirect parameters."
        ),
        "references": [
            ("OWASP Open Redirect", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
        ],
    },
```

- [ ] **Step 4: Add 4 entries to `SUBDIR_VTYPE` in `reporter.py`**

`SUBDIR_VTYPE` is at line ~189. Current last line of the dict:
```python
    "cves": "cves", "cloud": "misconfig", "metasploit": "rce",
```

Add after that line (before the closing `}`):

```python
    # Browser agent phase (real-browser validation)
    "browser/xss_dom":       "xss_dom",
    "browser/csrf":          "csrf",
    "browser/auth_bypass":   "auth_bypass",
    "browser/open_redirect": "open_redirect",
```

- [ ] **Step 5: Run all tests**

```bash
python3 -m pytest tests/test_browser_agent.py -v
```
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add reporter.py tests/test_browser_agent.py
git commit -m "feat: add browser phase VULN_TEMPLATES and SUBDIR_VTYPE entries to reporter.py"
```

---

## Task 5: Patch `hunt.py` — TOOL_REGISTRY + SKIP_ALIASES + requirements

**Files:**
- Modify: `hunt.py`
- Modify: `requirements.txt`

- [ ] **Step 1: Add entry to `TOOL_REGISTRY` in `hunt.py`**

`TOOL_REGISTRY` ends at line ~195 (just before `TOOL_LIST = ...`). Append:

```python
    # browser-use uses "playwright" as the binary proxy check.
    # auto_repair_tools() uses shell=True so the && compound command works.
    ("browser-use", "playwright",
     'pip install "browser-use>=0.1.40" playwright langchain-anthropic '
     '&& playwright install chromium'),
```

- [ ] **Step 2: Add entry to `SKIP_ALIASES` in `hunt.py`**

`SKIP_ALIASES` is at line ~203. Add:

```python
    "browser": "browser_scan",
```

- [ ] **Step 3: Add commented deps to `requirements.txt`**

Append to `requirements.txt`:

```
# Browser agent phase (--browser-scan)
# pip install "browser-use>=0.1.40" "playwright>=1.44.0" "langchain-anthropic>=0.1.0"
# playwright install chromium
```

- [ ] **Step 4: Verify `hunt.py` parses cleanly**

```bash
python3 hunt.py --help 2>&1 | head -5
```
Expected: help text, no syntax errors.

- [ ] **Step 5: Commit**

```bash
git add hunt.py requirements.txt
git commit -m "feat: add browser-use to TOOL_REGISTRY, SKIP_ALIASES, requirements.txt"
```

---

## Task 6: Patch `hunt.py` — `hunt_target()` signature + pipeline + call sites

**Files:**
- Modify: `hunt.py` (5 specific locations)

This task modifies `hunt_target()` and its two call sites in `main()`.

- [ ] **Step 1: Add 3 params to `hunt_target()` signature (line ~5200)**

Current last params before the closing `)`:
```python
    skip_scan: bool = False,
    scope_lock: bool = False,
    max_urls: int = 100,
) -> dict:
```

Change to:
```python
    skip_scan: bool = False,
    scope_lock: bool = False,
    max_urls: int = 100,
    browser_scan: bool = False,
    browser_headed: bool = False,
    browser_model: str | None = None,
) -> dict:
```

- [ ] **Step 2: Add `browser_scan` to `result` dict (line ~5210)**

The `result` dict initialisation — after `"jwt_audit": False,` add:
```python
        "browser_scan":      False,
```

- [ ] **Step 3: Add `browser_scan` to `explicit_phase_selection` tuple (line ~5232)**

Change:
```python
    explicit_phase_selection = any((
        js_scan, param_discover, api_fuzz, secret_hunt, cors_check,
        cms_exploit, rce_scan, sqlmap_scan, jwt_audit, cve_hunt, zero_day,
        post_param_discover,
    ))
```

To:
```python
    explicit_phase_selection = any((
        js_scan, param_discover, api_fuzz, secret_hunt, cors_check,
        cms_exploit, rce_scan, sqlmap_scan, jwt_audit, cve_hunt, zero_day,
        post_param_discover, browser_scan,
    ))
```

- [ ] **Step 4: Add `browser_scan = True` to the `if full:` block (line ~5241)**

Change:
```python
    if full:
        js_scan = param_discover = api_fuzz = secret_hunt = cors_check = True
        cve_hunt = cms_exploit = rce_scan = sqlmap_scan = jwt_audit = True
        post_param_discover = True
```

To:
```python
    if full:
        js_scan = param_discover = api_fuzz = secret_hunt = cors_check = True
        cve_hunt = cms_exploit = rce_scan = sqlmap_scan = jwt_audit = True
        post_param_discover = browser_scan = True
```

- [ ] **Step 5: Add `run_browser_scan()` function**

Before the `hunt_target()` function definition (line ~5179), add:

```python
def run_browser_scan(
    domain: str,
    findings_dir: str,
    headed: bool = False,
    model_override: str | None = None,
    session_id: str | None = None,
) -> bool:
    """Run the browser-use real-browser vulnerability phase."""
    try:
        from browser_agent import BrowserAgent
    except ImportError:
        log("warn", "browser_agent.py not found — skipping browser phase")
        return False
    log("info", f"Browser scan: {domain} (headless={not headed})")
    try:
        agent = BrowserAgent(
            target=domain,
            findings_dir=findings_dir,
            headed=headed,
            model_override=model_override,
            session_id=session_id,
        )
        results = agent.run()
        total = sum(results.values()) if results else 0
        log("ok" if total else "info", f"Browser scan complete: {total} finding(s)")
        return bool(results)
    except Exception as exc:
        log("err", f"Browser scan failed: {exc}")
        return False
```

- [ ] **Step 6: Insert phase 9 (before brain post-scan hook)**

In `hunt_target()`, the brain post-scan hook is at line ~5371:
```python
    findings_dir = result.get("findings_dir") or _resolve_findings_dir(...)
    ...
    if _brain and _brain.enabled and os.path.isdir(findings_dir) and not selected_only_mode:
        ...
        _brain.post_scan_hook(findings_dir, recon_dir)
```

Insert the browser scan **before** this block (so brain sees browser findings):

```python
    # ── Phase 9: Browser Scan (real-browser vuln validation) ──────────────
    # Resolve findings_dir here so run_browser_scan gets the per-session path.
    _findings_dir_early = (
        result.get("findings_dir") or
        _resolve_findings_dir(domain, session_id=result.get("session_id"), create=True)
    )
    if browser_scan and not skip_has(skip_items, "browser_scan", "browser"):
        result["browser_scan"] = run_browser_scan(
            domain,
            findings_dir=_findings_dir_early,
            headed=browser_headed,
            model_override=browser_model,
            session_id=result.get("session_id"),
        )
```

- [ ] **Step 7: Forward new args at call site 1 (single-target `hunt_target()` call, line ~5865)**

After `full=args.full,` add:
```python
                browser_scan=args.browser_scan,
                browser_headed=args.browser_headed,
                browser_model=args.browser_model,
```

- [ ] **Step 8: Forward new args at call site 2 (batch pipeline call, line ~5913)**

The batch call currently only passes `quick`, `resume`, etc. After `full=args.full,` add:
```python
            browser_scan=args.browser_scan if hasattr(args, "browser_scan") else False,
            browser_headed=args.browser_headed if hasattr(args, "browser_headed") else False,
            browser_model=args.browser_model if hasattr(args, "browser_model") else None,
```

- [ ] **Step 9: Verify no syntax errors**

```bash
python3 hunt.py --help 2>&1 | head -5
```
Expected: help text with no errors.

- [ ] **Step 10: Commit**

```bash
git add hunt.py
git commit -m "feat: add browser_scan phase to hunt_target() pipeline and call sites"
```

---

## Task 7: Patch `hunt.py` — CLI flags + dashboard

**Files:**
- Modify: `hunt.py` (2 locations)

- [ ] **Step 1: Add CLI flags after `--jwt-audit` (~line 5597)**

```python
    parser.add_argument("--browser-scan",   action="store_true",
                        help="Real-browser vuln validation: DOM XSS, CSRF, auth bypass, open redirect (browser-use + Playwright)")
    parser.add_argument("--browser-headed", action="store_true",
                        help="Show browser window during --browser-scan (default: headless)")
    parser.add_argument("--browser-model",  type=str, default=None, metavar="MODEL",
                        help="Override LLM model for browser agent (default: auto-detect Ollama/Claude)")
```

- [ ] **Step 2: Add browser_scan to `print_dashboard()` (~line 5420)**

After `if r.get("jwt_audit"): phases.append(...)`, add:

```python
        if r.get("browser_scan"): phases.append(f"{CYAN}Browser✓{NC}")
```

- [ ] **Step 3: Smoke test new flags**

```bash
python3 hunt.py --help 2>&1 | grep -A1 "browser"
```
Expected: `--browser-scan`, `--browser-headed`, `--browser-model` listed.

```bash
python3 hunt.py --target testphp.vulnweb.com --browser-scan --no-brain 2>&1 | head -15
```
Expected: yellow `browser-use not installed` warning, pipeline continues cleanly.

```bash
python3 hunt.py --target testphp.vulnweb.com --full --skip browser --no-brain 2>&1 | grep -i browser
```
Expected: `Skipping` or no browser output — phase correctly skipped.

- [ ] **Step 4: Run all tests**

```bash
python3 -m pytest tests/test_browser_agent.py -v
```
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add hunt.py
git commit -m "feat: add --browser-scan CLI flags and Browser✓ dashboard entry"
```

---

## Task 8: Install deps + end-to-end smoke test

- [ ] **Step 1: Install browser-use and playwright**

```bash
pip install "browser-use>=0.1.40" playwright langchain-anthropic
playwright install chromium
```

- [ ] **Step 2: Verify imports**

```bash
python3 -c "from playwright.sync_api import sync_playwright; print('Playwright OK')"
python3 -c "from browser_use import Agent, Browser; print('browser-use OK')"
```
Expected: both print OK.

- [ ] **Step 3: Re-run tests with deps installed**

```bash
python3 -m pytest tests/test_browser_agent.py -v
```
Expected: all PASS

- [ ] **Step 4: End-to-end test against safe target**

```bash
python3 browser_agent.py \
  --target https://testphp.vulnweb.com \
  --findings-dir /tmp/browser_e2e \
  --headed
```
Expected: browser opens, 6 tasks run, findings written.

```bash
ls /tmp/browser_e2e/browser/
cat /tmp/browser_e2e/browser/xss_dom.txt 2>/dev/null || echo "(no DOM XSS found)"
cat /tmp/browser_e2e/browser/auth_bypass.txt 2>/dev/null || echo "(no auth bypass found)"
```

- [ ] **Step 5: Test hunt.py integration**

```bash
python3 hunt.py --target testphp.vulnweb.com --browser-scan --no-brain 2>&1 | tail -20
```
Expected: Browser phase runs, `Browser✓` appears in dashboard.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "feat: browser agent phase complete — browser-use + Playwright integration"
```

---

## Verification Checklist

- [ ] `python3 -m pytest tests/test_browser_agent.py -v` — all green
- [ ] `python3 hunt.py --help` shows `--browser-scan`, `--browser-headed`, `--browser-model`
- [ ] `python3 hunt.py --target x.com --browser-scan --no-brain` runs without crashing
- [ ] `python3 hunt.py --target x.com --full --skip browser --no-brain` skips browser phase
- [ ] `reporter.py` includes `browser/xss_dom`, `browser/csrf`, `browser/auth_bypass`, `browser/open_redirect` in `SUBDIR_VTYPE`
- [ ] `reporter.py` includes `xss_dom`, `csrf`, `auth_bypass`, `open_redirect` in `VULN_TEMPLATES`
- [ ] Browser findings in `browser/xss_dom.txt` appear in generated HTML report
- [ ] `python3 browser_agent.py --target testphp.vulnweb.com --findings-dir /tmp/x` writes at least one findings file

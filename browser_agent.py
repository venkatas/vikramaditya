#!/usr/bin/env python3
"""
browser_agent.py — Real-browser vulnerability validation phase for Vikramaditya.

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

import asyncio  # pre-declared for async task execution in BrowserAgent (Tasks 2-3)
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from request_guard import SafeMethodPolicy

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
MODEL_PRIORITY = [
    "qwen3-coder-64k:latest",    # PRIMARY — 30.5B, 64K context
    "vapt-qwen25:latest",        # custom 32B VAPT-tuned
    "vikramaditya-custom:latest", # custom 32B vikramaditya
    "vapt-model:latest",         # custom 30B VAPT
    "qwen3-coder:30b",           # coder 30B
    "deepseek-r1:32b",           # strong reasoning
    "qwen3:30b-a3b",             # MoE 30B
    "qwen2.5-coder:32b",         # coder 32B
    "qwen2.5:32b",               # general 32B
    "deepseek-r1:14b",           # reasoning 14B
    "qwen3:14b",                 # 14B fallback
    "baron-llm:latest",          # BaronLLM 8B — offensive security fine-tune (fast)
    "qwen3:8b",                  # 8B fallback
    "mistral:7b-instruct-v0.3-q8_0",  # 7B last resort
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
            for m in MODEL_PRIORITY:
                if m in available:
                    model = m
                    break
            if not model and available:
                model = next(iter(available))
        if not model:
            return None
        _log("info", f"Browser LLM: Ollama ({model})")
        return ChatOllama(model=model, base_url=OLLAMA_HOST)
    except Exception as exc:
        _log("warn", f"Ollama unavailable: {exc}")
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
    except Exception as exc:
        _log("warn", f"Claude LLM unavailable: {exc}")
        return None


class BrowserAgent:
    """
    Orchestrates browser-based validation tasks against a single target.

    The findings directory should be the resolved per-session path so browser
    artifacts land alongside the rest of the pipeline outputs.
    """

    def __init__(
        self,
        target: str,
        findings_dir: str | Path,
        headed: bool = False,
        model_override: str | None = None,
        session_id: str | None = None,
        allow_unsafe: bool = False,
    ) -> None:
        self.target = target.rstrip("/")
        self.findings_dir = Path(findings_dir)
        self.headed = headed
        self.model_override = model_override
        self.session_id = session_id
        env_allow_unsafe = os.environ.get("ALLOW_UNSAFE_BROWSER_TASKS", "").lower()
        self.allow_unsafe = allow_unsafe or env_allow_unsafe in {"1", "true", "yes", "on"}
        self.method_policy = SafeMethodPolicy()
        self.llm = None
        (self.findings_dir / "browser" / "screenshots").mkdir(parents=True, exist_ok=True)

    def _init_llm(self) -> bool:
        self.llm = init_browser_llm(model_override=self.model_override)
        return self.llm is not None

    def is_ready(self) -> bool:
        """Return True only when browser-use is installed and an LLM is available."""
        if not _browser_use_ok:
            return False
        if self.llm is None:
            return self._init_llm()
        return True

    def _load_dalfox_candidates(self) -> list[str]:
        dalfox_file = self.findings_dir / "xss" / "dalfox_results.txt"
        if not dalfox_file.is_file():
            return []

        lines: list[str] = []
        try:
            with open(dalfox_file, errors="ignore") as fh:
                for raw in fh:
                    line = raw.strip()
                    if line and not line.startswith("#"):
                        lines.append(line)
        except OSError:
            return []
        return lines[:20]

    def _write_finding(self, task: "BrowserTask", result_text: str) -> int:
        """Write confirmed finding lines to the task output file."""
        out_file = Path(task.output_file())
        out_file.parent.mkdir(parents=True, exist_ok=True)

        lines_written = 0
        with open(out_file, "a", encoding="utf-8") as fh:
            for raw in result_text.splitlines():
                line = raw.strip()
                if not line:
                    continue
                if line.startswith("http") and f"[{task.vtype}]" in line:
                    fh.write(line + "\n")
                    lines_written += 1
        return lines_written

    def _task_allowed(self, task: "BrowserTask") -> bool:
        decision = self.method_policy.check(task.required_method, self.target)
        if decision["decision"] == "allow":
            return True
        if self.allow_unsafe:
            _log(
                "warn",
                f"{task.__class__.__name__} uses {task.required_method}; proceeding because unsafe browser tasks are enabled",
            )
            return True
        _log(
            "warn",
            f"Skipping {task.__class__.__name__}: {decision['reason']}. "
            "Re-run with --browser-unsafe or ALLOW_UNSAFE_BROWSER_TASKS=1 to opt in.",
        )
        return False

    def _browser_use_kwargs(self, task: "BrowserTask | None" = None) -> dict[str, object]:
        """Tune browser-use settings for the active LLM backend."""
        kwargs: dict[str, object] = {}

        if task is not None and task.target_url.startswith(("http://", "https://")):
            kwargs["initial_actions"] = [{"go_to_url": {"url": task.target_url}}]

        configured = os.environ.get("BROWSER_TOOL_CALLING_METHOD", "").strip().lower()
        if configured in {"function_calling", "json_mode", "raw"}:
            kwargs["tool_calling_method"] = configured
            return kwargs

        if self.llm is not None and self.llm.__class__.__name__ == "ChatOllama":
            # Ollama models often fail browser-use's default structured-output path
            # with "does not support tools". Raw mode keeps the run usable.
            kwargs["tool_calling_method"] = "raw"

        return kwargs

    async def _run_task(self, task: "BrowserTask") -> int:
        if not _browser_use_ok:
            _log("warn", "browser-use not installed — skipping browser task")
            return 0
        if self.llm is None and not self._init_llm():
            _log("warn", "No LLM available — skipping browser task")
            return 0

        _log("info", f"Browser task: {task.__class__.__name__} -> {self.target}")
        cfg = BrowserConfig(headless=not self.headed)
        browser = Browser(config=cfg)
        try:
            agent = BUAgent(
                task=task.prompt,
                llm=self.llm,
                browser=browser,
                **self._browser_use_kwargs(task),
            )
            result = await asyncio.wait_for(agent.run(), timeout=TASK_TIMEOUT)
            count = self._write_finding(task, str(result))
            if count:
                _log("ok", f"{task.__class__.__name__}: {count} finding(s)")
            return count
        except asyncio.TimeoutError:
            _log("warn", f"{task.__class__.__name__} timed out after {TASK_TIMEOUT}s")
            return 0
        except Exception as exc:
            _log("err", f"{task.__class__.__name__} failed: {exc}")
            return 0
        finally:
            try:
                maybe_close = browser.close()
                if asyncio.iscoroutine(maybe_close):
                    await maybe_close
            except Exception:
                pass

    async def _run_all_tasks(self, tasks: list["BrowserTask"]) -> dict[str, int]:
        """Run all tasks inside a single event loop to avoid loop teardown issues."""
        results: dict[str, int] = {}
        for task in tasks:
            name = task.__class__.__name__
            if not self._task_allowed(task):
                results[name] = 0
                continue
            try:
                results[name] = await self._run_task(task)
            except Exception as exc:
                _log("err", f"Task {name} crashed: {exc}")
                results[name] = 0
        return results

    def run(self) -> dict[str, int]:
        """Run all configured browser tasks and return finding counts per task."""
        if not _browser_use_ok:
            _log(
                "warn",
                "browser-use not installed. Run: "
                "pip install 'browser-use>=0.1.40' playwright langchain-anthropic "
                "&& playwright install chromium",
            )
            return {}

        if not self._init_llm():
            _log("warn", "No LLM available for browser phase — skipping")
            return {}

        target_url = self.target if self.target.startswith("http") else f"https://{self.target}"
        dalfox_candidates = self._load_dalfox_candidates()

        tasks: list[BrowserTask] = [
            XSSDOMTask(target_url, str(self.findings_dir)),
            CSRFTask(target_url, str(self.findings_dir)),
            AuthBypassTask(target_url, str(self.findings_dir)),
            OpenRedirectTask(target_url, str(self.findings_dir)),
            FormDiscoveryTask(target_url, str(self.findings_dir)),
        ]
        if dalfox_candidates:
            tasks.insert(
                1,
                XSSReflectedBrowserTask(
                    target_url,
                    str(self.findings_dir),
                    candidates=dalfox_candidates,
                ),
            )

        results = asyncio.run(self._run_all_tasks(tasks))
        total = sum(results.values())
        _log("ok" if total else "info", f"Browser phase complete — {total} finding(s)")
        return results


class BrowserTask:
    """Base class for a single browser-based security validation task."""
    vtype:    str = "misconfig"
    severity: str = "medium"
    required_method: str = "GET"

    def __init__(self, target_url: str, findings_dir: str):
        self.target_url   = target_url.rstrip("/")
        self.findings_dir = findings_dir
        self.prompt       = self._build_prompt()

    def _scope_prefix(self) -> str:
        parts = urlsplit(self.target_url)
        origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else self.target_url
        return (
            f"Stay within the authorised target origin {origin}. "
            f"Begin at {self.target_url}. "
            "Do not substitute placeholder domains such as example.com or iana.org. "
            "Only leave the target origin when the specific test explicitly requires following a redirect destination. "
        )

    def _scoped(self, instructions: str) -> str:
        return self._scope_prefix() + instructions

    def _build_prompt(self) -> str:
        raise NotImplementedError

    def output_file(self) -> str:
        return os.path.join(self.findings_dir, "browser", self.vtype, f"{self.vtype}.txt")


class XSSDOMTask(BrowserTask):
    vtype    = "xss_dom"
    severity = "high"

    def _build_prompt(self) -> str:
        return self._scoped(
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
        return self._scoped(
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
    required_method = "POST"

    def _build_prompt(self) -> str:
        return self._scoped(
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
    required_method = "POST"

    def _build_prompt(self) -> str:
        return self._scoped(
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
        return self._scoped(
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
        return self._scoped(
            f"Navigate to {self.target_url}. "
            "Wait for all JavaScript to execute and dynamic content to load. "
            "List every form and input field rendered dynamically by JavaScript "
            "(i.e. NOT present in the initial HTML source). "
            "For each, output exactly: PAGE_URL FORM_ACTION_URL"
        )

    def output_file(self) -> str:
        return os.path.join(self.findings_dir, "browser", "form_discovery.txt")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Vikramaditya browser agent — real-browser vuln validation")
    parser.add_argument("--target", required=True, help="Target URL or domain")
    parser.add_argument("--findings-dir", required=True, help="Per-session findings directory")
    parser.add_argument("--headed", action="store_true", help="Show browser window")
    parser.add_argument("--model", default=None, help="LLM model override")
    parser.add_argument("--allow-unsafe", action="store_true",
                        help="Allow browser tasks that may submit forms or use credentials")
    args = parser.parse_args()

    agent = BrowserAgent(
        target=args.target,
        findings_dir=args.findings_dir,
        headed=args.headed,
        model_override=args.model,
        allow_unsafe=args.allow_unsafe,
    )
    results = agent.run()
    sys.exit(0 if results else 1)

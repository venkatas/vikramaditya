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

import asyncio  # pre-declared for async task execution in BrowserAgent (Tasks 2-3)
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
MODEL_PRIORITY = [
    "qwen3-coder-64k:latest",    # PRIMARY — 30.5B, 64K context
    "vapt-qwen25:latest",        # custom 32B VAPT-tuned
    "obsidian-custom:latest",    # custom 32B obsidian
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
    Placeholder class for the autonomous browser-based vulnerability validator.

    Full implementation (task execution, finding extraction, report integration)
    is added in subsequent tasks. This scaffold satisfies the import contract
    required by tests/test_browser_agent.py.
    """

    def __init__(
        self,
        target: str,
        findings_dir: str | Path,
        headed: bool = False,
        model_override: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self.target = target
        self.findings_dir = Path(findings_dir)
        self.headed = headed
        self.session_id = session_id
        self.llm = init_browser_llm(model_override=model_override)

    def is_ready(self) -> bool:
        """Return True only when browser-use is installed and an LLM is available."""
        return _browser_use_ok and self.llm is not None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="OBSIDIAN browser agent — real-browser vuln validation"
    )
    parser.add_argument("--target", required=True, help="Target FQDN or IP")
    parser.add_argument("--findings-dir", required=True, help="Session findings directory")
    parser.add_argument("--headed", action="store_true", help="Show browser window")
    parser.add_argument("--model", default=None, help="LLM model override")
    args = parser.parse_args()

    agent = BrowserAgent(
        target=args.target,
        findings_dir=args.findings_dir,
        headed=args.headed,
        model_override=args.model,
    )
    if not agent.is_ready():
        _log("warn", "browser_agent not ready — install: pip install 'browser-use>=0.1.40' playwright langchain-anthropic")
        sys.exit(1)
    _log("info", f"BrowserAgent initialised for {args.target}")

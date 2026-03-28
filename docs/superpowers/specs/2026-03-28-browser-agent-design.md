# Browser Agent Design

**Date:** 2026-03-28
**Status:** Approved

## Overview

Add a real-browser vulnerability validation phase to OBSIDIAN using `browser-use` (Python + Playwright + LLM). The agent drives a Chromium browser against external targets, testing attack surfaces that require a live browser to validate — reflected/DOM XSS, CSRF, auth bypass, open redirects, and JS-rendered form discovery.

## Architecture

### New file: `browser_agent.py`

Self-contained module (~300 lines). Provides:
- LLM auto-detection (Claude API if `ANTHROPIC_API_KEY` set, else Ollama)
- 6 pre-defined `BrowserTask` classes
- Findings written to OBSIDIAN session structure
- Screenshot evidence capture

### LLM bootstrap

```
ANTHROPIC_API_KEY set?  →  ChatAnthropic (claude-sonnet-4-6)
else                    →  ChatOllama    (model from brain.py config, default llama3)
```

Mirrors the existing `brain.py` pattern for consistency.

### Task system

| Task | What it tests | Severity |
|------|--------------|----------|
| `XSSReflectedTask` | Injects payloads into every input/param, checks DOM for unsanitized reflection | High |
| `XSSDOMTask` | `document.write`, `innerHTML`, `eval` sinks via JS execution | High |
| `CSRFTask` | State-changing forms — token presence, SameSite cookie flags | Medium |
| `AuthBypassTask` | `/admin`, `/dashboard`, default creds, forced browsing | High/Critical |
| `OpenRedirectTask` | `?url=`, `?redirect=`, `?next=` params with external host payloads | Medium |
| `FormDiscoveryTask` | JS-rendered forms/params invisible to static crawlers | Info |

Each task:
- Receives a `target_url`
- Has a natural-language prompt template fed to the browser-use agent
- Outputs structured findings
- Saves screenshot evidence on confirmation

## Data Flow

```
hunt.py --browser-scan
    └── browser_agent.py
            ├── init_llm()          # auto-detect Claude or Ollama
            ├── BrowserTask x6      # run each task in sequence
            │     ├── browser-use Agent (Playwright + LLM)
            │     ├── parse findings
            │     └── save screenshot → FINDINGS_DIR/browser/screenshots/
            └── write findings JSON → FINDINGS_DIR/browser/{xss,csrf,...}.json
                write form list     → FINDINGS_DIR/browser/form_discovery.txt
```

## Findings Schema

Each JSON finding matches the schema used by `reporter.py`:

```json
{
  "title": "Reflected XSS",
  "severity": "high",
  "url": "https://target.com/search?q=...",
  "evidence": "Payload <img src=x onerror=alert(1)> reflected unescaped",
  "screenshot": "browser/screenshots/xss_abc123.png"
}
```

## Session Structure

```
FINDINGS_DIR/browser/
├── xss.json
├── csrf.json
├── auth_bypass.json
├── open_redirect.json
├── form_discovery.txt     ← fed back into scanner.sh URL list
└── screenshots/
    └── xss_<hash>.png
```

## Integration with `hunt.py`

### New CLI flags

```
--browser-scan        Run browser agent phase (standalone)
--browser-headed      Show browser window (debug mode, default: headless)
--browser-model STR   Override LLM model (optional, default: auto-detect)
```

### Included in `--full`

Browser scan is automatically added to the `--full` pipeline, after `scanner.sh` and before brain analysis.

### Tool registry entry

```python
("playwright", "playwright", "pip install playwright && playwright install chromium")
```

## Dependencies

Added to `requirements.txt`:

```
browser-use>=0.1.0
playwright>=1.44.0
langchain-anthropic>=0.1.0
langchain-ollama>=0.1.0
```

One-time post-install: `playwright install chromium`

## Error Handling

- `browser-use` or `playwright` not installed → yellow warning, skip phase, continue pipeline
- LLM init fails → skip browser phase, log warning, continue pipeline
- Each task isolated — one crash does not abort others
- Per-task timeout: 120s
- Headless by default; `--browser-headed` for visibility

## Out of Scope

- Authenticated scanning (cookie injection, session tokens) — future enhancement
- Multi-tab parallel task execution — future enhancement
- Integration with Burp Suite proxy passthrough — future enhancement

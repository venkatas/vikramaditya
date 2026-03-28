# Browser Agent Design

**Date:** 2026-03-28
**Status:** Approved (v2 — post spec review)

## Overview

Add a real-browser vulnerability validation phase to OBSIDIAN using `browser-use` (Python + Playwright + LLM). The agent drives a Chromium browser against external targets, testing attack surfaces that require a live browser to validate: DOM XSS, CSRF, auth bypass on JS-rendered SPAs, open redirects, and JS-rendered form discovery.

## Architecture

### New file: `browser_agent.py`

Self-contained module (~300 lines). Provides:
- LLM auto-detection mirroring `brain.py`'s `LLMClient._auto_detect()` priority order
- 6 pre-defined `BrowserTask` classes
- Findings written as `.txt` files compatible with `reporter.py`'s `parse_custom_line()` loader
- Screenshot evidence capture per confirmed finding

### LLM bootstrap

Mirrors `brain.py`'s five-provider priority list exactly:

```
Priority: ollama → mlx → claude → openai → grok
```

`browser_agent.py` supports the two providers relevant to `browser-use` (which requires a LangChain chat model):
- Ollama → `ChatOllama` using the same model resolution list as `brain.py` (`vapt-qwen25:latest`, etc.)
- Claude → `ChatAnthropic(model="claude-sonnet-4-6")` if `ANTHROPIC_API_KEY` is set

If the resolved provider is `mlx`, `openai`, or `grok`, the module falls back to Ollama with a warning. This keeps the provider resolution consistent with `brain.py` without requiring a full LangChain wrapper for every provider.

The LLM is initialised via a shared `init_browser_llm()` helper that accepts an optional `model` override (from `--browser-model` flag).

### Task system

6 pre-defined `BrowserTask` classes. Each task targets a gap not covered by existing tools (`dalfox`, `nuclei`) — specifically JS-rendered content and SPA flows invisible to static scanners.

| Task | What it tests | Complements |
|------|--------------|-------------|
| `XSSDOMTask` | `document.write`, `innerHTML`, `eval` sinks after JS execution | dalfox (static injection only) |
| `XSSReflectedBrowserTask` | DOM-rendered validation of reflected payloads — confirms real browser execution, not just response text | dalfox candidates |
| `CSRFTask` | State-changing POST forms rendered by JS — token presence, SameSite cookie flags | scanner.sh (static forms only) |
| `AuthBypassTask` | JS-rendered login flows, SPA-based auth, forced browsing to protected routes | nuclei auth templates (static) |
| `OpenRedirectTask` | `?url=`, `?redirect=`, `?next=` params — confirms redirect in real browser (follows JS redirects) | scanner.sh redirects check |
| `FormDiscoveryTask` | Discovers JS-rendered inputs/params invisible to static crawlers | Feeds into scanner.sh URL list |

**Important distinction:** `XSSReflectedBrowserTask` does not independently inject payloads into every parameter. It takes the URL list from `FINDINGS_DIR/xss/dalfox_results.txt` and validates each candidate in a real browser, confirming whether the payload executes. This prevents duplicate findings.

Similarly, `AuthBypassTask` targets only JS-rendered auth flows and SPA routes that nuclei's static templates cannot reach. It does not re-test endpoints already covered by nuclei `auth` tag templates.

### Screenshot evidence

Each confirmed finding saves a `.png` to `FINDINGS_DIR/browser/screenshots/`. The screenshot path is appended as a comment in the `.txt` finding line.

## Data Flow

```
hunt.py --browser-scan
    └── browser_agent.py
            ├── init_browser_llm()       # mirrors brain.py provider priority
            ├── load_dalfox_candidates() # from FINDINGS_DIR/xss/dalfox_results.txt
            ├── BrowserTask x6           # each task isolated, 120s timeout
            │     ├── browser-use Agent (Playwright + LLM)
            │     ├── parse findings → line format for reporter.py
            │     └── save screenshot → FINDINGS_DIR/browser/screenshots/
            └── write findings .txt → FINDINGS_DIR/browser/{xss_dom,csrf,auth_bypass,...}.txt
                write form list     → FINDINGS_DIR/browser/form_discovery.txt
```

## Findings Format

Findings are written as `.txt` files using the same line format that `reporter.py`'s `parse_custom_line()` already reads:

```
https://target.com/search?q=<payload> [xss_dom] [high] DOM XSS via innerHTML sink confirmed in browser # screenshot:browser/screenshots/xss_abc123.png
```

Fields: `URL [vtype] [severity] description # screenshot:path`

### Changes to `reporter.py`

Add `browser` subdirectory entries to `SUBDIR_VTYPE`:

```python
"browser/xss_dom":      "dom_xss",
"browser/csrf":         "csrf",
"browser/auth_bypass":  "auth_bypass",
"browser/open_redirect":"open_redirect",
```

This is a minimal, additive change — no changes to `parse_custom_line()` or the HTML template logic.

## Session Structure

```
FINDINGS_DIR/browser/
├── xss_dom.txt
├── csrf.txt
├── auth_bypass.txt
├── open_redirect.txt
├── form_discovery.txt     ← fed back into scanner.sh URL list
└── screenshots/
    └── xss_<hash>.png
```

`FINDINGS_DIR` here refers to the **resolved per-session path** passed as an argument to `BrowserAgent.__init__()` — the same per-session path used by `run_vuln_scan()` in `hunt.py`. Not the module-level `FINDINGS_DIR` constant.

## Integration with `hunt.py`

### New CLI flags

```
--browser-scan        Run browser agent phase (standalone)
--browser-headed      Show browser window (debug mode, default: headless)
--browser-model STR   Override LLM model (optional, default: auto-detect)
```

Naming follows existing `hunt.py` convention: lowercase hyphen-separated.

### `--skip` alias

Add to `SKIP_ALIASES`:

```python
"browser": "browser_scan",
```

Allows `--skip browser` to suppress the phase during `--full` runs.

### `--full` pipeline

Browser scan is inserted as **phase 9** (after `scanner.sh`, before brain analysis), controlled by variable `do_browser_scan`. Position in the `--full` sequence:

```
... phase 8: vuln scan (scanner.sh)
    phase 9: browser scan (browser_agent.py)  ← NEW
    phase 10: brain analysis (brain.py)
...
```

## Dependencies

Added to `requirements.txt` as **commented optional** (consistent with existing langchain/langgraph pattern):

```
# Browser agent phase (--browser-scan)
# pip install "browser-use>=0.1.40" "playwright>=1.44.0" "langchain-anthropic>=0.1.0"
# playwright install chromium
```

Users who never run `--browser-scan` incur zero additional install cost. The module checks for `browser-use` at import time and skips gracefully if not present.

### Tool registry entry

```python
("browser-use", "playwright",
 'pip install "browser-use>=0.1.40" playwright langchain-anthropic && playwright install chromium')
```

The install hint is a compound shell command. The `--repair-tools` invocation for this entry must use `shell=True` (or be split into sequential steps). This will be noted in the implementation.

## Error Handling

| Condition | Behaviour |
|-----------|-----------|
| `browser-use` / `playwright` not installed | Yellow warning, skip phase, continue pipeline |
| LLM init fails | Yellow warning, skip phase, continue pipeline |
| Individual task crashes | Log error, continue remaining tasks |
| Per-task timeout (120s) | Task marked as timed-out, continue |
| No dalfox candidates for `XSSReflectedBrowserTask` | Task skipped silently |

All error handling follows the existing `hunt.py` yellow-warning-and-continue pattern.

## Out of Scope

- Authenticated scanning (cookie injection, session tokens) — future enhancement
- Multi-tab parallel task execution — future enhancement
- Burp Suite proxy passthrough — future enhancement
- LangChain wrappers for OpenAI/Grok/MLX providers in browser agent — future enhancement

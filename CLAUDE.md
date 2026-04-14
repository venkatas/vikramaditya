# Vikramaditya — VAPT Tool Guide

Autonomous penetration testing platform for professional VAPT engagements.
Targets: URL, FQDN, single IP, or CIDR range. Outputs Burp Suite-style HTML reports.

## Quick Usage

```bash
python3 vikramaditya.py      # Interactive — handles everything automatically
```

No flags needed. It auto-detects the target type, fingerprints the tech stack,
finds login pages and API endpoints, collects credentials interactively, enables
the AI brain if Ollama is installed, and routes to the right scan engine.

## Core Files

| File | Role |
|------|------|
| `vikramaditya.py` | **Main entry point** — interactive orchestrator, auto-detects everything |
| `brain_scanner.py` | LLM writes + executes exploit code (scan / verify-fix / audit-code) |
| `autopilot_api_hunt.py` | Brain-supervised 12-phase API VAPT engine |
| `hunt.py` | Infrastructure VAPT — recon + vuln scan for domains/IPs/CIDR |
| `brain.py` | AI analysis engine (Ollama local LLM) |
| `agent.py` | Autonomous ReAct agent — drives assessment without manual input |
| `recon.sh` | Subdomain enum, live host discovery, URL crawling |
| `scanner.sh` | Vulnerability scanner (SQLi, XSS, SSTI, RCE, cloud, frameworks) |
| `reporter.py` | Burp Suite-style HTML + Markdown report generator |
| `auth_utils.py` | JWT helper, rate limiter, authenticated session management |
| `prioritize.py` | CVE risk scoring and host prioritization |

## Advanced Usage (Direct Engine Access)

```bash
# Infrastructure VAPT
python3 hunt.py --target example.com
python3 hunt.py --target 192.168.1.0/24
python3 hunt.py --target example.com --autonomous --time 4

# API VAPT with explicit flags
python3 autopilot_api_hunt.py --base-url URL --auth-creds user:pass --with-brain

# Report
python3 reporter.py recon/example.com/sessions/<id>/findings/ --client "Acme Corp"
```

## Session Structure

```
recon/<target>/sessions/<timestamp_id>/
├── subdomains/          # Enumerated subdomains
├── live/                # Live hosts (httpx output)
├── urls/                # Crawled URLs
├── js/                  # JS files + extracted secrets
├── ports/               # nmap/naabu scan results
├── priority/            # CVE-ranked host lists
├── findings/            # Vulnerability findings by type
├── brain/               # AI analysis output
├── agent_session.json   # Agent state (resume support)
├── agent_trace.jsonl    # Live agent decision log
└── reports/             # vapt_report.html / vapt_report.md
```

## HAR-Based Authenticated Testing (NEW)

Comprehensive authenticated vulnerability testing using browser session data.

### HAR Testing Tools

| File | Role |
|------|------|
| `har_analyzer.py` | **HAR analysis** — extract endpoints, sessions, attack surface |
| `har_vapt_engine.py` | **Authenticated VAPT** — comprehensive vulnerability testing |
| `har_vapt.py` | **Standalone HAR VAPT** — complete workflow in one tool |
| `vapt_companion.py` | **Integration helper** — combine infrastructure + HAR testing |
| `vapt_suite.py` | **Unified interface** — interactive menu for all tools |

### HAR Testing Usage

```bash
# Complete HAR-based VAPT
python3 har_vapt.py session.har

# Individual components
python3 har_analyzer.py session.har                    # Analysis only
python3 har_vapt_engine.py session_analysis.json       # Testing only

# Combined workflow (infrastructure + authenticated)
python3 vapt_companion.py --full example.com

# Interactive suite with all tools
python3 vapt_suite.py
```

### HAR Capture Guide

1. **Browser Setup**: Open Developer Tools (F12) → Network tab
2. **User Actions**: Login and navigate authenticated areas
3. **Capture Session**: Right-click → Save as HAR file  
4. **Run Assessment**: `python3 har_vapt.py captured_session.har`

### HAR Testing Capabilities

- ✅ **SQL Injection** — authentication bypass, parameter injection
- ✅ **File Upload RCE** — malicious file uploads with bypass techniques
- ✅ **Authentication Bypass** — admin panel access without credentials
- ✅ **IDOR** — user enumeration and unauthorized data access
- ✅ **XSS** — cross-site scripting across all parameters
- ✅ **Session Management** — token security and session controls

## Rules
- All targets must have written client authorization
- Never test outside defined scope
- Use `--scope-lock` to restrict to exact target only
- HAR files may contain sensitive session data — handle securely

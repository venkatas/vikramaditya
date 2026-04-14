<div align="center">

```
 ██╗   ██╗██╗██╗  ██╗██████╗  █████╗ ███╗   ███╗ █████╗ ██████╗ ██╗████████╗██╗   ██╗ █████╗
 ██║   ██║██║██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝██╔══██╗
 ██║   ██║██║█████╔╝ ██████╔╝███████║██╔████╔██║███████║██║  ██║██║   ██║    ╚████╔╝ ███████║
 ╚██╗ ██╔╝██║██╔═██╗ ██╔══██╗██╔══██║██║╚██╔╝██║██╔══██║██║  ██║██║   ██║     ╚██╔╝  ██╔══██║
  ╚████╔╝ ██║██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║██████╔╝██║   ██║      ██║   ██║  ██║
   ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝
```

**v2.1 — Autonomous VAPT platform. One command. Give it a target — it figures out the rest.**

> *"He who seeks the truth must be ready to face the fire."*
> — inspired by the legend of Vikramaditya

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Shell](https://img.shields.io/badge/Shell-bash-4EAA25.svg?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![AI Powered](https://img.shields.io/badge/AI-Ollama%20%7C%20MLX%20%7C%20Claude%20%7C%20GPT--4o%20%7C%20Grok-blueviolet.svg?style=flat-square)](#multi-provider-ai)

[Quick Start](#quick-start) · [What's New in v2.0](#whats-new-in-v20) · [How It Works](#how-it-works) · [Architecture](#architecture) · [Vulnerability Coverage](#vulnerability-coverage) · [Reports](#reports) · [Installation](#installation) · [Contributing](#contributing)

---

**One target → Auto-fingerprint → Smart engine selection → AI writes exploit code → Professional report**

</div>

---

## What's New in v2.0

| Feature | v1.x | v2.0 |
|:--------|:-----|:-----|
| **Entry point** | 5+ scripts with flags (`hunt.py --target x --full`) | `python3 vikramaditya.py` — one command, interactive |
| **Target detection** | Manual: pick the right script | Auto: fingerprints tech stack, login, API, routes to right engine |
| **Brain role** | Supervisor only (CONTINUE/SKIP/INJECT) | **Writes and executes exploit code** — PoCs, bypasses, code audits |
| **Fix verification** | Manual retest | `--verify-fix` mode: brain reads deployed code, finds logic flaws, writes bypasses |
| **Code audit** | Not available | `--audit-code` mode: feed source code, brain finds vulns and writes PoCs |
| **Endpoint discovery** | Single main.js bundle only | All JS chunks (Vite, Next.js, CRA), dynamic imports, OpenAPI/Swagger |
| **Login detection** | Required `--login-url` flag | Auto-detects from 18+ common patterns + dev/staging endpoints |
| **API base path** | Required `--base-url` flag | Auto-probes `/api/`, `/v1/`, subdomains, same-origin detection |
| **URL dedup** | No dedup (scans thousands of identical news/video URLs) | Pattern-based collapse: 5000 → 50 unique code paths |
| **Scope lock** | `--scope-lock` flag | Interactive prompt: "scan this exact host only?" |
| **CLI args** | Required (`--target x --full --with-brain`) | `python3 vikramaditya.py example.com` — one arg, everything auto |
| **Banner** | Orange gradient | Indian flag colors (saffron, white, green, Ashoka blue) |

---

## The Legend

**Vikramaditya** — the legendary Indian emperor whose throne could only be ascended by one who sought truth fearlessly and judged without bias. His name means *"valour of the sun"*.

This tool operates the same way. Give it a target. Walk away. Come back to a full VAPT report — every vulnerability exposed, every weakness catalogued.

It was inspired by and evolved from [**claude-bug-bounty**](https://github.com/shuvonsec/claude-bug-bounty) — the original AI-assisted bug bounty automation platform that laid the recon pipeline, ReAct agent architecture, and AI analysis engine that powers this tool today.

---

## What It Does

Vikramaditya is an autonomous VAPT tool built for professional security consultants. You give it a target — a domain, a single IP, or an entire subnet. It runs the full assessment pipeline and produces a submission-ready report.

| Stage | What happens |
|:------|:-------------|
| 🔭 **Recon** | Subdomain enumeration, DNS resolution, live host discovery, URL crawling, JS analysis, secret extraction |
| 🔬 **Fingerprint** | Tech stack detection (httpx), CVE risk scoring, priority host ranking |
| 🔍 **Scan** | SQLi, XSS, SSTI, RCE, file upload, CORS, JWT, cloud misconfigs, framework exposure |
| 💥 **Exploit** | CMS exploit chains (Drupal, WordPress), Spring actuators, exposed admin panels |
| 🧠 **Analyze** | AI-powered triage — finds chains, ranks by impact, kills noise |
| 📋 **Report** | Burp Suite-style HTML report: executive summary, CVSS scores, PoC evidence, remediation |

---

## Quick Start

```bash
git clone https://github.com/venkatas/vikramaditya.git
cd vikramaditya
chmod +x setup.sh && ./setup.sh      # installs all required tools

# Download BugTraceAI brain (security-tuned, recommended)
wget -c 'https://huggingface.co/BugTraceAI/BugTraceAI-Apex-G4-26B-Q4/resolve/main/BugTraceAI-Apex-G4-26B-Q4.gguf' -O /tmp/BugTraceAI-Apex-G4-26B-Q4.gguf
ollama create bugtraceai-apex -f Modelfiles/BugTraceAI-Modelfile

# Or use stock Gemma4 (also works well)
ollama pull gemma4:26b               # fast all-rounder brain (17GB)
```

### The Only Command You Need

```bash
python3 vikramaditya.py                    # interactive — asks for target
python3 vikramaditya.py example.com        # pass target directly
python3 vikramaditya.py https://app.example.com
python3 vikramaditya.py 10.0.0.0/24
```

That's it. No flags, no script selection, no manual configuration. It will:

1. Ask for a target (URL, domain, IP, or CIDR)
2. Auto-fingerprint the target (tech stack, login pages, API endpoints, JS bundles, OpenAPI specs)
3. Show a summary of what it found and recommend the right scan type
4. Ask for credentials if a login page is detected (password input is hidden)
5. Enable the AI brain automatically if Ollama is installed
6. Offer **brain active scanner** — LLM writes and executes exploit code, not just supervises
7. Offer **fix verification** — developer says "fixed"? Brain reads the code and finds bypasses
8. Route to the right scan engine and run the full assessment
9. Offer to generate a professional report at the end

```
$ python3 vikramaditya.py app.example.com

  ────────────────────────────────────────────────────────
    TARGET SUMMARY
  ────────────────────────────────────────────────────────
    Target  : https://app.example.com
    Status  : HTTP 200
    Tech    : Vite, React
    Login   : /auth/login
    API     : https://app.example.com/v1
    JS      : 52 bundles, 80+ API calls found
    OpenAPI : found

    Recommended: Authenticated API VAPT
  ────────────────────────────────────────────────────────

  Proceed? [Y/n]: y
  Do you have credentials? [Y/n]: y
  Username / email: admin@example.com
  Password: ********
  Second account for IDOR / privilege escalation testing? [y/N]: n
  AI brain supervisor: enabled. Keep enabled? [Y/n]: y
  Run brain active scanner? (LLM writes + executes exploit code) [y/N]: y
  Verify a developer's fix claim? [y/N]: n

  [launching 12-phase brain-supervised API VAPT...]
  [then brain active scanner writes + runs exploit PoCs...]
```

For unauthenticated domain scans, it asks about scope:

```
$ python3 vikramaditya.py is.rediff.com

  Scope lock? (scan this exact host only, no subdomain expansion) [y/N]: y
  [scans is.rediff.com only — no www.rediff.com, no ishare.rediff.com]
```

### Brain Active Scanner

The brain doesn't just supervise — it **writes exploit code, executes it, reads the results, and iterates**. Three modes:

```bash
# General scanning — brain writes PoCs for every vuln it finds
python3 brain_scanner.py --target https://example.com

# Fix verification — developer says "fixed", brain proves them wrong
python3 brain_scanner.py --target https://example.com --verify-fix \
    --fix-claim "File upload now blocks .phtml extensions" \
    --code-url "https://example.com/scriptsNew/fileUpload-action.phtml"

# Source code audit — feed code, brain finds vulns and writes PoCs
python3 brain_scanner.py --target https://example.com --audit-code \
    --code-file /path/to/source.php
```

The `--verify-fix` mode is what caught the Rediffmail Pro OR-logic flaw: developers claimed they fixed the file upload, but the brain read the actual PHP code, spotted `if (mime_ok OR ext_ok)` (should be AND), and wrote the bypass PoC that regained RCE.

### Direct Engine Access (Advanced)

If you prefer flags and direct control, the individual engines are still available:

```bash
# Infrastructure VAPT (domains, IPs, subnets)
python3 hunt.py --target example.com
python3 hunt.py --target 10.0.0.0/24
python3 hunt.py --target example.com --autonomous

# Authenticated API VAPT (with all options)
python3 autopilot_api_hunt.py \
    --base-url https://api.target.com \
    --auth-creds "admin@target.com:password" \
    --with-brain

# Brain active scanner (LLM writes + executes exploit code)
python3 brain_scanner.py --target https://example.com --verify-fix \
    --fix-claim "CSRF fixed via ols token"

# Generate report manually
python3 reporter.py findings/target/ --client "Acme Corp"
```

---

## How It Works

`vikramaditya.py` is the smart orchestrator. It classifies your target and routes to the right engine:

| You give it | It detects | It runs |
|:------------|:-----------|:--------|
| `https://app.example.com` | Vite SPA, login page, API at `/v1` | Authenticated API VAPT (autopilot) |
| `https://api.example.com` | REST API, no frontend | API VAPT with endpoint discovery |
| `example.com` | Domain with web app | Fingerprint → API VAPT or recon |
| `example.com` | Domain, no web app | Full recon + vulnerability scan |
| `192.168.1.100` | Single IP | Recon + vulnerability scan |
| `10.0.0.0/24` | CIDR range | Network sweep + scan |

**Auto-detection features:**
- **Tech stack** — Vite, React, Next.js, Vue, Angular, Django, Laravel, WordPress, etc.
- **Login pages** — scans JS bundles + probes common auth URLs (`/auth/login`, `/login`, `/sign-in`, etc.)
- **API base path** — probes `/api/`, `/v1/`, `/graphql`, subdomain `api.*`, same-origin detection
- **JS code-split chunks** — follows Vite/Next.js/Webpack dynamic imports to find all endpoints
- **OpenAPI/Swagger** — discovers specs at `/docs`, `/swagger.json`, `/openapi.json`

---

## Architecture

```
python3 vikramaditya.py
        │
        ├── Classify target (URL / domain / IP / CIDR)
        ├── Fingerprint (tech stack, login, API, JS bundles, OpenAPI)
        ├── Interactive prompts (credentials, brain toggle)
        │
        ├──► Web app + credentials ──► autopilot_api_hunt.py (12-phase API VAPT)
        │                                    │
        │                              brain.py (AI supervisor: INJECT/SKIP/CONTINUE)
        │
        ├──► Verify developer fix ──► brain_scanner.py --verify-fix
        │                              (reads code, finds logic flaws, writes bypass PoCs)
        │
        ├──► Brain active scan ──► brain_scanner.py (LLM writes + executes exploits)
        │
        ├──► Web app, no creds ──► hunt.py (unauthenticated scan)
        │
        └──► Domain / IP / CIDR ──► hunt.py (recon + vuln scan)
                                       │
                                  ┌────┴──────────────────────────┐
                                  │                               │
                               recon.sh                      scanner.sh
                                  │                               │
                                  ├── subfinder / assetfinder     ├── SQLi (sqlmap)
                                  ├── httpx (tech detect)         ├── XSS (dalfox)
                                  ├── katana / waybackurls        ├── SSTI / RCE
                                  ├── nuclei (CVE templates)      ├── File upload
                                  ├── nmap / naabu (ports)        ├── Cloud exposure
                                  └── trufflehog (secrets)        └── Race conditions
                                       │
                                       ▼
                                  reporter.py
                                    ├── vapt_report.html
                                    └── vapt_report.md
```

---

## Vulnerability Coverage

| Category | Checks |
|:---------|:-------|
| **Injection** | SQLi (error/blind/time-based), SSTI (Jinja2/Freemarker/Thymeleaf/ERB), XXE, LDAP injection |
| **XSS** | Reflected, stored, DOM — via dalfox pipeline |
| **RCE** | Log4Shell OOB, Tomcat PUT (CVE-2017-12615), JBoss deserialization, Spring4Shell |
| **Auth** | JWT (alg=none, RS256→HS256, weak secret), OAuth misconfig, session fixation |
| **IDOR** | Object-level, field-level, GraphQL node() IDOR, UUID enumeration |
| **File Upload** | Extension bypass, MIME confusion, polyglots, SVG XSS |
| **Cloud** | Firebase open read/write, K8s API unauthenticated, Docker socket exposure, S3 bucket enum |
| **Framework** | Spring actuators (env/heapdump), H2 console, GraphQL introspection, Swagger UI |
| **CMS** | Drupalgeddon2 (CVE-2018-7600), WordPress user enum + xmlrpc, Joomla/Magento |
| **Infrastructure** | Subdomain takeover (subzy), CORS misconfiguration, open redirect, HTTP smuggling |
| **Secrets** | JS bundle secrets (trufflehog/gitleaks), .env exposure, .git/config leak |
| **Race Conditions** | Concurrent probes on OTP, coupon, payment endpoints |

---

## Reports

The report output matches professional pentest engagement standards — suitable for client submission.

**HTML report** (`vapt_report.html`) — single self-contained file:
- Dark navy cover page with client name, consultant, date, and classification
- Executive summary with risk breakdown bar
- Vulnerability summary table (ID, name, severity, CVSS, host)
- Per-finding detail: description, impact, PoC evidence, remediation, CWE/OWASP reference
- Appendix: tools used, methodology, assessment timeline

```bash
# Generate report from a completed scan session
python3 reporter.py recon/example.com/sessions/20260325_120000_abc1/findings/ \
    --client "Acme Corp" \
    --consultant "Your Name" \
    --title "Web Application Penetration Test"
```

Output: `reports/example.com/vapt_report.html` + `vapt_report.md`

---

## Autonomous Agent Mode

The `--autonomous` flag activates the ReAct agent (`agent.py`) which drives the entire assessment without manual intervention — planning, choosing tools, analysing results, and pivoting to the next attack surface on its own.

```bash
# Autonomous hunt with a 4-hour budget
python3 hunt.py --target example.com --autonomous --time 4

# Watch live decisions as they happen
tail -f recon/example.com/sessions/<session_id>/agent_trace.jsonl

# Inject operator guidance mid-run without stopping the agent
python3 agent.py --bump recon/example.com/sessions/<session_id>/ \
    "Focus on /api/v2/ endpoints — de-prioritize static assets"
```

The agent operates in a tight loop: **Observe → Think (LLM) → Act (tool) → Observe**. Every decision is logged to `agent_trace.jsonl` for post-engagement review.

---

## Multi-Provider AI

`brain.py` supports five LLM backends. Set `BRAIN_PROVIDER` to force one, or let Vikramaditya auto-detect in priority order: **Ollama → MLX → Claude → OpenAI → Grok**.

### Recommended Local Models (Benchmark-Tested)

Tested on MacBook Pro M4 Max (36GB) with real VAPT findings. Dual-model setup: **BugTraceAI** for deep security analysis, **gemma4:26b** for fast supervision.

| Rank | Model | Speed | Quality | RAM | Best For |
|:-----|:------|------:|:--------|----:|:---------|
| #1 | **`bugtraceai-apex`** | 57.0 tok/s | 4/4 | 16GB | **Primary brain** — Gemma4 26B fine-tuned on HackerOne/Bugcrowd reports, `<thinking>` blocks, 0% refusal, DPO-trained |
| #2 | **`gemma4:26b`** | 66.4 tok/s | 4/4 | 17GB | **Fast supervisor** — phase decisions (CONTINUE/SKIP/INJECT), 262K context |
| #3 | **`qwen3-coder-64k`** | 10.2 tok/s | 4/4 | 18GB | **Code analysis** — 64K context for large JS bundles |
| #4 | **`vapt-qwen25`** | 4.1 tok/s | 4/4 | 19GB | **Deep analysis** — custom VAPT training data |
| #5 | **`baron-llm`** | 14.2 tok/s | 2/4 | 6.6GB | **Fast triage** — offensive security fine-tune |
| — | `gemma4:e4b` | fast | 3/4 | 9.6GB | Lightweight — laptops with 16GB RAM |

```bash
# Recommended setup (one command):
ollama pull gemma4:26b

# Run fully local — no API keys, no data leaves your machine
python3 hunt.py --target example.com

# Autopilot API VAPT (autonomous, no manual direction needed)
python3 autopilot_api_hunt.py --base-url https://api.target.com \
    --auth-creds user:pass --with-brain
```

### All Supported Providers

| Provider | Env var required | Notes |
|:---------|:----------------|:------|
| **Ollama** (local, default) | — | CPU/GPU, all platforms, auto-detects best model |
| **MLX** (Apple Silicon) | — | ~40 tok/s on M-series, SSD paging for large models |
| **Claude** (Anthropic) | `ANTHROPIC_API_KEY` | Best reasoning, cloud-only |
| **OpenAI** | `OPENAI_API_KEY` | `gpt-4o`, `o3-mini` |
| **Grok** (xAI) | `XAI_API_KEY` | `grok-2-latest`, `grok-3-mini` |

---

## Installation

### Prerequisites

```bash
# macOS
brew install go python3 node jq nmap

# Debian/Ubuntu
sudo apt install golang python3 nodejs jq nmap
```

### Install security tools

```bash
chmod +x setup.sh && ./setup.sh
```

`setup.sh` installs **25+ tools** automatically:

| Source | Tools |
|:-------|:------|
| **Homebrew** | `subfinder` `httpx` `nuclei` `ffuf` `nmap` `amass` `sqlmap` `trufflehog` `gitleaks` `whatweb` |
| **Go** | `dnsx` `katana` `naabu` `cdncheck` `interactsh-client` `gau` `dalfox` `subzy` `waybackurls` `anew` `qsreplace` `assetfinder` `gf` |
| **Prebuilt binary** | `gowitness` (v3, Apple Silicon + Intel) |
| **pip** | `arjun` `httpx[cli]` `mlx-lm` *(arm64 only)* |
| **git clone → tools/** | `LinkFinder` `SecretFinder` `XSStrike` `drupalgeddon2` |
| **Auto** | nuclei-templates, gf patterns (`~/.gf/`), subfinder config scaffold |

### Python dependencies

```bash
pip install -r requirements.txt
```

See `requirements.txt` for LLM provider SDK details.

---

## API Keys Setup

### CHAOS API (ProjectDiscovery) — Required for best subdomain coverage

The recon pipeline uses the [Chaos](https://chaos.projectdiscovery.io) dataset from ProjectDiscovery — millions of pre-enumerated subdomains indexed per domain. Free key.

1. Sign up at **[chaos.projectdiscovery.io](https://chaos.projectdiscovery.io)**
2. Copy your API key
3. Export before running:

```bash
export CHAOS_API_KEY="your-key-here"

# For persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc
source ~/.zshrc
```

`recon.sh` detects `$CHAOS_API_KEY` and auto-injects it into subfinder's provider config on first run. **The key is never stored in any file in this repo.**

---

### Optional API Keys — Better Subdomain Coverage

`setup.sh` creates a config scaffold at `~/.config/subfinder/provider-config.yaml`. Uncomment and fill in any of these free/cheap keys:

| Provider | Free? | Signup | Benefit |
|:---------|:------|:-------|:--------|
| **VirusTotal** | ✅ Free | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | +passive subdomain data |
| **SecurityTrails** | ✅ Free tier | [securitytrails.com](https://securitytrails.com/app/account/credentials) | +historical DNS |
| **Censys** | ✅ Free tier | [search.censys.io/account/api](https://search.censys.io/account/api) | +certificate transparency |
| **Shodan** | 💲 ~$9/mo | [account.shodan.io](https://account.shodan.io) | +banner grab, port data |
| **GitHub** | ✅ Free | [github.com/settings/tokens](https://github.com/settings/tokens) | +source code subdomain leaks |

```yaml
# ~/.config/subfinder/provider-config.yaml
chaos:
  - YOUR_CHAOS_API_KEY
virustotal:
  - YOUR_VIRUSTOTAL_API_KEY
securitytrails:
  - YOUR_SECURITYTRAILS_API_KEY
censys:
  - YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET
shodan:
  - YOUR_SHODAN_API_KEY
github:
  - YOUR_GITHUB_TOKEN
```

See [`subfinder-config.yaml.example`](subfinder-config.yaml.example) for the full template.

---

## CLI Reference

### vikramaditya.py — The Main Entry Point

```bash
python3 vikramaditya.py        # Interactive — no flags needed
```

Everything is handled through prompts. No flags to remember.

### hunt.py — Infrastructure VAPT (Advanced)

```
Target input:
  --target example.com          FQDN
  --target 192.168.1.100        Single IP
  --target 10.0.0.0/24          CIDR range (nmap ping sweep first)

Scan modes:
  --quick                       Faster scan, fewer checks
  --full                        All checks including race conditions
  --autonomous                  AI-driven autonomous assessment

Selective phases:
  --recon-only / --scan-only / --js-scan / --param-discover
  --api-fuzz / --secret-hunt / --cors-check / --exploit
  --rce-scan / --sqlmap / --jwt-audit

AI options:
  --no-brain                    Skip AI analysis (tools only)
  --brain-only / --brain-next   AI analysis on existing data

Utilities:
  --repair-tools / --status / --oob-setup / --resume SESSION_ID
```

### autopilot_api_hunt.py — API VAPT (Advanced)

```
  --base-url URL                API base URL (auto-detected by vikramaditya.py)
  --auth-creds user:pass        Primary account credentials
  --auth-creds-b user:pass      Second account for IDOR/priv esc testing
  --login-url PATH              Login endpoint (auto-detected by vikramaditya.py)
  --frontend-url URL            Frontend URL for JS scraping (auto-inferred)
  --with-brain                  Enable brain supervisor (auto-enabled by vikramaditya.py)
  --rate-limit N                Max requests/sec (default: 5)
  --output DIR                  Output directory for findings
```

### reporter.py — Report Generation

```bash
python3 reporter.py <findings_dir> [--client NAME] [--consultant NAME] [--title TITLE]
```

---

## Autopilot API VAPT Engine

The `autopilot_api_hunt.py` module is a **brain-supervised dynamic VAPT engine** for modern SPA + REST API applications. It runs 12 attack phases autonomously with an AI supervisor that decides what to test next based on discoveries.

### How the Brain Supervisor Works

```
Discover endpoints (JS bundle + Django debug + crawl)
  → Brain categorizes endpoints and creates prioritized test plan
  → Loop:
      Execute top-priority phase
      → Brain reviews findings
      → Brain decides: CONTINUE / INJECT / SKIP / PIVOT
      → Modify test queue based on decision
  → Chain building → Brain validation (FP removal) → Report
```

### Attack Phases

| Phase | Tests |
|-------|-------|
| Auth Bypass | No token, expired, tampered, alg=none |
| IDOR | Sequential ID enum, Base64 decode, PII detection |
| Privilege Escalation | Learner → admin endpoint access |
| Business Logic | Score manipulation, workflow bypass, negative values |
| File Upload | Double extension, MIME mismatch, polyglot, S3 arbitrary type |
| Injection | SQLi (time + error), SSTI, command injection |
| Info Disclosure | Django DEBUG, server headers, SMTP creds, AWS keys, DB schema |
| Rate Limiting | Rapid login, password change, reset |
| Token Security | JWT lifetime, refresh token abuse |
| Timing Oracles | User enumeration via response time |
| Chain Building | Cross-reference findings for escalation |
| Brain Validation | FP removal + severity correction via LLM |

### Brain Model Stack (Dual-Model Architecture)

| Role | Model | Speed | Use |
|------|-------|-------|-----|
| **Deep analysis** | `bugtraceai-apex` | 57 tok/s | Exploit writing, code audit, fix verification, brain_scanner |
| Fast supervisor | `baron-llm` | 14 tok/s | Per-phase INJECT/SKIP/CONTINUE decisions |
| Fast fallback | `gemma4:26b` | 66 tok/s | All-rounder when specialized models unavailable |
| FP validation | `bugtraceai-apex` | 57 tok/s | Finding triage, severity corrections |
| Chain analysis | `bugtraceai-apex` | 57 tok/s | Exploit chain identification + recommendations |

---

## New Modules (v5+)

| Module | Purpose |
|--------|---------|
| `autopilot_api_hunt.py` | Brain-supervised autonomous API VAPT (12 phases) |
| `auth_api_tester.py` | Broken access control testing (5 auth states per endpoint) |
| `api_idor_scanner.py` | Generic two-token IDOR scanner (ID mutation + Base64 decode) |
| `business_logic_tester.py` | Score manipulation, rate limits, pagination abuse |
| `oauth_tester.py` | OAuth state entropy, redirect_uri bypass, host header injection |
| `auth_utils.py` | JWT decode/tamper (no PyJWT), rate limiter, auth session |
| `finding_validator.py` | 7-Question Gate + 28-pattern never-submit list |
| `chain_builder.py` | 12-pattern A→B exploit chain discovery |
| `scope_checker.py` | Deterministic domain matching (anchored suffix, IP rejection) |
| `memory/` | Hunt journal (JSONL), pattern DB, audit log with circuit breaker |

---

## Directory Structure

```
vikramaditya/
├── vikramaditya.py          ★ Single entry point — run this
├── brain_scanner.py         LLM writes + executes exploit code (scan/verify-fix/audit-code)
├── hunt.py                  Infrastructure VAPT engine (domains, IPs, CIDR)
├── autopilot_api_hunt.py    Brain-supervised API VAPT engine
├── brain.py                 AI analysis engine (Gemma 4, Ollama, MLX, Claude, OpenAI, Grok)
├── agent.py                 Autonomous ReAct agent
├── auth_api_tester.py       Authenticated API broken access control
├── api_idor_scanner.py      Generic REST IDOR scanner
├── business_logic_tester.py Score manipulation, rate limits, pagination
├── oauth_tester.py          OAuth/OIDC security testing
├── auth_utils.py            JWT helper, rate limiter, auth session
├── finding_validator.py     7-Question Gate + never-submit list
├── chain_builder.py         A→B exploit chain discovery
├── scope_checker.py         Deterministic scope enforcement
├── recon.sh                 Subdomain + URL discovery
├── scanner.sh               Vulnerability scanner
├── reporter.py              Report generator (HTML + Markdown + inline PoC)
├── memory/                  Hunt journal, pattern DB, audit log
├── prioritize.py        CVE risk scoring
├── api_audit.py         OpenAPI/REST API auditing
├── cve.py               CVE matcher
├── fuzzer.py            Smart logic fuzzer
├── validate.py          Finding validator (4-gate)
├── intel.py             CVE + advisory intel
├── mindmap.py           Attack surface mapper
├── targets.py           Target management
├── idor.py              IDOR scanner
├── idor_mutator.py      GraphQL mutation IDOR
├── oauth.py             OAuth misconfiguration tester
├── race.py              Race condition tester
├── payloads.py          Payload generator
├── probe.py             HTTP prober
├── browser_recon.js     Browser-side recon (Playwright)
├── evasion.py           WAF bypass helpers
├── zendesk_idor.py      Zendesk-specific IDOR
├── setup.sh             Tool installer
├── sqli_verify.sh       SQLi verification
├── procs.sh             Pipeline process monitor
├── requirements.txt     Python dependencies
├── config.example.json  Configuration template
├── skills/              Skill definitions
├── wordlists/           Custom wordlists
├── recon/               Scan output (gitignored)
├── findings/            Validated findings (gitignored)
└── reports/             Generated reports (gitignored)
```

---

## Configuration

Copy and edit the example config:

```bash
cp config.example.json config.json
```

Key settings:

```json
{
  "brain_provider": "ollama",
  "ollama_model": "qwen2.5:14b",
  "interactsh_token": "YOUR_INTERACTSH_TOKEN",
  "rate_limit": 50,
  "threads": 10,
  "timeout": 30,
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
}
```

---

## Contributing

PRs welcome. This tool was originally inspired by and built on top of [`shuvonsec/claude-bug-bounty`](https://github.com/shuvonsec/claude-bug-bounty) — the original AI-assisted bug bounty platform. Contributions that advance its mission are appreciated.

**Good contributions:**

- New vulnerability scanners or detection modules for `scanner.sh`
- Payload additions to `skills/` and `wordlists/`
- New agent tool definitions in `agent.py`
- Report template improvements — better HTML, better Markdown
- New AI provider support in `brain.py`
- Real-world methodology improvements (with evidence from authorized engagements)
- IP / network scanning improvements (better CIDR handling, IPv6)
- Platform-specific modules (Jira, Confluence, GitLab, cloud consoles)

**How to contribute:**

```bash
git checkout -b feature/your-contribution
# ... make your changes ...
git commit -m "Add: short description"
git push origin feature/your-contribution
```

Then open a pull request describing what you added and why it's useful.

**Commit message conventions:**

| Prefix | Use for |
|:-------|:--------|
| `Add:` | New scanner, module, or feature |
| `Fix:` | Bug fix |
| `Improve:` | Enhancement to existing functionality |
| `Refactor:` | Code cleanup, no behaviour change |
| `Docs:` | README, comments, docs only |

---

## Legal

**For authorized security testing only.**

Only use this tool against systems you own or have explicit written authorization to test. Vikramaditya is designed for professional VAPT consultants working under signed engagement letters. Unauthorized use against systems you do not have permission to test is illegal in most jurisdictions.

The authors accept no liability for misuse.

---

## Credits

Vikramaditya evolved from [**claude-bug-bounty**](https://github.com/shuvonsec/claude-bug-bounty) by [@shuvonsec](https://github.com/shuvonsec) — an AI-assisted bug bounty automation framework that pioneered the recon pipeline, ReAct agent loop, and AI-driven analysis engine that form the core of this tool.

Named after **Emperor Vikramaditya** — whose legendary throne tested every claimant with 32 trials of truth before granting the seat of judgment. Like the emperor's court: thorough, relentless, and no weakness goes unexamined.

---

<div align="center">

MIT License · Built for professional VAPT consultants

*"In the end, the Order sees all."*

</div>

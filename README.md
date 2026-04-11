<div align="center">

```
 ██╗   ██╗██╗██╗  ██╗██████╗  █████╗ ███╗   ███╗ █████╗ ██████╗ ██╗████████╗██╗   ██╗ █████╗
 ██║   ██║██║██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝██╔══██╗
 ██║   ██║██║█████╔╝ ██████╔╝███████║██╔████╔██║███████║██║  ██║██║   ██║    ╚████╔╝ ███████║
 ╚██╗ ██╔╝██║██╔═██╗ ██╔══██╗██╔══██║██║╚██╔╝██║██╔══██║██║  ██║██║   ██║     ╚██╔╝  ██╔══██║
  ╚████╔╝ ██║██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║██████╔╝██║   ██║      ██║   ██║  ██║
   ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝
```

**Autonomous VAPT platform. Give it a target — FQDN, IP, or CIDR range. It hunts, it reports.**

> *"He who seeks the truth must be ready to face the fire."*
> — inspired by the legend of Vikramaditya

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Shell](https://img.shields.io/badge/Shell-bash-4EAA25.svg?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![AI Powered](https://img.shields.io/badge/AI-Ollama%20%7C%20MLX%20%7C%20Claude%20%7C%20GPT--4o%20%7C%20Grok-blueviolet.svg?style=flat-square)](#multi-provider-ai)

[Quick Start](#quick-start) · [Architecture](#architecture) · [Vulnerability Coverage](#vulnerability-coverage) · [Reports](#reports) · [Installation](#installation) · [API Keys](#api-keys-setup) · [Contributing](#contributing)

---

**Recon → Tech fingerprinting → CVE mapping → Vulnerability scanning → AI analysis → Professional report**

</div>

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
ollama pull gemma4:26b               # recommended brain model (17GB)
```

### Infrastructure VAPT (domains, IPs, subnets)

```bash
# Full assessment on a domain
python3 hunt.py --target example.com

# Single IP address
python3 hunt.py --target 192.168.1.100

# Subnet (discovers live hosts first via nmap ping sweep)
python3 hunt.py --target 10.0.0.0/24

# Faster scan (fewer checks)
python3 hunt.py --target example.com --quick

# Autonomous mode — AI drives all decisions
python3 hunt.py --target example.com --autonomous
```

### Authenticated API VAPT (SPA + REST API targets)

```bash
# Brain-supervised autonomous scan (recommended)
python3 autopilot_api_hunt.py \
    --base-url https://api.target.com \
    --auth-creds "admin@target.com:password" \
    --login-url sign-in/ \
    --frontend-url https://app.target.com \
    --with-brain

# With second account for IDOR + privilege escalation testing
python3 autopilot_api_hunt.py \
    --base-url https://api.target.com \
    --auth-creds "admin@target.com:password" \
    --auth-creds-b "user@target.com:password" \
    --login-url sign-in/ \
    --with-brain

# Without brain (fully deterministic, no LLM needed)
python3 autopilot_api_hunt.py \
    --base-url https://api.target.com \
    --auth-creds "admin@target.com:password" \
    --login-url sign-in/
```

### Individual Tools

```bash
# Authenticated API broken access control
python3 auth_api_tester.py --base-url URL --auth-creds user:pass --login-url sign-in/

# Generic REST API IDOR scanner (two-token cross-user testing)
python3 api_idor_scanner.py --base-url URL --token-a TOKEN1 --token-b TOKEN2

# Business logic testing (score manipulation, rate limits, pagination abuse)
python3 business_logic_tester.py --base-url URL --auth-creds user:pass --login-url sign-in/

# OAuth/OIDC security testing
python3 oauth_tester.py --target target.com

# Finding validator (7-Question Gate — kills weak findings before report)
python3 finding_validator.py findings/target/

# Chain builder (A→B exploit escalation)
python3 chain_builder.py findings/target/

# Generate VAPT report (HTML + Markdown with inline PoC)
python3 reporter.py findings/target/ --target target.com --client "Client Name"
```

---

## Architecture

```
Target (FQDN / IP / CIDR)
        │
        ▼
   hunt.py  ◄── brain.py (AI analysis + multi-provider LLM)
        │         └── agent.py (autonomous ReAct loop)
        │
   ┌────┴────────────────────────────────────┐
   │                                         │
   ▼                                         ▼
recon.sh                               scanner.sh
  │                                       │
  ├── subfinder / assetfinder             ├── SQLi (sqlmap + verifier)
  ├── amass / dnsx                        ├── XSS (dalfox)
  ├── httpx (tech detect)                 ├── SSTI (math-canary probes)
  ├── katana / waybackurls / gau          ├── RCE (Log4Shell, Tomcat, JBoss)
  ├── nuclei (CVE templates)              ├── File upload bypass
  ├── nmap / naabu (port scan)            ├── Cloud exposure (Firebase, K8s, Docker)
  ├── subzy (takeover check)              ├── Framework exposure (Spring, GraphQL)
  └── trufflehog / gitleaks (JS secrets)  └── Race conditions (xargs -P 20)
        │
        ▼
  prioritize.py (CVE risk scoring)
        │
        ▼
   brain.py (AI triage)
        │
        ▼
   reporter.py
     ├── vapt_report.html  (Burp Suite-style, self-contained)
     └── vapt_report.md    (Markdown summary)
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

Tested on MacBook Pro M4 Max (36GB) with a real VAPT findings set. Quality scored on: exploit chain identification, missed-test suggestions, and attack path analysis.

| Rank | Model | Speed | Quality | RAM | Best For |
|:-----|:------|------:|:--------|----:|:---------|
| #1 | **`gemma4:26b`** | 25.6 tok/s | 4/4 | 17GB | **Primary brain** — fastest with full quality, native tool calling, 262K context |
| #2 | **`qwen3-coder-64k`** | 10.2 tok/s | 4/4 | 18GB | **Code analysis** — 64K context for large JS bundles |
| #3 | **`vapt-qwen25`** | 4.1 tok/s | 4/4 | 19GB | **Deep analysis** — custom VAPT training data |
| #4 | `deepseek-r1:32b` | 3.9 tok/s | 4/4 | 19GB | Chain-of-thought reasoning (slow) |
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

```
hunt.py — VAPT Orchestrator

Target input:
  --target example.com          FQDN
  --target 192.168.1.100        Single IP
  --target 10.0.0.0/24          CIDR range (nmap ping sweep first)

Scan modes:
  --quick                       Faster scan, fewer checks
  --full                        All checks including race conditions
  --autonomous                  AI-driven autonomous assessment
  --scope-lock                  Test exact target only (no subdomain expansion)

Selective phases:
  --recon-only                  Recon only
  --scan-only                   Scan only (requires prior recon)
  --js-scan                     JS analysis + secret extraction
  --param-discover              Parameter discovery (Arjun + ParamSpider)
  --api-fuzz                    API endpoint brute (Kiterunner)
  --secret-hunt                 TruffleHog + GitHound
  --cors-check                  CORS misconfiguration check
  --exploit                     CMS exploit chains (Drupal, WordPress)
  --rce-scan                    RCE: Log4Shell, Tomcat, JBoss, Spring
  --sqlmap                      sqlmap on discovered SQLi candidates
  --jwt-audit                   JWT algorithm confusion + weak secret crack

AI options:
  --no-brain                    Skip AI analysis (tools only)
  --brain-only                  AI analysis on existing recon data
  --brain-next                  Ask AI: what is the highest-impact next action?

Reporting:
  python3 reporter.py <findings_dir> [--client NAME] [--consultant NAME] [--title TITLE] [--target DOMAIN]

Utilities:
  --repair-tools                Auto-install missing tools
  --status                      Show current assessment progress
  --oob-setup                   Configure interactsh OOB token
  --resume SESSION_ID           Resume a previous session

Autopilot API VAPT (autopilot_api_hunt.py):
  --base-url URL                API base URL (required)
  --auth-creds user:pass        Primary account credentials (required)
  --auth-creds-b user:pass      Second account for IDOR/priv esc testing
  --login-url PATH              Login endpoint path (default: sign-in/)
  --frontend-url URL            Frontend URL for JS bundle scraping
  --with-brain                  Enable brain supervisor (local LLM)
  --rate-limit N                Max requests/sec (default: 5)
  --output DIR                  Output directory for findings
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

### Brain Model Stack

| Role | Model | Speed | Use |
|------|-------|-------|-----|
| Decision engine | `baron-llm` | 14 tok/s | Per-phase INJECT/SKIP/CONTINUE decisions |
| FP validation | `qwen3-coder-64k` | 10 tok/s | JSON severity corrections |
| Chain analysis | `gemma4:26b` | 25 tok/s | Final exploit chain + recommendations |

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
├── hunt.py                  Main orchestrator (infrastructure VAPT)
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

<div align="center">

# OBSIDIAN

**Autonomous VAPT platform. Give it a target — FQDN, IP, or CIDR range. It hunts, it reports.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Shell](https://img.shields.io/badge/Shell-bash-4EAA25.svg?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)

[Quick Start](#quick-start) · [Architecture](#architecture) · [Vulnerability Coverage](#vulnerability-coverage) · [Reports](#reports) · [Installation](#installation)

---

**Recon → Tech fingerprinting → CVE mapping → Vulnerability scanning → AI analysis → Professional report**

</div>

---

## What It Does

OBSIDIAN is an autonomous VAPT tool built for professional security consultants. You give it a target — a domain, a single IP, or an entire subnet. It runs the full assessment pipeline and produces a submission-ready report.

| Stage | What happens |
|:------|:-------------|
| **Recon** | Subdomain enumeration, DNS resolution, live host discovery, URL crawling, JS analysis, secret extraction |
| **Fingerprint** | Tech stack detection (httpx), CVE risk scoring, priority host ranking |
| **Scan** | SQLi, XSS, SSTI, RCE, file upload, CORS, JWT, cloud misconfigs, framework exposure |
| **Exploit** | CMS exploit chains (Drupal, WordPress), Spring actuators, exposed admin panels |
| **Analyze** | AI-powered triage — finds chains, ranks by impact, kills noise |
| **Report** | Burp Suite-style HTML report: executive summary, CVSS scores, PoC evidence, remediation |

---

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/obsidian.git
cd obsidian
chmod +x setup.sh && ./setup.sh      # installs all required tools

# Run a full assessment
python3 hunt.py --target example.com

# IP address
python3 hunt.py --target 192.168.1.100

# Subnet (discovers live hosts first)
python3 hunt.py --target 10.0.0.0/24

# Quick scan (faster, fewer checks)
python3 hunt.py --target example.com --quick

# Autonomous mode (AI drives all decisions)
python3 hunt.py --target example.com --autonomous
```

---

## Architecture

```
Target (FQDN / IP / CIDR)
        │
        ▼
   hunt.py  ←── brain.py (AI analysis)
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
  ├── nuclei (CVE templates)              ├── File upload
  ├── nmap / naabu (port scan)            ├── Cloud exposure (Firebase, K8s, Docker)
  ├── subzy (takeover check)              ├── Framework exposure (Spring, GraphQL)
  └── trufflehog / gitleaks (JS secrets)  └── Race conditions
        │
        ▼
  prioritize.py (CVE risk scoring)
        │
        ▼
   brain.py (AI triage)
        │
        ▼
   reporter.py
     └── vapt_report.html  (Burp Suite-style)
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
| **Cloud** | Firebase open read/write, K8s API unauthenticated, Docker socket exposure, S3 bucket enumeration |
| **Framework** | Spring actuators (env/heapdump), H2 console, GraphQL introspection, Swagger UI |
| **CMS** | Drupalgeddon2 (CVE-2018-7600), WordPress user enum + xmlrpc, Joomla/Magento |
| **Infrastructure** | Subdomain takeover (subzy), CORS misconfiguration, open redirect, HTTP smuggling |
| **Secrets** | JS bundle secrets (trufflehog/gitleaks), .env exposure, .git/config exposure |
| **Race Conditions** | Concurrent probes on OTP, coupon, payment endpoints (`xargs -P 20`) |

---

## Reports

The report output matches professional pentest report standards.

**HTML report** (`vapt_report.html`):
- Cover page with client name, consultant, date, classification
- Executive summary with risk breakdown
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

The `--autonomous` flag enables the ReAct agent (`agent.py`) which drives the entire assessment without manual intervention.

```bash
# Autonomous hunt with 4-hour budget
python3 hunt.py --target example.com --autonomous --time 4

# Watch live decisions
tail -f recon/example.com/sessions/<session_id>/agent_trace.jsonl

# Inject guidance mid-run without stopping
python3 agent.py --bump recon/example.com/sessions/<session_id>/ \
    "Focus on /api/v2/ endpoints, de-prioritize static assets"
```

The agent uses Ollama (local LLM) for all analysis — no data leaves your machine.

---

## AI Analysis

`brain.py` provides AI-powered triage using local Ollama models. Recommended models:

| Role | Model | Size |
|:-----|:------|:-----|
| Deep analysis | `qwen3-coder:32b` | ~19 GB |
| Fast triage | `baron-llm:latest` (BaronLLM, offensive security fine-tune) | 6.6 GB |
| Fallback | `qwen2.5:14b` | ~9 GB |

```bash
ollama pull qwen2.5:14b   # minimum recommended
```

---

## Installation

### Prerequisites

```bash
# macOS
brew install go python3 node jq nmap

# Linux (Debian/Ubuntu)
sudo apt install golang python3 nodejs jq nmap
```

### Install tools

```bash
chmod +x setup.sh && ./setup.sh
```

Installs: `subfinder`, `httpx`, `dnsx`, `nuclei`, `katana`, `waybackurls`, `gau`, `dalfox`, `ffuf`, `anew`, `qsreplace`, `assetfinder`, `subzy`, `naabu`, `sqlmap`, `interactsh-client`, `trufflehog`, `gitleaks`, nuclei-templates.

### Python dependencies

```bash
pip install -r requirements.txt
```

---

## CLI Reference

```
hunt.py — VAPT Orchestrator

Target input:
  --target example.com          FQDN
  --target 192.168.1.100        Single IP
  --target 10.0.0.0/24          CIDR range

Scan modes:
  --quick                       Faster scan, fewer checks
  --full                        All checks including race conditions
  --autonomous                  AI-driven autonomous assessment
  --scope-lock                  Test exact target only (no subdomains)

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
  --brain-next                  Ask AI: what's the highest-impact next action?

Reporting:
  python3 reporter.py <findings_dir> [--client NAME] [--consultant NAME]

Utilities:
  --repair-tools                Auto-install missing tools
  --status                      Show current assessment progress
  --oob-setup                   Configure interactsh OOB token
  --resume SESSION_ID           Resume a previous session
```

---

## Directory Structure

```
obsidian/
├── hunt.py              Main orchestrator
├── brain.py             AI analysis engine (Ollama)
├── agent.py             Autonomous ReAct agent
├── recon.sh             Subdomain + URL discovery
├── scanner.sh           Vulnerability scanner
├── reporter.py          Report generator (HTML + Markdown)
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
├── browser_recon.js     Browser-side recon
├── evasion.py           WAF bypass helpers
├── zendesk_idor.py      Zendesk-specific IDOR
├── setup.sh             Tool installer
├── procs.sh             Pipeline process monitor
├── sqli_verify.sh       SQLi verification
├── skills/              Claude Code skill definitions
├── wordlists/           Custom wordlists
├── recon/               Scan output (gitignored)
├── findings/            Validated findings (gitignored)
└── reports/             Generated reports (gitignored)
```

---

## Multi-Provider AI

`brain.py` supports four LLM backends. Set `BRAIN_PROVIDER` to choose, or let OBSIDIAN auto-detect.

| Provider | Env var | Example models |
|:---------|:--------|:---------------|
| **Ollama** (local, default) | — | `qwen2.5:14b`, `qwen3-coder:32b` |
| **Claude** (Anthropic) | `ANTHROPIC_API_KEY` | `claude-sonnet-4-6`, `claude-opus-4-6` |
| **OpenAI** | `OPENAI_API_KEY` | `gpt-4o`, `o3-mini` |
| **Grok** (xAI) | `XAI_API_KEY` | `grok-2-latest`, `grok-3-mini` |

```bash
# Force a specific provider
export BRAIN_PROVIDER=claude
export ANTHROPIC_API_KEY=sk-ant-...
python3 hunt.py --target example.com

# Or use Ollama locally (no API key needed)
ollama pull qwen2.5:14b
python3 hunt.py --target example.com
```

---

## Legal

**For authorized security testing only.** Only use this tool against systems you own or have explicit written authorization to test. Unauthorized use is illegal. The authors accept no liability for misuse.

---

## Credits

OBSIDIAN grew out of [claude-bug-bounty](https://github.com/YOUR_USERNAME/claude-bug-bounty) — an AI-assisted bug bounty automation project. The original recon pipeline, ReAct agent architecture, and brain.py AI analysis engine were built there and later extended into this professional VAPT platform.

---

<div align="center">

MIT License · Built for professional VAPT consultants

</div>

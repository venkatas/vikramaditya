# Vikramaditya — VAPT Tool Guide

Autonomous penetration testing platform for professional VAPT engagements.
Targets: FQDN, single IP, or CIDR range. Outputs Burp Suite-style HTML reports.

## Core Files

| File | Role |
|------|------|
| `hunt.py` | Main orchestrator — run all phases or individual stages |
| `brain.py` | AI analysis engine (Ollama local LLM) |
| `agent.py` | Autonomous ReAct agent — drives assessment without manual input |
| `recon.sh` | Subdomain enum, live host discovery, URL crawling |
| `scanner.sh` | Vulnerability scanner (SQLi, XSS, SSTI, RCE, cloud, frameworks) |
| `reporter.py` | Burp Suite-style HTML + Markdown report generator |
| `prioritize.py` | CVE risk scoring and host prioritization |

## Quick Usage

```bash
# Full assessment
python3 hunt.py --target example.com

# IP or subnet
python3 hunt.py --target 192.168.1.0/24

# Autonomous (AI-driven)
python3 hunt.py --target example.com --autonomous --time 4

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

## Rules
- All targets must have written client authorization
- Never test outside defined scope
- Use `--scope-lock` to restrict to exact target only

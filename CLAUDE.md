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
| `whitebox/cloud_hunt.py` | **Whitebox VAPT** — AWS audit (Prowler + PMapper + secrets), feeds blackbox |

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

## Whitebox VAPT (AWS Cloud Integration)

Run alongside blackbox to add cloud audit, IAM blast-radius, secrets scanning,
and exploit chaining.

```bash
# Standalone whitebox audit (single account)
python3 -m whitebox.cloud_hunt --profile adf-erp \
  --allowlist adfactorspr.com \
  --session-dir recon/adfactorspr.com

# Both accounts in one run
python3 -m whitebox.cloud_hunt --profile adf-erp --profile adf-pranapr \
  --allowlist adfactorspr.com --allowlist pranapr.com \
  --session-dir recon/<target>

# Bust the 24h phase cache and re-run everything
python3 -m whitebox.cloud_hunt --profile adf-erp --refresh \
  --allowlist adfactorspr.com --session-dir <dir>

# Disable scope-lock (audit ALL public Route53 zones in the account)
python3 -m whitebox.cloud_hunt --profile adf-erp --no-scope-lock \
  --session-dir <dir>
```

When `vikramaditya.py` runs, it auto-detects whether the target domain is
listed in `whitebox_config.yaml`. If so, it offers to run cloud whitebox
alongside blackbox; the `cloud/` directory under `recon/<target>/` is
populated and the final report includes a "Cloud Posture" chapter plus
inline cloud context on each blackbox finding.

**Required external tools:**
- `prowler-cloud==4.5.0` — MUST be installed in an isolated venv because it
  hard-pins `pydantic==1.10.18`, which conflicts with `ollama` (used by
  `brain.py`) and most other packages in the main venv.

  ```bash
  python3 -m venv ~/.venvs/prowler          # use Python 3.11 (Prowler 4.5 incompatible with 3.14)
  ~/.venvs/prowler/bin/pip install prowler-cloud==4.5.0
  ```

  The runner discovers the binary via (in order): `PROWLER_BIN` env var →
  `~/.venvs/prowler/bin/prowler` → `~/.local/share/prowler/bin/prowler` →
  `/opt/prowler/bin/prowler` → `$PATH`. If missing, the phase is skipped
  with a friendly `FileNotFoundError` in the manifest.
- `principalmapper>=1.1.5` — install in an isolated venv:
  ```bash
  python3.11 -m venv ~/.venvs/pmapper
  ~/.venvs/pmapper/bin/pip install principalmapper
  # Patch the Python 3.10+ collections.abc import bug:
  sed -i 's/from collections import Mapping/from collections.abc import Mapping/' \
    ~/.venvs/pmapper/lib/python*/site-packages/principalmapper/util/case_insensitive_dict.py
  ```
  Discovery order: `PMAPPER_BIN` env → `~/.venvs/pmapper/bin/pmapper` →
  `~/.local/share/pmapper/bin/pmapper` → `/opt/pmapper/bin/pmapper` → `$PATH`.
  Region narrowing: set `PMAPPER_REGIONS=us-east-1,ap-south-1,eu-west-1`
  to skip slow/opt-in regions where the graph build can hang on
  `ConnectTimeoutError` (e.g. `me-south-1`).

**Permission gaps:** Whitebox falls back to metadata-only when
`secretsmanager:GetSecretValue` is denied. To enable full secret-value
scanning, add `secretsmanager:GetSecretValue` to the audit user's policy.

**Scope-lock:** `--allowlist` is REQUIRED unless `--no-scope-lock` is
passed explicitly. Route53 zones in the AWS account are intersected with
the allowlist before being treated as in-scope.

**Real-account smoke test:** set `WHITEBOX_SMOKE=1` to run
`tests/whitebox/smoke/test_real_aws.py` against `adf-erp` and
`adf-pranapr` profiles.

---
description: Email authentication + mail security posture audit — SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, DNSSEC, live SMTP STARTTLS probe, .eml header analysis. Ported from subspace-sentinel in v7.2.0. Usage: /email-audit <domain|email|.eml>
---

# /email-audit

Full email-auth posture audit for a domain, an email address, or a captured `.eml` file. A standard recon deliverable for any bug-bounty target that accepts email — missing SPF / permissive DMARC / weak DKIM are often the starter finding in an account-takeover chain.

## Usage

```bash
/email-audit target.com                          # full domain audit
/email-audit alice@target.com                    # same, derived from the @-domain
/email-audit target.com --selectors s1,s2,mail   # probe specific DKIM selectors
/email-audit target.com --smtp-probe             # live STARTTLS against MX
/email-audit --targets-file domains.txt          # bulk audit
/email-audit --message-file phish.eml            # analyse a received email
```

Or via the v7.2.0 hunt.py integration — just run:

```bash
python3 hunt.py --target target.com
# Phase 8.7 runs email_audit automatically on every domain hunt.
```

## What it checks

| Area | Severity trigger |
|:-----|:-----------------|
| **SPF** | Missing record → HIGH. `+all` → HIGH. `~all`+many includes → MEDIUM (DNS lookup limit). `?all` → MEDIUM |
| **DMARC** | Missing → HIGH. `p=none` → MEDIUM. Relaxed alignment + no RUA/RUF → LOW |
| **DKIM** | No discoverable selector → MEDIUM. RSA < 1024 bits → HIGH. 1024-bit → MEDIUM (deprecated) |
| **MX hygiene** | Privateish IPs → MEDIUM. Non-authoritative records → MEDIUM. STARTTLS unavailable (with `--smtp-probe`) → HIGH |
| **DNSSEC** | Unsigned → MEDIUM. Broken chain → HIGH |
| **MTA-STS** | Missing → MEDIUM. Policy `mode=testing` for > 90 days → MEDIUM |
| **TLS-RPT** | Missing → LOW |
| **BIMI** | Present without DMARC enforcement → MEDIUM (misleading visual trust) |
| **Cross-finding** | SPF+DMARC+DKIM all permissive → HIGH (spoofable) |

## Where outputs land

Standalone:
```
recon/<target>/email_auth/audit.json   # full report (text + JSON both supported)
```

Via `hunt.py` integration:
```
recon/<target>/email_auth/audit.json            # raw report
findings/<target>/email_auth/findings.json      # distilled issue list, HTML-reporter shape
```

## Multi-LLM analysis (optional)

`email_audit.py` supports Ollama / Claude / OpenAI / xAI / Gemini for AI-assisted summary. Configure via `.env`:

```bash
EMAIL_AUDIT_AI_PROVIDER=ollama
EMAIL_AUDIT_AI_MODEL=qwen3-coder-64k:latest
# or Claude
ANTHROPIC_API_KEY=sk-ant-...
```

See `.env.example` of the upstream `subspace-sentinel` project for full config reference — the same keys work here.

## Credit

Tool originally authored by the repo owner (`venkatas/subspace-sentinel`, MIT). Integrated verbatim in Vikramaditya v7.2.0; v7.3.0 will refactor it into an `email_audit/` package that reuses Vikramaditya's `brain.py` LLM dispatcher and `memory/schemas.py` finding schema.

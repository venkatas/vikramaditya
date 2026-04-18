---
description: VAPT anonymization reverse proxy — anonymize real client data before it reaches Claude, deanonymize surrogates on the way back. Usage: /anon start | stop | status | vault-stats | vault-clear
---

# /anon

Transparent anonymization proxy for Claude Code during VAPT engagements. Real client IPs, hostnames, hashes, credentials, AWS keys, JWTs never leave your machine — the proxy strips them on the way out and restores them on the way back.

## When to use it

Any engagement where your NDA / contract says "don't send client data to third-party AI services" but you still want Claude Code's reasoning on the output of `nmap`, `crackmapexec`, `mimikatz`, `responder`, Burp, `enum4linux`, `ldapsearch`, etc.

## Architecture

```
Claude Code  ──► http://127.0.0.1:8080/v1/messages  ──► api.anthropic.com
                         ▲                                        │
                         │        [anonymize request body]        │
                         │                                        │
                         └─── [deanonymize SSE stream] ◄──────────┘
```

- Requests: every JSON string field walked recursively; every IPv4/CIDR/IPv6/MAC/email/URL/FQDN/hash (MD5, SHA1, SHA256, NTLM)/AWS key/API token/JWT replaced with a deterministic surrogate (RFC 5737 TEST-NET IPs, `.pentest.local` FQDNs, locally-administered MACs).
- Responses: same treatment in reverse. SSE (`text/event-stream`) is handled line-by-line so streaming stays live.
- Mapping storage: SQLite at `~/.vikramaditya/anon_vault.db`, keyed by `ENGAGEMENT_ID`. Same IP → same surrogate across sessions within one engagement.

## Usage

### Start the proxy

```bash
# Terminal 1 — start the proxy (uses the real ANTHROPIC_API_KEY from env)
export ENGAGEMENT_ID=acme-2026-vapt
python3 -m llm_anon.proxy
# Listens on 127.0.0.1:8080

# Terminal 2 — point Claude Code at the proxy
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ENGAGEMENT_ID=acme-2026-vapt      # must match Terminal 1
claude
```

### Health + stats

```bash
curl -s http://127.0.0.1:8080/health | python3 -m json.tool
```
Returns the active `engagement`, vault DB path, upstream URL, and entity histogram.

### Between engagements

```bash
# Option A: a new engagement_id gives a fresh namespace, old mappings stay.
export ENGAGEMENT_ID=acme-2026-retest
python3 -m llm_anon.proxy

# Option B: explicitly clear the vault for the current engagement.
python3 -c "
from llm_anon import Vault
v = Vault('${HOME}/.vikramaditya/anon_vault.db', '${ENGAGEMENT_ID}')
print(f'cleared {v.clear()} mappings')
"
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ENGAGEMENT_ID` | `default` | **Set this per client.** Isolates mappings so two clients never share surrogates. |
| `ANON_PROXY_PORT` | `8080` | Port the proxy binds on `127.0.0.1`. |
| `ANTHROPIC_UPSTREAM` | `https://api.anthropic.com` | Forward target. Override for testing. |
| `ANON_VAULT_PATH` | `~/.vikramaditya/anon_vault.db` | SQLite file. |
| `ANTHROPIC_API_KEY` | *(none)* | Forwarded as-is to upstream. The proxy never reads its value. |

## Guardrails

- **Never expose on a public interface.** Binds to `127.0.0.1` by default.
- **Do not pipe the vault DB off the machine.** It contains the mapping between real and synthetic — the thing you're trying to keep out of Anthropic's logs.
- **Binary / image uploads pass through untouched.** Don't paste screenshots of sensitive dashboards.
- **This is not a compliance certification.** Review your client contract. The proxy prevents content-based correlation; timing / query-pattern correlation is out of scope.

## Design credit

Architecture inspired by [zeroc00I/LLM-anonymization](https://github.com/zeroc00I/LLM-anonymization) — independent implementation from that public README design spec.

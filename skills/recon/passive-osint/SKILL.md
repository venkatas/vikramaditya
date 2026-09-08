---
name: passive-osint
description: Passive OSINT / external recon checklist — CT logs, DNS, public search, Shodan-style host intel. Portable CAI-inspired recon craft; no CAI runtime.
---

# Passive OSINT / External Recon

## Checklist
- [ ] Confirm scope (apex + declared wildcards) before any query that touches third-party APIs
- [ ] Certificate Transparency: `crt.sh`, public CT aggregators → hostnames / SANs
- [ ] Passive DNS / subdomain sources: zone transfers only if in-scope; prefer multi-source passive enum
- [ ] Public host/port intel (Shodan/Censys-style): banners, product versions, exposed panels
- [ ] Historical URLs / archives for forgotten apps and staging hosts
- [ ] Org / ASN / email MX footprint only when engagement allows OSINT depth

## Common misses
| Area | Miss |
|---|---|
| CT only | Skip expired/wildcard SANs that still resolve |
| Shodan query | Over-broad org search → out-of-scope hosts |
| DNS | Trusting a single passive source without merge/dedupe |
| Archives | Ignoring status-code drift on resurrected paths |

## Proof standard
- Asset list is **in-scope**, resolvable (or explicitly noted as NXDOMAIN/takeover candidate), and deduped.
- Public banner/CVE hints are **leads**, not confirmed vulns — hand off to live verification.
- Never claim exploitability from OSINT alone.

## Vik wiring
- Prefer existing `recon.sh` / subfinder / dnsx / httpx pipeline; this pack guides prioritization only.
- `VIK_SKILLS=0` disables injection of this pack into the brain.

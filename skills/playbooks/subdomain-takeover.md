---
name: subdomain-takeover
aliases: [subdomain-takeover, takeover, dangling-dns]
tags: [subdomain-takeover, dns, cloud, recon]
severity: high
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/web-application-security/exploiting-subdomain-takeover-vulnerabilities/SKILL.md -->

# Subdomain Takeover

## When to Use
- Subdomain enumeration reveals CNAME/A records pointing to external services.
- Cloud endpoints returning "not found" / "no such bucket" pages.
- Orgs with large subdomain footprints and uncertain DNS hygiene.

## Critical Checks Most Often Missed
- **Resolve the full CNAME chain** (`dig +short CNAME`) — any hop could be the dangling one, and intermediate hops can mask the real target.
- **Match the exact service fingerprint** from `can-i-take-over-xyz` (NoSuchBucket, "There isn't a GitHub Pages site here", "No such app", Fastly/Shopify/Surge strings) — not just a status code.
- **Verify the service actually allows claiming the name now** — many historically "vulnerable" fingerprints are no longer registrable (modern Azure/AWS require domain verification).

## Validation / Confirm Steps
- Positive signal = the dangling resource is **actually claimable** AND you serve your own content. Confirm with a **benign canary claim** and fetch the subdomain to see your marker — then document and clean up.
- Assess impact: cookie scope (`.target.com`), OAuth redirect / CORS trust — so the finding reflects real risk, not just content control.

## False-Positive Traps
- A `404` or generic error is **NOT** proof — many services 404 while still owned/unclaimable. Require the exact service fingerprint.
- A matching fingerprint is not enough if the provider now blocks claiming that name — verify registrability before reporting.
- Don't conclude "vulnerable" (or "safe") until you've resolved the full CNAME chain, matched the fingerprint, confirmed claimability, and (where authorized) performed the benign canary claim.

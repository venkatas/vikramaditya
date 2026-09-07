# Severity rubric (Vikramaditya)

Adapted from openai/codex-security severity/policy guidance (Apache-2.0 ideas;
clean-room rewrite for our web/API VAPT reports). Apply AFTER reachability and
proof are established — never inflate from bug-class alone.

## Critical (keep only with clear path + major impact)

- Credible RCE / code execution from in-scope input
- Auth bypass / 0-click account takeover
- Cross-tenant IDOR / authz break with sensitive data
- SQLi (or equivalent) with proven attacker control + impact
- SSTI leading to RCE or secret exfil with proof
- Arbitrary file read/write of secrets/keys with proof
- Sandbox/isolation escape

## High

- SSRF with proven destination control + likely internal/metadata impact
- Authz/IDOR limited to same-tenant or narrower objects
- XXE with proven XML control + impact
- Dangerous upload enabling stored active content with proof
- Deserialization / template abuse impactful but not fully RCE-proven
- CSRF enabling credential/permission/billing/security changes

## Usually NOT high/critical alone

- Missing headers, cookie flags, CSP/TLS hygiene
- Version/banner disclosure, directory listing, stack traces
- Open redirect / clickjacking / user enum / rate-limit weakness alone
- Self-XSS; alert()-only XSS without session/impact proof
- Theoretical memory corruption; "could chain if..." without the chain
- Bugs that already require admin/root unless the priv-esc delta is the finding

## High/Critical acceptance checklist (all should hold)

1. In-scope component
2. Realistic attacker
3. Reasonable in-scope attack surface
4. Credible exploitation path (not speculation)
5. Major security impact
6. Would pass serious audit / bounty triage as high/critical

## Policy adjustments

- Self-only / unachievable preconditions → ignore or info
- Internal-only surfaces: lower likelihood/confidence; do not auto-ignore if a real authz/trust regression remains
- Real bug but not security → low/info, not critical

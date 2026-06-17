---
name: cors
aliases: [cors, cors-misconfiguration]
tags: [cors, same-origin-policy, owasp-a05, data-exfiltration]
severity: medium
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/web-application-security/testing-cors-misconfiguration/SKILL.md -->

# CORS Misconfiguration

## When to Use
- API endpoints serving authenticated data to SPAs / cross-origin clients.
- Assessing whether a victim's authenticated responses can be read cross-origin.

## Critical Checks Most Often Missed
- **Reflected arbitrary Origin + credentials** is the high-impact case — send `Origin: https://evil.example.com` and watch whether it is echoed in `Access-Control-Allow-Origin` alongside `Access-Control-Allow-Credentials: true`.
- **`Origin: null`** (sandboxed-iframe / data-URI attack) — many servers allowlist `null`.
- **Subdomain trust** — `https://evil.target.example.com` reflected means any XSS/takeover on a subdomain reads the API.
- **Prefix/suffix-match bypasses** — `https://target.example.com.evil.com`, `https://eviltarget.example.com`, trailing-dot/backtick tricks reveal naive string matching.

## Validation / Confirm Steps
```
curl -s -I -H "Origin: https://evil.example.com" https://api.target.example.com/api/user/profile \
  | grep -iE "access-control-allow-(origin|credentials)"
```
- Confirm a hit when `Access-Control-Allow-Origin: https://evil.example.com` is echoed **next to** `Access-Control-Allow-Credentials: true`.
- Prove real exploitability with a browser PoC — `fetch(url,{credentials:'include'})` that actually **reads the body** cross-origin, not just the headers.

## False-Positive Traps
- A reflected ACAO **without** `Allow-Credentials: true` is lower impact (only non-credentialed data leaks) — note it, but don't claim account-data theft.
- `Access-Control-Allow-Origin: *` cannot be combined with credentials by browsers — a wildcard alone does not expose authenticated data.
- Don't conclude "not vulnerable" after one Origin test — also try `null`, an arbitrary subdomain, and prefix/suffix bypasses.

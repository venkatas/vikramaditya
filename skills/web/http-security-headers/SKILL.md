---
name: http-security-headers
description: HTTP request/response security header checklist — CORS, CSP, cookies, cache, redirect chains. Portable CAI web-analysis ideas.
---

# HTTP Security Headers / Response Analysis

## Checklist
- [ ] Capture baseline request/response (status, redirects, Set-Cookie, WWW-Authenticate)
- [ ] CORS: reflected Origin + `Access-Control-Allow-Credentials: true`?
- [ ] Cookies: missing `Secure` / `HttpOnly` / `SameSite` on session tokens
- [ ] CSP / X-Frame-Options / HSTS presence and bypass gaps (report-only ≠ enforced)
- [ ] Cache / CDN: `Cache-Control` on authenticated JSON; shared-cache leakage
- [ ] Verbose errors / stack traces / debug headers (`X-Powered-By`, server versions)

## Common bypasses / traps
| Observation | Trap |
|---|---|
| `ACAO: *` | Harmless with credentials; browsers block `*` + credentials |
| Missing CSP | Often Low/Info alone — escalate only with XSS/clickjack proof |
| HSTS absent | Note for HTTP hosts; not Critical by itself |
| Long redirect chain | Check open-redirect / SSRF hop abuse separately |

## Proof standard
- For CORS data-theft: prove credentialed cross-origin **body** read, not just header echo.
- Header hygiene alone → Informational/Low unless chained to a confirmed impact.

## Vik wiring
- Complements `skills/playbooks/cors.md`; keep live proof in browser/fetch PoC when claiming Medium+.

---
name: open-redirect
aliases: [open-redirect, redirect, unvalidated-redirect]
tags: [open-redirect, phishing, oauth, owasp-a01]
severity: low
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/web-application-security/testing-for-open-redirect-vulnerabilities/SKILL.md -->

# Open Redirect

## When to Use
- Login/logout flows that redirect to a supplied URL.
- OAuth/SSO `redirect_uri` validation (chains into token theft).
- Any URL param: `next`, `url`, `redirect`, `return`, `goto`, `target`, `dest`, `continue`, `returnTo`.

## Critical Checks Most Often Missed
- **Fuzz every redirect-ish param** — `url, redirect, redir, next, target, return, rurl, dest, destination, redirect_uri, redirect_url, checkout_url, continue, return_to, returnTo, go, image_url, view, out, r, u`.
- **Bypass matrix** (paste into the param):
  `//attacker.com`, `/\attacker.com`, `https:attacker.com`, `\/\/attacker.com`, `//attacker.com/%2f..`, `https://target.com@attacker.com`, `https://target.com%2f@attacker.com`, `//attacker%E3%80%82com` (unicode dot), `https://target.com.attacker.com` (whitelisted host as prefix), `https://attacker.com/target.com` (whitelisted host in path), `///attacker.com/`.

## Validation / Confirm Steps
- Confirm the server issues a **3xx with `Location:` pointing at the attacker domain** (or client-side `window.location`/meta-refresh navigates there) — follow with `curl -sI` and inspect `Location`.
- For OAuth impact, show the **token/code is delivered to the attacker origin** via the redirect — that elevates Low → High.

## False-Positive Traps
- A redirect that stays **same-origin** (path-only) is not an open redirect — the `Location` must resolve to an external host you control.
- Reflected-in-body but not followed is not exploitable on its own; confirm actual navigation.
- Standalone open redirect is typically Low/Informational — only escalate when chained (OAuth token theft, SSRF filter bypass, phishing on a trusted domain). State the chain explicitly.

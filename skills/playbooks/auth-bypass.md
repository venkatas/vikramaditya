---
name: auth-bypass
aliases: [auth-bypass, authentication-bypass, forced-browsing]
tags: [access-control, owasp-a01, authentication, forced-browsing]
severity: high
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/web-application-security/bypassing-authentication-with-forced-browsing/SKILL.md -->

# Authentication / Authorization Bypass (Forced Browsing)

## When to Use
- Discovering hidden/unprotected admin pages, APIs, debug/actuator/swagger interfaces.
- Verifying auth is consistently enforced across every endpoint and method.
- Finding exposed backup/config/VCS files left in production.

## Critical Checks Most Often Missed
- **HTTP method swap.** Auth is often enforced per-method only — try GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD and override headers (`X-HTTP-Method-Override`, `_method`).
- **Path / normalization tricks.** Case changes, trailing `/`, `;`, `..;/`, `%2f`, `%2561`, `%00`, `/.;/`, and `../` traversal to slip past path-based rules and reverse-proxy ACLs.
- **Forced/hidden endpoints** from fuzzing — admin, actuator, swagger, debug, internal — and **backup/VCS files** (`.bak`, `.old`, `.env`, `.git/HEAD`, `.svn`).
- **Header-based trust.** `X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host` to reach "internal-only" routes.

## Validation / Confirm Steps
- Positive signal = the **actual protected resource/action** returned to an unauthenticated (or lower-priv) request — the real admin panel, real user data, or a real config/backup file — not a login redirect or empty SPA shell.
- **Differential with a second context:** compare the unauth response against the authenticated owner's response (body + length). Matching sensitive content proves missing access control.
- `.git/HEAD` returning `ref: refs/heads/...` confirms VCS exposure (then reconstruct the repo).

## False-Positive Traps
- A 200 alone is NOT a hit (could be a login page or SPA shell that hydrates client-side).
- A 403/302 alone is NOT a clean negative — the endpoint may be reachable via another method, header, or path form.
- Don't conclude "not vulnerable" until you've tried method swaps, path-normalization tricks, header trust, and forced/backup paths.

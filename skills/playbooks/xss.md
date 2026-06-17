---
name: xss
aliases: [xss, cross-site-scripting, dom-xss]
tags: [injection, owasp-a03, client-side, javascript]
severity: medium
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/penetration-testing/testing-for-xss-vulnerabilities/SKILL.md -->

# Cross-Site Scripting (XSS)

## When to Use
- Any reflected, stored, or DOM context where user input reaches HTML/JS output.
- Assessing input sanitization + output encoding across all features.
- SPA (React/Angular/Vue) DOM-XSS via client-side routing/rendering.

## Critical Checks Most Often Missed
- **Match the output context, not just `<script>alert(1)`.** Payload must fit where input lands: HTML body vs attribute (`" onfocus=alert(1) autofocus`) vs JS string (`';alert(1)//`) vs URL/`href` (`javascript:`) vs CSS. One body-context payload misses attribute breakouts and JS-string escapes.
- **Blind/stored XSS that fires elsewhere.** Payloads in support tickets, profile fields, filenames, and `User-Agent`/`Referer` headers often execute in an admin panel you cannot see. Use XSS Hunter / Collaborator callbacks.
- **DOM XSS in SPAs.** Server encoding can be perfect while client JS pipes `location.hash`/`postMessage` into `innerHTML`/`eval`/`dangerouslySetInnerHTML`/`v-html`. Trace source→sink in the JS — don't just diff server responses.
- **CSP / WAF gaps.** Check `unsafe-inline`/`unsafe-eval`/wildcard/JSONP; try case/event-handler/SVG/encoded variants before declaring a sink safe.

## Validation / Confirm Steps
- Prove **execution**, not reflection: a fired `alert(document.domain)`, a screenshot, or an OOB callback containing the cookie/DOM (for blind/stored).
- Show the payload **unencoded** in the response source and the exact context it broke out of.
- For DOM XSS, set a breakpoint at the sink and show the tainted value reaching it.

## False-Positive Traps
- `&lt;script&gt;` in the response means it was **encoded** → NOT vulnerable. Confirm the payload appears raw and in an executable position.
- Reflection in a JSON/`Content-Type: application/json` response with correct content type usually does not execute — verify it renders as HTML.
- Don't conclude a field is safe until tested across HTML/attribute/JS/URL contexts with filter-bypass variants; don't conclude an SPA is safe until you've traced client sources to DOM sinks.

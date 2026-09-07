---
name: ssti
description: Focused SSTI checklist — delimiter matrix, engine fingerprint, RCE proof.
---

# SSTI — Server-Side Template Injection

## Checklist
- [ ] Probe all delimiters: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`, `{7*7}`
- [ ] Fingerprint: `{{7*'7'}}` → `7777777` = Jinja2; `49` = Twig
- [ ] Non-obvious sinks: emails, PDFs, error pages, filenames, headers
- [ ] Blind/OOB when no reflection
- [ ] CSTI on Angular/Vue if server does not evaluate

## Common bypasses
- URL-encoded braces; `{%` when `{{` stripped
- Engine-specific sandbox escapes only AFTER fingerprint

## Proof standard
- Computed `49` (or Jinja string-mult tell) proves evaluation — literal `7*7` echo is reflection/XSS, not SSTI.
- RCE claim requires benign command output or OOB callback, not just math canary.

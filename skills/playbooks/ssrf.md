---
name: ssrf
aliases: [ssrf, server-side-request-forgery, blind-ssrf]
tags: [ssrf, cloud-metadata, owasp-a10, internal-pivot]
severity: high
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/security-operations/performing-ssrf-vulnerability-exploitation/SKILL.md -->

# Server-Side Request Forgery (SSRF)

## When to Use
- Any param that accepts a URL/host/path (webhooks, image/PDF fetch, import-from-URL, `redirect_uri`-style, SSO metadata).
- Pivoting to cloud metadata (169.254.169.254) or internal services.

## Critical Checks Most Often Missed
- **IMDSv2 needs a token, not just a GET.** On AWS, `GET /latest/meta-data/` returns 401 under IMDSv2 — but SSRF can still win if it can first send `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`. Don't conclude "safe" from a single 401. (IMDSv2 hop-limit=1 blocks proxied/container hops, not same-host SSRF.)
- **Other clouds use different hosts/headers.** GCP/Azure metadata require headers (`Metadata-Flavor: Google`, `Metadata: true`); a plain fetch 403 looks safe but isn't. Hit `metadata.google.internal`, `169.254.169.254/metadata/instance?api-version=...`.
- **`gopher://` for non-HTTP pivots.** When only HTTP-ish fetches are allowed, `gopher://127.0.0.1:6379/_<redis>` or `:3306` hits internal Redis/MySQL/SMTP. Enumerate `gopher://`, `dict://`, `file://`, `ftp://`.
- **Filter bypasses.** `http://0x7f000001`, `http://127.0.0.1.nip.io`, decimal IPs, `[::1]`, open redirects on a trusted domain, DNS rebinding (TTL-0 flip to 169.254.169.254 after the validation check).

## Validation / Confirm Steps
- Gold standard = **attributable exfiltrated data**: real IAM creds (`AccessKeyId`/`SecretAccessKey`), a returned metadata document, or an OOB callback (Collaborator / your DNS log) proving the server made the request.
- AWS IAM creds path: `GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` returning `AccessKeyId`+`SecretAccessKey` = critical, confirmed.

## False-Positive Traps
- Blind/time-based deltas are **candidates, not confirmation** — require an OOB hit or returned internal content.
- A single 401/403 from a metadata host is NOT a clean negative until you've tried token-based IMDSv2, alternate schemes, encoded IPs, and redirect/rebinding.

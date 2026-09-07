---
name: cloud-metadata-imds
description: Cloud instance metadata (IMDS) exposure via SSRF/misconfig — AWS/GCP/Azure. Portable cloud recon ideas; no aggression defaults.
---

# Cloud Metadata / IMDS

## Checklist
- [ ] Only probe when SSRF or host-level access is already in authorized scope
- [ ] AWS IMDS: `169.254.169.254` — try IMDSv1; if 401, note IMDSv2 hop-limit / token PUT requirement
- [ ] GCP: `metadata.google.internal` + `Metadata-Flavor: Google`
- [ ] Azure: `169.254.169.254` + `Metadata: true` (and Identity endpoints when relevant)
- [ ] Distinguish DNS OOB hit (info) from returned credentials/document (high impact)

## Common bypasses (when SSRF filtered)
| Technique | Note |
|---|---|
| IP encoding | Decimal/octal/hex/IPv6-mapped forms of link-local |
| DNS rebind / redirect | Allowlisted host → internal after check |
| Alternate metadata hosts | Vendor-specific aliases / stacked proxies |

## Proof standard
- **Confirm**: retrieved IAM/service credentials, user-data secrets, or equivalent metadata document.
- Token-required IMDSv2 rejection alone ≠ "safe" — document hop-limit and whether SSRF can still PUT token.
- Do **not** enable `ALLOW_STATE_CHANGES` or blast-radius actions from this pack.

## Vik wiring
- Complements `skills/web/ssrf`; cloud blast-radius remains explicit opt-in elsewhere.

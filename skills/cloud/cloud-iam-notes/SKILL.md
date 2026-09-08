---
name: cloud-iam-notes
description: Optional cloud IAM posture notes. Checklist only. Not a scanner and not installed by setup.sh.
---

# Cloud IAM notes (optional)

Coverage notes for a gap Vik does not run by default. HexStrike-style cloud tool dumps are intentionally skipped. This pack does not change `ALLOW_STATE_CHANGES` or aggression defaults.

## Already in Vik
- `skills/cloud/cloud-metadata-imds` for metadata exposure via an already-in-scope SSRF or host
- `skills/cloud/storage-exposure` for public bucket/container checks
- `whitebox/cloud_hunt.py` (Prowler / PMapper) when the engagement is an authorized AWS account review

## Checklist
- [ ] Confirm the account, role, and regions are in the written scope
- [ ] Prefer the existing whitebox/Prowler path over a new IAM enumerator
- [ ] Note unused access keys, wildcard actions, and public resource policies only when you can show them from an in-scope credential
- [ ] Bucket or container *name* discovery (s3scanner-style) is optional and operator-owned. Do not add it to the default hunt path
- [ ] Empty or marketing-only storage stays informational; follow `storage-exposure` proof standard

## Do not
- Install enumerate-iam, cloudbrute, or similar as a required `setup.sh` dependency
- Treat this pack as permission to pivot into an account that is not in scope
- Enable destructive or blast-radius actions from this checklist

## Vik wiring
- Skill context only. No hunt `TOOL_REGISTRY` entry. No MCP execute tool.

---
name: storage-exposure
description: Cloud storage exposure checklist — S3/GCS/Azure Blob public ACLs, listing, signed-URL abuse. Portable cloud recon ideas.
---

# Cloud Storage Exposure

## Checklist
- [ ] Identify candidate buckets/containers from JS, errors, DNS, takeover wordlists
- [ ] Public list vs public read vs authenticated-only; test object guessability
- [ ] Look for backup dumps, `.env`, terraform state, copies of source
- [ ] Signed URL / SAS token leakage in logs, referrers, mobile apps
- [ ] Cross-account / mis-applied bucket policies (principal `*` + risky actions)

## Common traps
| Trap | Note |
|---|---|
| 403 on list | Individual objects may still be world-readable |
| "Website hosting" bucket | Public by design — check for sensitive prefixes only |
| CDN in front | Origin ACL may differ from edge behavior |
| Name squatting | Confirm ownership/scope before reporting |

## Proof standard
- Demonstrate retrieval (or listing) of **non-public** sensitive objects without credentials you should not have.
- Empty public marketing bucket → Informational at most.

## Vik wiring
- Opt-in cloud modules elsewhere; this pack is checklist context only — no default aggressive scanning.

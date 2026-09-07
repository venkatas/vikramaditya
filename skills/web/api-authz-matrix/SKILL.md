---
name: api-authz-matrix
description: API authorization matrix — roles, IDOR/BOLA, BFLA, mass-assignment. Portable CAI web/API testing ideas.
---

# API Authorization Matrix

## Checklist
- [ ] Enumerate roles (anon / user / other-user / admin) and token types
- [ ] For each sensitive object ID: same-role horizontal IDOR + vertical privilege
- [ ] Verb confusion: GET vs POST vs PUT vs PATCH vs DELETE on the same resource
- [ ] Function-level (BFLA): admin-only routes callable with user token
- [ ] Mass-assignment: `role`/`isAdmin`/`accountId` aliases in JSON/`$set`
- [ ] GraphQL: field guessing, nested authz gaps, batching/alias abuse

## Common misses
| Miss | Why it matters |
|---|---|
| Detail vs list drift | List redacts fields that detail leaks |
| Numeric ID only | UUID/hash IDs still need cross-tenant checks |
| 403 on UI path | API twin may still authorize |
| "Works without auth" on docs | Confirm against production auth middleware |

## Proof standard
- Confirm with **cross-identity** differential: victim object readable/writable by attacker identity, compared to baseline denial.
- Status-code-only "success" without body/state change is insufficient.

## Vik wiring
- Pairs with `auth-bypass-idor`, `skills/playbooks/mass-assignment.md`, Hadrian/authz steps when enabled.

---
name: auth-bypass-idor
description: Focused auth-bypass + IDOR checklist — sibling rule, ID swap matrix, proof.
---

# Auth Bypass / IDOR

## Checklist
- [ ] Two accounts (A attacker, B victim); replay A's session with B's object IDs
- [ ] Every method: GET/PUT/PATCH/DELETE
- [ ] Sibling endpoints: `/admin/users` auth'd but `/admin/export` missing middleware
- [ ] API v1 vs v2; GraphQL `node(id:)`; WebSocket client-supplied IDs
- [ ] Parameter add `?user_id=`; client-side-only role checks

## Common bypasses
- Numeric/UUID swap; indirect IDOR via export/report IDs
- Method swap (PUT protected, DELETE open)
- Hidden fields / JWT role claims without server enforcement

## Proof standard
- Cross-account read/write of B's object with A's token (diff response content, not just 200).
- Missing auth on admin sibling = confirm by unauthenticated/low-priv access returning sensitive data.

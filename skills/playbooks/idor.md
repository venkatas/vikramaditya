---
name: idor
aliases: [idor, insecure-direct-object-reference, bola, broken-access-control]
tags: [access-control, owasp-a01, authorization, api]
severity: high
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/web-application-security/exploiting-idor-vulnerabilities/SKILL.md -->

# Insecure Direct Object Reference (IDOR / BOLA)

## When to Use
- Endpoints that reference objects by ID (numeric, UUID, slug, base64, hash).
- Multi-tenant apps where users must only access their own data.
- Validating object-level authorization across all CRUD operations.

## Critical Checks Most Often Missed
- **Unauthenticated access** (the single most missed IDOR): replay the request with NO cookie / NO token. APIs frequently leak objects entirely without auth.
- **Every reference, every method.** Path IDs, query params (`?id=`, `?user_id=`), body fields, JSON-nested IDs, and headers. Test GET/POST/PUT/PATCH/DELETE — read may be locked while write is not.
- **All ID encodings.** Numeric ±1, UUIDs (use a second account's real UUID), base64 (`MTAx`=101), hashes, slugs.
- **Wrapper / override tricks.** Parameter pollution (`?id=101&id=102`), arrays/bulk (`{"ids":[101,102]}`), wrapping a value in `[]`/`{}`, switching `Content-Type` to JSON, appending `.json`/`.xml`, and method-override headers (`X-HTTP-Method-Override`, `_method`) — authz is often enforced on one representation only.

## Validation / Confirm Steps
- **Two-account differential (definitive):** request User B's object id with User A's session; confirm the response returns **User B's data** (match a unique field — B's email/UUID/order total). Identical data for both = confirmed IDOR.
- **Unauthenticated:** if the object still returns with no session, that's a confirmed (higher-severity) IDOR.
- **Write IDOR:** re-read the object as User B to verify the change actually persisted — not just a 200.
- **Scale:** enumerate a small id range to prove it's systemic; record exactly which sensitive fields leak.

## False-Positive Traps
- A 200 alone is NOT confirmation — you must see *another principal's* data, not your own object echoed back.
- A 403 on the numeric `{id}` swap is NOT a clean negative — also try UUID/base64/hash encodings, the id in query/body/header positions, every method, parameter pollution, bulk wrappers, and `.json`/`.xml`.
- Guessing IDs without a second account yields false positives; register/obtain one.

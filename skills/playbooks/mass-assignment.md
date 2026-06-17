---
name: mass-assignment
aliases: [mass-assignment, mass_assignment, auto-binding, autobinding, mass-assign, bopla]
tags: [api, owasp-api3-2023, authorization, privilege-escalation, injection]
severity: high
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/api-security/testing-api-for-mass-assignment-vulnerability/SKILL.md -->

# Mass Assignment (Auto-Binding / OWASP API3:2023 BOPLA)

## When to Use
- JSON/form APIs that create or update objects by binding the request body straight onto a model (Rails `update_attributes`, Django `**request.data`, Mongoose `findByIdAndUpdate`, Spring `@ModelAttribute`).
- Any endpoint where the object has sensitive properties the UI does **not** expose (role, account balance, verification flags).
- Both **create** (`POST`) and **update** (`PUT`/`PATCH`) — the writable field set often differs between them.

## Critical Checks Most Often Missed
- **Privilege fields by every alias.** Add `role`, `roleId`, `isAdmin`, `is_admin`, `admin`, `is_superuser`, `is_staff`, `userType`, `account_type`, `permissions`, `scopes`, `groups` to the body even though the form never sends them.
- **Domain/business fields.** `subscription_plan`, `credit_limit`, `balance`, `discount_percent`, `price`, `verified`, `email_verified`, `kyc_status`, `tenant_id`, `organization_id` — money/tenancy fields are the high-impact ones.
- **Nested & framework-specific shapes.** `user[role]=admin` (Rails strong-params bypass), `{"user":{"isAdmin":true}}`, MongoDB operators (`{"$set":{"role":"admin"}}`), and dot-paths (`profile.role`).
- **Read the GET first.** Fetch the object, copy its FULL JSON (including read-only fields the API returns), flip the sensitive ones, and PUT it back — servers that whitelist on input but echo everything reveal the exact bindable field names.
- **Both directions.** A field may be locked on create but writable on update (or vice-versa) — test create AND update for each candidate.

## Validation / Confirm Steps
- **Persistence, not echo.** After the `PATCH`/`POST`, issue a **fresh GET** (ideally as a different/again-authenticated session) and confirm the privileged value actually stuck. A 200 that echoes your input proves nothing.
- **Effect check.** For `isAdmin`/`role`, confirm you can now reach an admin-only endpoint; for `balance`/`credit_limit`, confirm the new value is honored in a downstream operation (checkout, transfer).
- **Differential.** Compare the object before and after — exactly one privileged field changed = clean confirmation.

## False-Positive Traps
- A `200 OK` (or the field appearing in the response body) is **not** confirmation — many frameworks accept-and-ignore unknown keys. Re-GET to prove persistence.
- The server may store the field but enforce authorization elsewhere at use-time; verify the *effect*, not just the stored value.
- Some APIs reflect the whole request (including your injected key) without persisting it — never trust the immediate response alone.
- Don't conflate with IDOR: mass assignment changes *properties of an object you may legitimately own*; IDOR is accessing *another* object. Report the privilege impact precisely.

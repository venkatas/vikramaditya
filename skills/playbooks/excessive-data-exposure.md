---
name: excessive-data-exposure
aliases: [excessive-data-exposure, data-exposure, over-fetching, overfetching, excessive_data_exposure]
tags: [api, owasp-api3-2019, information-disclosure, owasp-api3-2023]
severity: medium
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/api-security/exploiting-excessive-data-exposure-in-api/SKILL.md -->

# Excessive Data Exposure (Over-Fetching / OWASP API3:2019)

## When to Use
- APIs that return a serialized object and rely on the **client** to hide fields (the classic "the mobile app only shows name+avatar, but the JSON also carries email, hash, and internal flags").
- List vs detail endpoints, GraphQL field selection, and any endpoint that accepts shaping params (`?fields=`, `?expand=`, `?include=`).
- After authenticating as a low-privilege user, to see what the backend over-shares.

## Critical Checks Most Often Missed
- **Read the raw JSON, not the rendered UI.** Enumerate every returned property — look for `password`, `passwordHash`, `salt`, `mfaSecret`, `totpSecret`, `ssn`, `aadhaar`, `pan`, `dob`, `salary`, `internalNotes`, `apiKey`, `token`, `isAdmin`, `resetToken`.
- **List vs detail drift.** A `/users/{id}` detail may scrub fields that `/users` (list) leaks for *every* user — and vice-versa. Compare both.
- **Representation/shaping params.** Try `?fields=*`, `?fields=password,role`, `?expand=owner`, `?include=payment_methods`, `?view=full`, `?format=json`, and `.json`/`.xml` suffixes — these often bypass the default serializer.
- **Nested-object flattening.** Expand related resources (`order.customer.creditCard`, `post.author.email`) — sensitive data hides one level down in embedded objects.
- **GraphQL field guessing.** With (or even without) introspection, request likely-sensitive fields directly: `{ user(id:1){ passwordHash mfaSecret email role } }` — field-level authz is frequently missing.
- **Error & debug leakage.** Trigger errors (bad type, missing field) and read stack traces / SQL / internal hostnames; check verbose headers (`X-Powered-By`, `X-Debug`, `Server`).

## Validation / Confirm Steps
- **Show the sensitive field with a value** in the response for a principal/object that should not expose it (e.g., another user's email/hash visible to a basic user). The presence of a real, populated sensitive value is the finding.
- **Scope of impact.** Demonstrate it's systemic — the list endpoint leaks the field for N users, not one — and record exactly which fields and which authz level.
- **Tie to a downstream attack** where possible (leaked `resetToken` → account takeover; leaked `apiKey` → authenticated calls).

## False-Positive Traps
- A field merely being **present but null/empty** for your own object is not a finding — you need a populated value you should not be able to see.
- Returning *your own* sensitive data (your own email on your own profile) is expected — the issue is exposing **other principals'** data or secrets the client should never receive.
- Public-by-design data (usernames on a public profile) is not excessive exposure — confirm the field is genuinely sensitive and unintended.
- Don't double-count with IDOR: if you accessed another object via a swapped ID, that's IDOR; excessive data exposure is over-sharing within a response you are *authorized* to fetch.

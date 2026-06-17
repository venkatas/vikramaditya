---
name: jwt
aliases: [jwt, jwt-attack, json-web-token]
tags: [jwt, authentication, token-forgery, owasp-a07, crypto]
severity: critical
---
<!-- Adapted from xalgorix (MIT) — internal/tools/skills/data/api-security/exploiting-jwt-algorithm-confusion-attack/SKILL.md -->

# JWT Attacks (alg confusion / none / key injection)

## When to Use
- APIs using JWTs for auth — check for `alg:none`, RS256→HS256 confusion, and `kid`/`jku`/`x5u` injection.
- Validating that the server enforces a fixed algorithm and does not trust the token header.

## Critical Checks Most Often Missed
- **Public-key format matters** for RS256→HS256 confusion — it fails silently unless the HMAC key bytes match the server's. Try PEM with/without trailing newline, with/without header lines, DER, and the X.509 cert form before giving up.
- **Reconstruct the key when JWKS is hidden** — derive the RSA public key from two captured tokens (e.g. `rsa_sign2n`) or pull it from the TLS cert.
- **`alg` casing and omission** — test `none`, `None`, `NONE`, `nOnE`, and a header with no `alg` at all, each with an empty and a dot-only signature.
- **Header-injection key sourcing** — `jku`/`x5u` pointing to attacker JWKS (URL-filter bypasses: `@`, `#`, open-redirect), `kid` path-traversal (`../../dev/null` → empty key) or SQLi.
- **Claim nuances** — match `iss`/`aud`/`exp`, then swap `sub`/`role`/`scope`; some servers ignore `role` but trust `sub` for lookup.

## Validation / Confirm Steps
- The forged token must return **authenticated data for a privileged identity you do not own** — e.g. an admin-only endpoint returns 200 with admin data — compared against an unauthenticated baseline.
- For `alg:none`, the modified-payload token (e.g. elevated `role`) must be accepted and grant the claimed privilege.

## False-Positive Traps
- "Token not rejected" ≠ confirmed — merely avoiding a 401 is not enough; you must access a privileged resource you couldn't before.
- Don't conclude negative until you've tried every public-key encoding for HS256 confusion, key reconstruction from captured tokens, all `none` casings with empty/dot signatures, and `jku`/`kid`/`x5u` injection when those headers are present.

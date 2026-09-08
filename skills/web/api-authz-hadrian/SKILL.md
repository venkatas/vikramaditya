---
name: api-authz-hadrian
description: Run Praetorian Hadrian for API BOLA/BFLA role-matrix authz when OpenAPI + roles/tokens are available. Complements schemathesis.
---

# API Authz — Hadrian

Use when the engagement has an **OpenAPI/Swagger (or GraphQL/gRPC) spec** and
**at least two roles with tokens**. Hadrian cross-tests every role against every
endpoint for BOLA / BFLA / BOPLA. Do **not** substitute it for Schemathesis
(schema conformance) or bac_matrix (HTTP replay matrix without a spec).

## Preconditions
- [ ] Spec path known (`openapi.yaml` / introspection / `.proto`)
- [ ] `roles.yaml` with privilege levels (admin > user > anon)
- [ ] `auth.yaml` with per-role bearer/API-key/cookie tokens (prefer env vars)
- [ ] Staging preferred — mutation templates may create/modify/delete resources
- [ ] Run `--dry-run` / `--hadrian-dry-run` once before live traffic

## Invoke
```bash
python3 hadrian_audit.py --protocol rest \
  --api "$SPEC" --roles roles.yaml --auth auth.yaml

# Orchestrator
python3 vikramaditya.py --hadrian "$SPEC" \
  --hadrian-roles roles.yaml --hadrian-auth auth.yaml
```

Example templates: `templates/hadrian/{roles,auth}.example.yaml`.

## Proof standard
- Cross-role access that returns **victim object data** (not just HTTP 200).
- For writes/deletes: Hadrian three-phase mutation VERIFY proves the change stuck.
- Map report via `tool_parsers.parse_hadrian_json` → status stays `suspected`
  until operator confirms with a replay PoC.

## Related
- `auth-bypass-idor` skill — manual IDOR checklist
- `bac_matrix` / `bfla_scanner` — in-tree HTTP authz without OpenAPI
- Schemathesis — property/schema conformance (not role authz)

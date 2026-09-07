# Hadrian config templates (Vikramaditya)

Praetorian [Hadrian](https://github.com/praetorian-inc/hadrian) (Apache-2.0) is
the optional API **authorization** tester. It complements Schemathesis (schema
conformance) and RESTler (stateful fuzz) with role-permutation BOLA/BFLA checks.

## Required inputs

| File | Purpose |
|------|---------|
| OpenAPI / GraphQL SDL / `.proto` | API surface |
| `roles.yaml` | Privilege levels + permissions (see `roles.example.yaml`) |
| `auth.yaml` | Per-role tokens / API keys / cookies (see `auth.example.yaml`) |

## Invoke via Vik

```bash
# Install once (also in setup.sh Go tools list)
go install github.com/praetorian-inc/hadrian/cmd/hadrian@latest

# REST
python3 hadrian_audit.py --protocol rest \
  --api openapi.yaml \
  --roles /path/to/roles.yaml \
  --auth /path/to/auth.yaml

# Or through the orchestrator
python3 vikramaditya.py --hadrian openapi.yaml \
  --hadrian-roles roles.yaml --hadrian-auth auth.yaml

# Dry-run first (no requests; mutation templates can modify data)
python3 vikramaditya.py --hadrian openapi.yaml \
  --hadrian-roles roles.yaml --hadrian-auth auth.yaml --hadrian-dry-run
```

## GraphQL / gRPC

```bash
python3 hadrian_audit.py --protocol graphql \
  --target https://api.example.com/graphql \
  --roles roles.yaml --auth auth.yaml

python3 hadrian_audit.py --protocol grpc \
  --target localhost:50051 --proto service.proto \
  --roles roles.yaml --auth auth.yaml
```

## Custom templates

Pass `--hadrian-templates DIR` / `--templates-dir DIR (maps to Hadrian --template-dir)` to load extra Hadrian YAML
templates beyond the built-in OWASP set.

## Output

`findings/<label>/hadrian/{report.json, findings.json, summary.json, hadrian.log}`

`findings.json` is normalized via `tool_parsers.parse_hadrian_json` (status=`suspected`).

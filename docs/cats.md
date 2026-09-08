# Endava CATS (opt-in OpenAPI negative fuzz)

Vikramaditya already covers OpenAPI via **Schemathesis** (property-based) and
**RESTler** (stateful). **CATS** (Contract API Testing and Security) adds
Endava's negative/boundary fuzzers (100+) with an HTML report — opt-in only;
never on the default scan path.

- Upstream: https://github.com/Endava/cats
- Docs: https://endava.github.io/cats/
- License: Apache-2.0

## Install

```bash
brew tap endava/tap && brew install cats
# or download native binary / uberjar from
# https://github.com/Endava/cats/releases
```

Optional env overrides:

| Env | Meaning |
|-----|---------|
| `CATS_BIN` | Path to the `cats` executable |
| `CATS_JAR` | Path to uberjar; wrapper runs `java -jar …` |

`setup.sh` only checks whether `cats` is on `PATH` (warn if missing).

## Auth / headers

CATS accepts:

- `-H Name=Value` on every path (wrapper `--header` / `--token`)
- `--headers path.yml` for per-path headers (wrapper `--headers-file`)

Examples:

```bash
# Bearer via convenience flag
python3 cats_audit.py --contract openapi.yml \
  --server https://api.example.com \
  --token "Bearer $TOK" --blackbox

# Explicit header (Name=Value or Name: Value)
python3 cats_audit.py --contract openapi.yml \
  --server https://api.example.com \
  --header "Authorization=Bearer $TOK" \
  --header "X-Api-Key=…"

# Per-path YAML (CATS format — path keys, header children)
python3 cats_audit.py --contract openapi.yml \
  --server https://api.example.com \
  --headers-file headers.yml
```

See https://endava.github.io/cats/docs/getting-started/api-authentication/

## Invoke

Standalone:

```bash
python3 cats_audit.py --contract openapi.yml --server https://api.example.com
python3 cats_audit.py --contract openapi.yml --server URL --blackbox --paths "/v1/users"
python3 cats_audit.py --contract openapi.yml --server URL --cats-arg "--maxRequestsPerMinute=30"
```

Via orchestrator (opt-in; exits after the CATS run like `--restler`):

```bash
python3 vikramaditya.py --cats openapi.yml \
  --cats-server https://api.example.com \
  --cats-token "Bearer $TOK" --cats-blackbox
```

## Artifacts

Reports land under `findings/<host>/cats/` (override with `--output-dir`):

| Path | Contents |
|------|----------|
| `index.html` | CATS HTML report |
| `cats-summary-report.json` | Native summary (`errors` / `warnings` / `testCases`) |
| `Test*.json` | Per-test JSON (replay: `cats replay TestN`) |
| `summary.json` | Wrapper metadata + parsed counts |
| `error_leads.json` | Compact list of `result=error` cases (when any) |

Parse an existing report without re-running:

```bash
python3 cats_audit.py --contract unused.yml --server unused \
  --parse-only findings/api.example.com/cats/
```

## Notes

- Prefer `--blackbox` (`-b -k`) against unknown APIs so only 5xx count as errors.
- Do **not** point CATS at production without explicit engagement approval.
- Complements, does not replace, Schemathesis / RESTler.

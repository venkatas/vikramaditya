# Specialist workflows

[Choose a workflow](../README.md#choose-your-workflow) · [API / MFA](#api-and-mfa-authentication) · [HAR replay](#har-based-testing) · [AWS](#aws-whitebox-assessments) · [Privacy proxy](#engagement-privacy-proxy)

Run these workflows only with written authorization for the hosts, accounts, credentials, and actions involved. Infrastructure scope-lock controls are not a general sandbox for every API, HAR, or cloud module.

Commands below run from the repository root with the project environment active. Example hosts and credentials are placeholders, not targets to scan. Treat tokens, TOTP secrets, HAR files, and generated evidence as sensitive; command-line values can appear in shell history or process listings even when application logs redact them.

## API and MFA authentication

[`autopilot_api_hunt.py`](../autopilot_api_hunt.py) supports login credentials, TOTP, bearer tokens, a second account, and caller-supplied endpoint inventories. Use dedicated test accounts with the roles required for the engagement.

### Login with TOTP

Mint codes from test-account secrets at login time:

```bash
python3 autopilot_api_hunt.py \
    --base-url https://app.example.com/api \
    --login-url auth/login \
    --auth-creds "vapt-admin@example.com:PasswordHere" \
    --totp-secret "$VAPT_MFA_ADMIN_TOTP_SECRET" \
    --auth-creds-b "vapt-user@example.com:PasswordHere" \
    --totp-secret-b "$VAPT_MFA_USER_TOTP_SECRET" \
    --frontend-url https://app.example.com \
    --output findings/example-vapt
```

If the login endpoint needs a workspace, tenant, or other metadata, supply it explicitly rather than changing target-specific fields in the code:

```bash
python3 autopilot_api_hunt.py \
    --base-url https://app.example.com/api \
    --login-url auth/login \
    --auth-creds "vapt-admin@example.com:PasswordHere" \
    --totp-secret "$VAPT_MFA_ADMIN_TOTP_SECRET" \
    --login-extra-json '{"loginSurface":"workspace"}'
```

When the server replies `requiresTotp: true` without a supplied secret/code, the autopilot fails rather than silently retrying with a non-MFA fallback.

### Use existing bearer tokens

Use tokens minted through the application's normal authorized login/MFA flow:

```bash
python3 autopilot_api_hunt.py \
    --base-url https://app.example.com/api \
    --auth-token "$ORG_ADMIN_TOKEN" \
    --auth-token-b "$ORG_USER_TOKEN" \
    --frontend-url https://app.example.com \
    --output findings/example-vapt
```

For focused two-account IDOR / privilege-escalation testing:

```bash
python3 api_idor_scanner.py \
    --base-url https://app.example.com/api \
    --token-a "$ORG_ADMIN_TOKEN" \
    --token-b "$ORG_USER_TOKEN" \
    --endpoints endpoints.json
```

### Supply known endpoints

`--endpoints-file` merges a caller-built inventory with discovered routes. Inventory metadata takes precedence, and paths are normalized against `--base-url`:

```bash
python3 autopilot_api_hunt.py \
    --base-url https://app.example.com/api \
    --auth-token "$ORG_ADMIN_TOKEN" \
    --auth-token-b "$ORG_USER_TOKEN" \
    --endpoints-file path/to/endpoints.json
```

## HAR-based testing

HAR workflows analyze captured browser requests and can actively replay them. Captures may include state-changing actions, third-party hosts, live tokens, and personal data. Authorize the actions to replay, not just the capture's primary domain.

### Capture and run

1. Open the authorized application with a dedicated test account.
2. Open browser DevTools → Network, log in, and visit the areas to assess.
3. Export the requests as a HAR file and store it securely.

```bash
# Analyze and test a capture
python3 har_vapt.py admin_session.har

# Or run the individual components
python3 har_analyzer.py session.har
python3 har_vapt_engine.py session_analysis.json

# Combined infrastructure + authenticated workflow
python3 vapt_companion.py --full example.com

# Interactive suite
python3 vapt_suite.py
```

### Set the complete host scope

The standalone [`har_vapt_engine.py`](../har_vapt_engine.py) defaults to the first-seen target host from the analysis. Repeated `--allow-host HOST` options **replace** that fallback; include every authorized host, including the primary target:

```bash
python3 har_vapt_engine.py session_analysis.json \
    --allow-host app.example.com \
    --allow-host api.example.com
```

Do not authorize analytics/CDN hosts merely because they appear in a capture. Engine AI follow-up is separately opt-in with `--with-brain`; it can generate and execute code and is not needed for the normal replay checks.

### Implemented probe families

| Family | Checks and limits |
|:--|:--|
| Injection | SQL injection, command injection, and SSTI response/evidence checks |
| Access control | Auth-stripped requests and object-reference probes |
| Files | LFI and multipart-upload checks; a successful upload alone does not prove RCE |
| XSS | Reflected-XSS checks, not a stored-XSS or DOM-browser test suite |
| Headers | Security-header observations |

These are probe families, not comprehensive detection guarantees. HAR replay does not provide dedicated NoSQL, session-hijacking, or chatbot tool-call/context-leak analysis. Review raw evidence before treating a probe label as exploitation proof. Retain or delete captures according to the engagement's data-handling policy.

## AWS whitebox assessments

[`whitebox/cloud_hunt.py`](../whitebox/cloud_hunt.py) combines AWS inventory, Prowler checks, PMapper IAM analysis, secret scanning, and correlation artifacts.

**Authorize AWS accounts/resources separately.** `--allowlist` controls Route53 domain intersection; it does not confine account-wide inventory, Prowler, IAM analysis, or secret access to that hostname. Neither this flag nor `--no-scope-lock` is a general AWS API sandbox.

Secret scanning uses heuristic bucket/log-group selection by default. Exhaustive selection is opt-in with `--secrets-mode exhaustive`; authorize the intended secret-reading mode explicitly.

### Run an assessment

```bash
python3 -m whitebox.cloud_hunt \
    --profile client-erp \
    --allowlist example.com \
    --session-dir recon/example.com
```

The main launcher can match a domain against `whitebox_config.yaml`. Interactive runs can offer the audit; autonomous runs require `whitebox.autonomous_default` in that configuration. For an explicit cloud-only assessment, use the standalone command above.

For multiple authorized profiles and explicitly selected regions:

```bash
PROWLER_TIMEOUT=7200 PMAPPER_TIMEOUT=3600 \
WHITEBOX_REGIONS=us-east-1,ap-south-1,eu-west-1 \
python3 -m whitebox.cloud_hunt \
    --profile client-erp --profile client-data \
    --allowlist example.com --allowlist example-data.invalid \
    --session-dir recon/example.com --refresh
```

`--allowlist` is required unless `--no-scope-lock` is passed. Only remove the Route53 intersection when the broader account/domain scope is authorized:

```bash
python3 -m whitebox.cloud_hunt \
    --profile client-erp --no-scope-lock \
    --session-dir recon/example.com
```

Region discovery normally filters to enabled regions, but errors can fall back to the SDK's available-region list. Set `WHITEBOX_REGIONS` when the engagement requires an explicit region set.

### Isolate cloud-tool dependencies

The macOS [`setup.sh`](../setup.sh) provisions and checks separate Prowler and PrincipalMapper environments. Their dedicated requirements conflict with the main scanner environment; do not merge them into it. The Prowler release pin is intentional because the parser is coupled to that release.

For manual provisioning, use a compatible interpreter. The installer prefers Python 3.11 when available:

```bash
python3.11 -m venv ~/.venvs/prowler
~/.venvs/prowler/bin/python -m pip install -r requirements-prowler.txt
~/.venvs/prowler/bin/python -m pip check
~/.venvs/prowler/bin/prowler --help

python3.11 -m venv ~/.venvs/pmapper
~/.venvs/pmapper/bin/python -m pip install -r requirements-pmapper.txt
~/.venvs/pmapper/bin/python -m pip check
~/.venvs/pmapper/bin/pmapper --help
```

See [`requirements-prowler.txt`](../requirements-prowler.txt) and [`requirements-pmapper.txt`](../requirements-pmapper.txt). Binary discovery checks `<TOOL>_BIN`, `~/.venvs/<tool>/bin/<tool>`, `~/.local/share/<tool>/bin/<tool>`, `/opt/<tool>/bin/<tool>`, then `PATH`. Missing/broken tools become failed phases and can produce a nonzero cloud-audit exit status.

Configure an authorized audit role with permissions for the selected checks. `ReadOnlyAccess` / `SecurityAudit` are starting points, not a guarantee of full coverage. Reading secret values needs additional permission such as `secretsmanager:GetSecretValue`; review denied calls and per-phase limitations.

### Cloud artifacts

With `--session-dir recon/example.com`, output is organized as:

```text
recon/example.com/cloud/
├── ACCOUNT_ID/
│   ├── inventory/       # Raw AWS inventory JSON
│   ├── prowler/         # OCSF JSON and compliance CSVs
│   ├── pmapper/         # IAM graph copy and command logs
│   ├── secrets/         # Redacted findings; sensitive evidence
│   ├── findings.json   # Normalized findings
│   └── manifest.json   # Phase status and TTL cache key
└── correlation/
    ├── asset_feed_ACCOUNT_ID.json
    └── asset_feed.json
```

## Engagement privacy proxy

The optional [`llm_anon/`](../llm_anon/) proxy applies best-effort regex redaction to supported request-body strings and restores mapped surrogates in responses, including streaming responses. The normal scanner does **not** automatically route all AI traffic through it.

**This is not a confidentiality or NDA-compliance boundary.** Headers, query strings, opaque binary bodies, and unrecognized sensitive content can pass through. Regex redaction does not eliminate content, timing, or query-pattern correlation. Use only approved providers/data and inspect what can leave the host.

Install the proxy's optional dependencies if needed:

```bash
python3 -m pip install fastapi uvicorn httpx
```

Use two terminals:

```bash
# Terminal 1: start the proxy (loopback port 8080 by default)
export ENGAGEMENT_ID=acme-2026-vapt
python3 -m llm_anon.proxy

# Terminal 2: configure the client to use it
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ENGAGEMENT_ID=acme-2026-vapt
# Client authentication is forwarded from incoming auth headers.
export ANTHROPIC_API_KEY=sk-ant-...
claude
```

Illustrative mapping; actual surrogates depend on the engagement vault:

| Location | Example text |
|:--|:--|
| Upstream body | `nmap scan of 203.0.113.47 on xkqpzt.pentest.local returned OpenSSH 8.2` |
| Restored response | `nmap scan of 10.20.0.10 on dc01.acmecorp.local returned OpenSSH 8.2` |

Mappings persist in `~/.vikramaditya/anon_vault.db`, scoped by `ENGAGEMENT_ID`. Protect the vault and local proxy access; use distinct engagement IDs. `/anon` is a repository command reference, not a system shell command.

Design credit: [zeroc00I/LLM-anonymization](https://github.com/zeroc00I/LLM-anonymization).

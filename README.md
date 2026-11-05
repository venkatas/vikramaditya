# Vikramaditya

Evidence-first vulnerability assessment for authorized infrastructure, web, and API engagements.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](requirements.txt)
[![Tests](https://img.shields.io/badge/tests-pytest-blue.svg)](#testing)
[![Changelog](https://img.shields.io/badge/releases-changelog-green.svg)](CHANGELOG.md)

Run reconnaissance and vulnerability checks, optionally add AI-assisted analysis, and produce Burp-style HTML and Markdown reports. Session artifacts keep raw evidence, finding classifications, and recorded coverage limits available for review.

> Test only with written authorization. An exact hostname does not authorize its subdomains, redirects, third-party services, or associated cloud accounts. A completed scan is not proof that a target is secure.

[Quick start](#quick-start) · [Choose a workflow](#choose-your-workflow) · [Scope](#scope-and-coverage) · [Results](#reports-and-results) · [AI](#ai-configuration) · [Troubleshooting](#troubleshooting) · [Development](#development)

## Quick start

Commands below run from the repository root with the project environment active. Replace `example.com` with an authorized target and `SESSION_ID` with a real session ID.

### 1. Install

The bundled installer targets **macOS** and uses Xcode Command Line Tools, Homebrew, Go, and pip. It creates `.venv`, installs the main Python requirements, and provisions isolated Prowler/PrincipalMapper environments. Optional tools and backends may need additional setup.

```bash
git clone https://github.com/venkatas/vikramaditya.git
cd vikramaditya
bash setup.sh
source .venv/bin/activate
```

<details>
<summary>Linux: manual setup</summary>

`setup.sh` is not a Linux bootstrap script. Create a Python environment, then install the external tools required by your selected phases. Python dependencies alone do not provide full scan coverage.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Use [requirements.txt](requirements.txt) and the external tool lists in [setup.sh](setup.sh) as references.

</details>

### 2. Check readiness

```bash
python3 -m pip check
python3 hunt.py --status
python3 hunt.py --help
```

Review missing and unusable capabilities before scanning. A binary being installed does not mean its phase can run successfully; see [troubleshooting](#troubleshooting).

### 3. Run an exact-host, tools-only assessment

```bash
python3 hunt.py --target example.com --full --scope-lock --no-brain
```

This is an active assessment. It excludes `www.example.com` and other subdomains. `--full` selects the phase checklist, not unlimited or exhaustive coverage; `--no-brain` avoids model inference. Read the [scope limits](#scope-and-coverage), then review the final status and [session artifacts](#session-artifacts).

To add AI, [configure a backend](docs/ai-configuration.md) and omit `--no-brain`.

## Choose your workflow

| Your task | Entry point | Details |
|:--|:--|:--|
| Explicit infrastructure assessment: FQDN, IP, or CIDR | `hunt.py` | [Common commands](#common-commands) |
| Fingerprint a target and select an engine | `vikramaditya.py` | [Launcher behavior](#launcher-behavior) |
| Authenticated API assessment with tokens, credentials, or MFA | `autopilot_api_hunt.py` | [API/MFA guide](docs/specialist-workflows.md#api-and-mfa-authentication) |
| Analyze and replay a captured browser session | `har_vapt.py` / `har_vapt_engine.py` | [HAR guide](docs/specialist-workflows.md#har-based-testing) |
| Separately authorized AWS account assessment | `python3 -m whitebox.cloud_hunt` | [AWS guide](docs/specialist-workflows.md#aws-whitebox-assessments) |

Scope and safety controls differ between entry points. The exact-host infrastructure controls below are not a general sandbox for every API, HAR, cloud, or AI-generated action.

### Common commands

```bash
# Resume an existing session; recon completion markers can be reused
python3 hunt.py --target example.com --resume SESSION_ID --full --scope-lock --no-brain

# Reuse recon without rerunning it
python3 hunt.py --target example.com --resume SESSION_ID --scan-only --full --scope-lock --no-brain

# Use a complete, explicitly authorized host list (implies scope lock)
python3 hunt.py --target example.com --targets-file authorized-hosts.txt --full --no-brain

# Assess an explicitly authorized subnet
python3 hunt.py --target 192.168.1.0/24 --full --no-brain
```

`--resume` reuses session data; it does not automatically skip every completed non-recon phase. Use `--skip` only for work actually performed and retain its evidence. Hunt-memory journals and repository slash-command references are separate from `hunt.py` session-resume state.

Failed archive/crawler and port-scan attempts retain diagnostics and partial evidence, but do not create clean completion markers. Resume retries those attempts rather than trusting a nonempty partial result file.

### Launcher behavior

```bash
python3 vikramaditya.py example.com --scope-lock
python3 vikramaditya.py https://app.example.com --scope-lock --creds "user:password"
```

The launcher selects autonomous routing when the configured Ollama daemon is reachable and has an installed model. Applicable branches enable brain supervision and the active brain scanner. Without a usable Ollama inventory, the launcher uses interactive routing and disables launcher AI; configuring another provider alone does not change that decision.

In autonomous mode, missing `--creds` means an unauthenticated assessment, not a credentials prompt. The launcher accepts `--scope-lock` and `--no-scope-lock` and forwards the choice on its infrastructure/hunt path. **Do not assume a bare run is locked.**

Use `python3 vikramaditya.py --help` for point tools and additional flags. Treat command-line credentials as sensitive: shell history and process listings can expose them.

## Scope and coverage

### Define the authorized surface

With `--scope-lock`, `example.com` does **not** include `www.example.com`, any other subdomain, or a different host reached by a redirect. Non-default active web ports must be explicitly authorized.

For an engagement covering several hosts, `authorized-hosts.txt` can contain:

```text
example.com
www.example.com
api.example.com:8443
```

With a host list, `--target` supplies the session label; it does not authorize hosts missing from that list. Certificate SANs and archive discoveries remain passive evidence rather than expanding execution scope. Missing or empty scope authority fails closed on the guarded scan-only/resume paths.

### Understand the trade-offs

| Path | Exact-host behavior and coverage limit |
|:--|:--|
| Crawling / HTTP probes | Destinations and redirects are checked before requests; discovered links cannot authorize another host. |
| Nuclei | Locked runs append `-dr`, disabling **all** redirects, including same-authority redirects. Redirect-dependent templates have partial coverage; conflicting follow-redirect configuration fails closed. |
| Browser work | Locked screenshots/forms use guarded Playwright, not unrestricted Gowitness or LLM navigation. Off-scope resources and unsupported transports are blocked. LLM-driven browser validation remains partial/unavailable. |
| Form / parameter discovery | POST form fetching uses static scoped HTTP, not JavaScript rendering. GET and POST Arjun probes use the bundled small wordlist and disabled redirects when locked. POST uses one worker with a six-second delay and a five-URL default cap; `ARJUN_POST_MAX_URLS=0` removes that probe cap. Known POST actions are prioritized, and caps/failures remain explicit coverage gaps. |

`--full` does not enable destructive, discovered-credential, or unsafe-browser opt-ins. Tool availability, phase caps, timeouts, and scope still limit coverage. Ctrl-C/timeouts tear down owned subprocess groups; interrupted artifacts are not a completed assessment.

SQLmap does not repeat a POST discovery attempt already made in the same invocation.
A later invocation can retry a failed attempt; failure never writes a successful
completion marker. MIME-qualified extensionless HTML pages are eligible for form
discovery. New query/API inputs invalidate autonomous core-scan completion, and
unconsumed work remains visible when the step budget is exhausted.

These controls are **not a general-purpose command sandbox**. The post-recon `brain/scan_plan.sh` is saved for manual review, not automatically run by that hook. Inspect its scope and actions before executing it.

### Browser prerequisites

The guarded backend needs context-level HTTP and WebSocket interception. If those controls are unavailable, it fails closed and records a coverage gap.

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
```

## Reports and results

Review evidence and coverage before delivering a report. HTML/Markdown can contain classified findings, configuration observations, and informational or unconfirmed context; these are not interchangeable.

### Session artifacts

`hunt.py` keeps matching session IDs across three trees:

```text
recon/<target>/sessions/<id>/
├── scope/allow.txt          # Exact-host authority, when applicable
├── live/                   # Probe results, exit records, completion markers
├── urls/                   # URL corpus; GF diagnostics in urls/gf/diagnostics/
├── screenshots/            # Guarded pages, screenshots, blocked-request records
├── params/                 # Static forms and Arjun discovery
└── brain/                  # Optional analysis and review-only scan plan

findings/<target>/sessions/<id>/
├── phase_manifest.json
├── coverage.json
├── coverage_degraded.json
└── manual_review/coverage_gaps.txt

reports/<target>/sessions/<id>/
├── vapt_report.html
└── vapt_report.md
```

Artifact presence depends on the phases and backend used. Regenerating a report does not refresh evidence or prove that skipped phases ran.

### Assessment status

Synchronous `hunt.py` pipelines and bounded `--autonomous` runs fold the shared manifest/coverage assessment into their final result. Failed, aborted, or degraded coverage produces **INCONCLUSIVE**, including recorded gaps retained on resume or found in sibling recon artifacts. Autonomous sessions save that final status even when a resume executes no new steps. Report rendering uses the coverage available when it runs; a later report-generation failure also makes the final CLI result inconclusive.

| Exit code | Meaning for a synchronous or bounded autonomous pipeline |
|:--|:--|
| `0` | No recorded assessment failure or coverage gap; not proof of a vulnerability-free target |
| `2` | Inconclusive assessment; inspect the coverage artifacts |
| `130` | Interrupted with SIGINT; partial artifacts are not completion |

Other point-tool modes and usage errors can have different exit meanings. A report-rendering command can succeed while rendering an inconclusive assessment. A successfully completed zero-finding phase is not itself a failure. Failed coverage persistence is retained as an in-memory failure signal, even if a file-only report cannot show the unwritten limitation.

Existing malformed or unreadable coverage is an integrity failure, not an empty
result. Atomic repairs retain corrupt bytes in `.corrupt.<sha256>` backups when
replacement is possible. API coverage distinguishes attempted requests from
completed HTTP responses; transport failures remain visible even with zero findings.

Reports use recorded session execution evidence rather than assuming that manual
testing, AI analysis, exploitation, or every installed tool was used. Unavailable
or incompatible finding scores display `N/A`; explicit recorded scores are retained.

Counts use supported parsers and classification/proof gates, not raw lines, dictionary keys, file counts, or model prose. Exact duplicate observations are removed while distinct parameters, CVEs, and evidence remain separate. `classified_findings` can include configuration observations: it is **not** an exploitation-confirmed count.

### Regenerate or export a report

```bash
python3 reporter.py findings/example.com/sessions/SESSION_ID/ \
    --client "Acme Corp" --consultant "Your Name"

# SARIF is the standalone exporter's default format
python3 saf_export.py findings/example.com/sessions/SESSION_ID/ -o report.sarif
```

Successful report generation emits HTML and Markdown. PDF conversion is attempted when `wkhtmltopdf` is available; check its outcome separately. HDF/ASFF exports require MITRE SAF; see [export formats and prerequisites](docs/saf-export.md).

## AI configuration

AI is optional. The implemented backends are Ollama, MLX, MLX-VLM server, Anthropic, OpenAI, xAI, and Gemini. Provider availability, model selection, and launcher routing are separate concerns.

The per-machine `~/.config/vikramaditya/brain.env` file **overrides inherited environment values** for allowlisted keys. `BRAIN_ENV_FILE` selects another file; `BRAIN_ENV_NOLOAD=1` bypasses it. Inspect startup provider/model messages instead of assuming an environment assignment took effect.

The [AI configuration guide](docs/ai-configuration.md) covers backend connections, a local MLX-VLM example, Ollama role pins, strict pin failures, fallback behavior, and historical benchmark limitations. There is no repository-wide best-model or hardware-fit guarantee.

Model output is not vulnerability evidence. Review generated actions and findings, and send engagement data only to approved providers. The optional privacy proxy is best-effort body redaction, **not** a confidentiality boundary; [read its limitations](docs/specialist-workflows.md#engagement-privacy-proxy).

## Troubleshooting

| Symptom | What to check |
|:--|:--|
| Report says `INCONCLUSIVE`, or a synchronous scan exits `2` | Review `phase_manifest.json`, `coverage.json`, `coverage_degraded.json`, and `manual_review/coverage_gaps.txt`; fix the recorded limitation before relying on a negative result. |
| Apex host redirects to `www` and coverage is partial | The hosts are separate scope entries. Add `www` only if it is explicitly authorized; otherwise keep the block and report the limitation. |
| HTTPX / DNSX / Nuclei / Katana is installed but unusable | Check executable identity/readiness with `tool_resolution.py`; a shadowing or crashing binary is not operational coverage. |
| GF output contains errors instead of URLs | Require tomnomnom's matcher and the requested patterns, not the unrelated GoFrame CLI. Inspect `urls/gf/diagnostics/`. |
| Browser phase is unavailable | Install Playwright/Chromium in the active environment and confirm required interception support. |
| AI is slow or uses an unexpected backend/model | Review `brain.env` file precedence and startup messages. For tools-only infrastructure work, use `--no-brain`. |
| AWS checks fail despite a domain allowlist | Domain filtering is not account authorization. Check audit-role permissions, regions, isolated tools, and the [AWS guide](docs/specialist-workflows.md#aws-whitebox-assessments). |

```bash
python3 tool_resolution.py httpx
python3 tool_resolution.py gf
```

The shared resolver runs bounded identity probes for ProjectDiscovery HTTPX, DNSX, Nuclei, and Katana. A healthy Go install keeps precedence; a crashing/shadowed binary can fall back to a healthy Homebrew keg or later `PATH` entry. Shell execution pins these tools by absolute path and preserves the invoking Python environment.

## Architecture

| Component | Responsibility |
|:--|:--|
| [hunt.py](hunt.py) | Infrastructure phase orchestration and session lifecycle |
| [vikramaditya.py](vikramaditya.py) | Fingerprinting, engine routing, and point-tool CLI |
| [recon.sh](recon.sh) / [scanner.sh](scanner.sh) | Reconnaissance and vulnerability-scanning pipelines |
| [brain.py](brain.py) / [brain_scanner.py](brain_scanner.py) | Optional AI analysis and active code-generation workflow |
| [scoped_http.py](scoped_http.py) / [scoped_browser.py](scoped_browser.py) / [nuclei_scope.py](nuclei_scope.py) | Guarded network paths and scope-related coverage recording |
| [tool_resolution.py](tool_resolution.py) / [tool_runtime.sh](tool_runtime.sh) | Executable identity, health checks, and runtime pins |
| [phase_manifest.py](phase_manifest.py) / [reporter.py](reporter.py) | Phase/coverage aggregation and report generation |

Infrastructure checks include injection probes, CVE/template checks, exposure/configuration checks, and selected framework checks, subject to installed tools and phase selection. API/HAR probe families and their limits are documented in the [specialist guide](docs/specialist-workflows.md). Supported detector outputs still require operator validation.

Successful scoped endpoint discoveries feed the canonical HTML, JavaScript, parameter, and API inputs before dependent checks run. Authentication/catchall responses, redirects, binary assets, and off-scope URLs are not promoted as application pages. Autonomous runs invalidate dependent completion state when new inputs arrive and report unfinished follow-up work if the step budget expires.

## Documentation and integrations

| Guide | Contents |
|:--|:--|
| [AI configuration](docs/ai-configuration.md) | Providers, model pins, configuration precedence, benchmarking |
| [Specialist workflows](docs/specialist-workflows.md) | API/MFA, HAR, AWS, and privacy proxy |
| [Recon enrichment](docs/recon-enrichment.md) | uncover, tlsx, waymore, xnLinkFinder and opt-ins |
| [CATS](docs/cats.md) / [Hadrian](templates/hadrian/README.md) | Optional OpenAPI fuzzing and role-based API authorization checks |
| [Supply-chain and evidence helpers](docs/gitleaks-syft-bagit.md) | Gitleaks SARIF, Syft SBOM, BagIt evidence packs |
| [SARIF / HDF / ASFF](docs/saf-export.md) | Machine-readable report exports |
| [MCP facade and session cache](docs/hexstrike-patterns.md) | Narrow opt-in integrations and their limits |
| [Web3 references](web3/README.md) | Manual audit material; `token_scanner.py` is source-regex heuristics, not bytecode/on-chain analysis |
| [Changelog](CHANGELOG.md) | Release history and dated integration notes |

Additional helpers include [CI/CD checks](cicd_scanner.sh), [email posture checks](email_audit.py), and [lifecycle metadata](eol_check.py). Lifecycle `unknown`/`no_data` or a versionless inference does not establish support for a deployed version. Retain the embedded endoflife.date attribution when redistributing its metadata.

Optional integrations have separate prerequisites; `--full` does not enable every module in this repository.

## Development

Keep documentation aligned with CLI/default changes. Add focused regressions for changed behavior, preserve user-local configuration, and never include engagement secrets or live client results in examples.

### Testing

```bash
source .venv/bin/activate
python3 -m pip install -r requirements.txt pytest
```

Focused scope/runtime/reporting regressions:

```bash
PYTHONDONTWRITEBYTECODE=1 BRAIN_ENV_NOLOAD=1 python3 -m pytest -q -rs -p no:cacheprovider \
    tests/test_scoped_http_redirects.py tests/test_recon_active_scope.py \
    tests/test_scoped_browser.py tests/test_nuclei_scope_guard.py \
    tests/test_tool_resolution.py tests/test_gf_resolution.py \
    tests/test_scoped_form_discovery.py tests/test_arjun_runtime_contract.py \
    tests/test_artifact_finding_count.py tests/test_reporter_exact_duplicates.py \
    tests/test_assessment_status_consistency.py tests/test_phase_manifest_coverage.py \
    tests/test_assessment_finalization.py tests/test_autonomous_assessment_status.py \
    tests/test_watched_command_accounting.py tests/test_no_brain_browser_policy.py \
    tests/test_discovery_feedback.py tests/test_hunt_discovery_feedback.py \
    tests/test_recon_failure_completion.py tests/test_cve_fallback_and_nested_coverage.py \
    tests/test_post_and_discovery_regressions.py tests/test_pipeline_and_phase_status.py \
    tests/test_report_accuracy_regressions.py tests/test_coverage_integrity_regressions.py \
    tests/test_secret_phase_activity.py \
    tests/test_interrupt_cleanup.py
```

These checks use fixtures/local servers. Native controls require usable Nuclei and Playwright/Chromium installations; review skips with `-rs`. An installed but unusable backend may fail instead of skipping.

Full suite, in a configured development environment:

```bash
env -u BRAIN_ENV_NOLOAD PYTHONDONTWRITEBYTECODE=1 BRAIN_ENV_FILE=/dev/null WHITEBOX_SMOKE=0 \
    python3 -m pytest -q -rs -p no:cacheprovider tests/
```

Use the output for your current checkout/environment as the test result; this README does not publish a fixed passing-test count.

## Responsible use and support

Obtain written authorization, use dedicated test accounts where possible, follow the agreed scope and disclosure process, and protect HAR files, tokens, findings, and raw evidence. Apply the engagement's encryption and retention requirements.

This tool is not a certification of OWASP, NIST, or CERT-In coverage. The operator owns methodology selection, evidence validation, untested-control reporting, client sign-off, and remediation retesting.

MIT license: [LICENSE](LICENSE). Report bugs or contribute through [GitHub issues and pull requests](https://github.com/venkatas/vikramaditya/issues). Contact: [venkat.9099@gmail.com](mailto:venkat.9099@gmail.com). Authorized testing only; developers assume no liability for misuse.

Inspired by [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty).

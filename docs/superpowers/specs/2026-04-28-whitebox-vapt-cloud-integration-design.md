# Vikramaditya Whitebox VAPT — Cloud Integration Design

**Date:** 2026-04-28
**Author:** Venkata Satish Guttula
**Status:** Draft — pending user review

## Summary

Transform Vikramaditya from a blackbox VAPT platform into a hybrid blackbox+whitebox tool by adding AWS-aware cloud auditing, IAM blast-radius analysis, secrets scanning, and bidirectional correlation between blackbox findings and cloud context.

The whitebox layer ships as a self-contained `whitebox/` Python package, integrates into `vikramaditya.py` as an auto-detected phase, and feeds discovered/tagged assets back into the existing `hunt.py` blackbox engine. The Ollama LLM (existing `brain.py`) orchestrates phase planning, target selection, chain filtering, and narrative generation. Every finding still traces to a deterministic rule (Prowler check ID, PMapper edge, regex, SG rule) — brain decides what to look at and how to narrate, never invents findings.

## Engagement Context

- **Targets:** `adfactorspr.com` (AWS profile `adf-erp`, account `443370705278`), `pranapr.com` (AWS profile `adf-pranapr`, account `591335425990`).
- **AWS access:** Both profiles authenticated as `venkata.satish-audit` with `ReadOnlyAccess` + `SecurityAudit` managed policies.
- **Authorization:** VAPT engagement conducted on behalf of a CERT-In empanelled company with written client authorization.
- **Account-to-domain model:** **Multi-domain per account** — Route53 zones are enumerated per account, every zone in an account is treated as in-scope automatically. Both accounts may host multiple domains; tool tags every finding with source account ID.

## Decisions Locked During Brainstorming

| # | Decision | Choice |
|---|---|---|
| Q1 | Whitebox scope | **Full whitebox**: cloud audit + asset correlation + insider analysis + cross-correlation with blackbox findings |
| Q2 | Account ↔ domain mapping | **Multi-domain per account** via Route53 zone enumeration |
| Q3 | Module shape | Standalone `whitebox/` package + plugin into `vikramaditya.py` orchestrator |
| Q4 | Report integration | One consolidated report with new "Cloud Posture" chapter; correlation rendered inline next to affected blackbox finding; raw inventory dumped to JSON |
| Q5 | Audit engine | Wrap **Prowler v4** for breadth of checks; build correlation/IAM/secrets/asset-feed as value-add |
| Q6 | IAM analysis depth | **PMapper full graph** for principal authorization graph + reachability + blast radius |
| Q7 | Secrets scanning | **Aggressive**: env vars, user-data, S3 bucket contents, CodeCommit, CloudWatch logs, AMI/EBS tags, plus decrypted SSM SecureStrings and `secretsmanager:GetSecretValue` (requires permission expansion) |
| Q8 | Asset feed to blackbox | **Tagged exposure surface**: full public attack surface + per-asset tags (internet-reachable, behind-WAF, TLS valid, exposed ports, exposed CIDRs); `hunt.py` prioritizes actually-reachable assets |
| Q9 | Cross-correlation | **Auto-chained findings with severity promotion** + inline PMapper graph in chain narrative |
| Q10 | Execution model | Sequential single-process per account, with per-phase manifest cache (24h TTL, `--refresh` to bust) |
| Q11 | Brain role | **Brain orchestrates everything**: phase planning, target selection, chain filtering, narrative generation. Defensibility constraint: brain never invents findings or alters severity without citing the underlying deterministic rule. |

## Architecture

### Package layout

```
whitebox/
├── __init__.py
├── cloud_hunt.py            # Top-level CLI + library entrypoint
├── orchestrator.py          # Phase orchestration (calls brain at every decision point)
├── profiles.py              # AWS profile/account/zone mapping & permission probing
├── inventory/
│   ├── __init__.py
│   ├── collector.py         # boto3 inventory pull (parallelized by region within phase)
│   ├── route53.py           # Zone enumeration → in-scope domain set per account
│   └── normalizer.py        # Cloud-agnostic Asset model
├── audit/
│   ├── __init__.py
│   ├── prowler_runner.py    # Subprocess wrapper, OCSF JSON parser
│   └── normalizer.py        # Prowler findings → vikramaditya Finding model
├── iam/
│   ├── __init__.py
│   ├── pmapper_runner.py    # PMapper graph build wrapper
│   ├── graph.py             # Graph queries: reachable_from, can_reach, blast_radius
│   └── privesc.py           # Privesc path detection + ranking
├── secrets/
│   ├── __init__.py
│   ├── scanner.py           # Multi-source secret extraction coordinator
│   ├── sources/
│   │   ├── lambda_env.py
│   │   ├── ssm.py           # Plaintext + decrypted SecureString (per-key probe)
│   │   ├── secretsmanager.py # Metadata + GetSecretValue (permission-gated)
│   │   ├── s3.py            # Brain-selected bucket contents
│   │   ├── cloudwatch_logs.py
│   │   ├── ec2_userdata.py
│   │   ├── ecs_taskdefs.py
│   │   ├── codecommit.py
│   │   ├── ami_ebs_tags.py
│   │   └── cloudformation.py
│   ├── detectors.py         # Regex + entropy patterns (truffleHog set + AWS/JWT/private-key)
│   └── redactor.py          # HTML-safe redaction (first/last 4 chars + length + ARN)
├── exposure/
│   ├── __init__.py
│   ├── analyzer.py          # SG/NACL/WAF reachability analysis
│   └── tagger.py            # internet-reachable, behind-WAF, exposed ports/CIDRs
├── correlator/
│   ├── __init__.py
│   ├── asset_join.py        # Blackbox host ↔ cloud asset matching
│   ├── chain_builder.py     # Auto-chain blackbox finding + IMDS check + IAM blast radius
│   └── severity.py          # Chain-aware severity promotion (rule-traced)
├── brain/
│   ├── __init__.py
│   ├── orchestrator.py      # Brain-driven phase planner; calls existing brain.py
│   ├── prompts.py           # System/task prompts per decision point
│   └── trace.py             # Audit log of every brain decision
├── cache/
│   ├── __init__.py
│   └── manifest.py          # 24h TTL phase cache, --refresh support
├── reporting/
│   ├── __init__.py
│   ├── posture_chapter.py   # New "Cloud Posture" HTML chapter
│   ├── correlation_inline.py # Cloud context renderer for blackbox findings
│   └── evidence.py          # JSON evidence file emission
└── tests/
    ├── unit/                # pytest with moto mocking
    ├── fixtures/            # canned OCSF JSON, PMapper graphs, brain responses
    └── smoke/               # opt-in real-account tests
```

### Integration touch points (minimal edits to existing code)

- `vikramaditya.py` — adds whitebox auto-detect: if a profile is configured for the target domain, offers cloud whitebox alongside blackbox.
- `hunt.py` — imports `whitebox.correlator.asset_join` to consume the prioritized asset feed; otherwise unchanged.
- `reporter.py` — imports `whitebox.reporting.posture_chapter` and `correlation_inline` to render the new chapter and inline cloud context.
- `brain.py` — unchanged. New `whitebox/brain/orchestrator.py` calls existing brain functions.
- New top-level config: `whitebox_config.yaml` mapping profile name → display name → in-scope domains (auto-populated from Route53 on first run, editable).

### External dependencies

Added to `requirements.txt`:
- `boto3` (AWS SDK)
- `prowler` (pinned version, OCSF JSON output)
- `principalmapper` (PMapper graph)
- `moto` (test-only)

Optional/deferred:
- `cloudsplaining` — explicitly deferred per Q6 decision; PMapper covers the same need with graph traversal.

### Session output structure

Extends existing `recon/<target>/sessions/<id>/` layout:

```
recon/<target>/sessions/<id>/cloud/
├── <account_id>/
│   ├── inventory/         # raw boto3 dumps per service per region (JSON)
│   ├── prowler/           # OCSF JSON output + parsed findings
│   ├── pmapper/           # graph.json + privesc paths + rendered PNG
│   ├── secrets/           # detected secrets (mode 0600), source-tagged
│   ├── exposure/          # SG analysis, internet-reachable assets
│   ├── findings.json      # normalized findings (vikramaditya model)
│   ├── brain_trace.jsonl  # every brain decision in this account
│   └── manifest.json      # phase cache TTLs
└── correlation/
    ├── asset_join.json    # blackbox host ↔ cloud asset map
    ├── chains.json        # auto-built exploit chains
    └── asset_feed.json    # prioritized asset list for hunt.py
```

## Data Flow

```
User runs: python3 vikramaditya.py
  └─> orchestrator detects whitebox-eligible target
      └─> python3 -m whitebox.cloud_hunt --profile adf-erp [--profile adf-pranapr]

For each AWS profile:
  1. profiles.validate()              → sts:GetCallerIdentity, list policies, probe critical perms
  2. inventory/route53.enumerate()    → in-scope domains derived from zones in account
  3. brain/orchestrator.plan_phases() → LLM picks region prio, service prio, scan depth
  4. CACHE CHECK (per phase, 24h TTL, --refresh busts)

  Phase A — Inventory (parallel by region within phase, sequential vs other phases)
     boto3 → cloud/<acct>/inventory/<service>/<region>.json
  Phase B — Prowler audit
     subprocess → OCSF JSON → audit/normalizer → normalized findings
  Phase C — IAM graph (PMapper)
     pmapper graph create → graph.json → privesc.detect_paths() → ranked paths
  Phase D — Exposure analysis
     SG/NACL/WAF → exposure/tagger → tagged asset list → asset_feed.json (for hunt.py)
  Phase E — Secrets scanning (brain selects targets from inventory)
     sources/* → detectors → redactor → secrets/findings + evidence (mode 0600)
  Phase F — Correlation
     asset_join (cloud assets ↔ existing blackbox findings if session has them)
     chain_builder (blackbox vuln + IMDS check + IAM blast radius → chain)
     severity.promote() → final severity per chain

  Phase G — Reporting
     posture_chapter.render() → HTML chapter
     correlation_inline.attach() → inline cloud context on blackbox findings
     evidence.dump() → JSON files for client audit trail

asset_feed.json → consumed by hunt.py on next blackbox run (or in same session if both ordered)
brain_trace.jsonl appended at every brain decision
```

### Brain decision points

Each brain call: prompt + structured context → JSON decision → logged to `brain_trace.jsonl` with input hash, model, timestamp, decision, downstream rule that fired.

| Phase | Brain decides |
|---|---|
| Plan | Which regions and services matter for this account? Scan depth per service. |
| Inventory | Which services to deep-pull vs sample? |
| Prowler | Which check groups to prioritize parsing? |
| Secrets | Which buckets / log groups / repos to scan based on naming, tags, size? |
| Correlation | Which candidate chains are real vs false-positive? |
| Report | Chain narratives, executive summary prose. |

## Component Contracts

### `whitebox/profiles.py`

```python
@dataclass
class CloudProfile:
    name: str                    # "adf-erp"
    account_id: str              # "443370705278"
    arn: str
    regions: list[str]           # all enabled regions
    in_scope_domains: list[str]  # from Route53 zones
    permission_probe: dict       # {"get_secret_value": True, "kms_decrypt": False, ...}

def load_profiles(config_path: Path) -> list[CloudProfile]
def validate(profile: CloudProfile) -> CloudProfile  # raises if STS fails
```

### `whitebox/inventory/collector.py`

```python
SERVICES = ["ec2", "s3", "iam", "rds", "lambda", "ecs", "eks", "elbv2",
            "apigateway", "apigatewayv2", "cloudfront", "route53",
            "ssm", "secretsmanager", "kms", "cloudtrail", "guardduty",
            "config", "wafv2", "sns", "sqs", "dynamodb", "stepfunctions",
            "codecommit", "ecr", "logs", "apprunner"]

def collect(profile: CloudProfile, services: list[str] = SERVICES) -> InventoryResult
# Writes per-service per-region JSON, returns manifest of what was collected
```

### `whitebox/audit/prowler_runner.py`

```python
def run(profile: CloudProfile, check_groups: list[str] | None = None) -> Path
def parse(ocsf_path: Path) -> list[Finding]
```

### `whitebox/iam/graph.py`

```python
class IAMGraph:
    def reachable_from(self, principal_arn: str) -> list[Path]
    def can_reach(self, principal_arn: str, target_arn: str) -> Path | None
    def blast_radius(self, principal_arn: str) -> BlastRadius
        # → buckets, kms keys, lambdas, roles, regions
    def render_subgraph(self, paths: list[Path]) -> Path  # PNG for inline report
```

### `whitebox/correlator/chain_builder.py`

```python
def build_chains(blackbox_findings: list[Finding],
                 cloud_assets: list[Asset],
                 iam_graph: IAMGraph) -> list[Chain]
# Chain = {trigger_finding, cloud_asset, iam_path, final_severity, narrative}
```

### `whitebox/brain/orchestrator.py`

```python
class BrainOrchestrator:
    def plan_phases(self, profile, inventory_summary) -> PhasePlan
    def select_secret_targets(self, inventory) -> list[ScanTarget]
    def filter_chains(self, candidate_chains) -> list[Chain]
    def write_executive_summary(self, findings, chains) -> str
    # Every method logs to brain_trace.jsonl
```

### Finding model (extends existing vikramaditya format)

```python
@dataclass
class Finding:
    id: str
    source: Literal["blackbox", "prowler", "pmapper", "secrets", "exposure", "chain"]
    rule_id: str           # MUST be present — defensibility constraint
    severity: Severity     # one of: Info, Low, Medium, High, Critical
    title: str
    description: str
    asset: Asset | None
    evidence_path: Path
    cloud_context: CloudContext | None  # account, region, service, ARN, IAM blast radius
    chain: Chain | None
    brain_narrative: str | None  # rendered separately, never affects severity
```

## Error Handling & Permissions

### Permission probing at startup

`profiles.permission_probe()` tests, recorded into `CloudProfile.permission_probe`:

- `sts:GetCallerIdentity` — required, hard fail if missing.
- `iam:SimulatePrincipalPolicy` — required for PMapper, soft fail → skip Phase C.
- `secretsmanager:GetSecretValue` — optional, soft fail → metadata-only mode.
- `kms:Decrypt` per key for SSM SecureStrings — soft fail → metadata-only per param.
- `s3:GetObject` per candidate bucket — soft fail → skip that bucket.
- `logs:GetLogEvents` — optional, soft fail → skip log scanning.

### Trust expansion note (re Q7)

`secretsmanager:GetSecretValue` is NOT in `ReadOnlyAccess` or `SecurityAudit`. Tool will:

1. Probe at startup; if denied, log a clear warning and fall back to metadata-only for that secret store (no crash).
2. Emit a "permission gap" line in the report listing exactly what the client needs to add to the audit user (`secretsmanager:GetSecretValue` on `Resource: "*"` or scoped) to enable full scanning.
3. All retrieved secret values are written ONLY to local session storage (`cloud/secrets/`) with mode 0600, redacted in HTML report (show first/last 4 chars + length + ARN), full value in JSON evidence file.

### Failure modes

| Failure | Behavior |
|---|---|
| AWS API throttling | Exponential backoff, retry up to 5x, then skip + warn |
| Region unreachable | Skip region, continue, note in manifest |
| Prowler subprocess crash | Capture stderr → `cloud/<acct>/prowler/error.log`, mark phase failed in manifest, continue with other phases |
| PMapper graph build timeout (>30 min) | Abort phase, fall back to Prowler IAM checks only, warn in report |
| Secrets scan finds 1000+ matches | Cap at 500/source, log "scan saturated — review targeting", continue |
| Brain (Ollama) unreachable | Fall back to deterministic defaults: scan everything, no narrative, no chain filtering. Findings still emit. |
| Cache corruption | Log + invalidate that phase + re-run |

### Hard guarantees

- No phase failure crashes the run.
- Every finding traces to a `rule_id` (Prowler check ID / PMapper edge type / regex name / SG rule).
- Brain failure = degraded report, never a missing finding.
- Secrets values written mode 0600, redacted in HTML, full only in evidence JSON.
- `--scope-lock` flag refuses to operate on assets outside discovered Route53 zones.
- Every finding tagged with source `account_id` to prevent cross-account scope bleed.

## Testing Strategy

- **Unit:** every module under `whitebox/` has pytest tests using `moto` for inventory, IAM graph, exposure analyzer, secret detectors, redactor, normalizer, asset-join, chain builder.
- **Integration:** end-to-end test against a moto-mocked account with seeded vulnerable config (public S3, overprivileged IAM role, SSM SecureString with fake AWS key, Lambda with hardcoded password in env). Asserts expected findings + chain.
- **Prowler runner:** test fixtures of canned OCSF JSON (no live Prowler call in unit tests).
- **PMapper:** test against a fixture graph JSON; do not invoke `pmapper` subprocess in unit tests.
- **Brain:** mock Ollama responses; assert prompts include required context, decisions logged to trace.
- **Real-account smoke test:** `tests/smoke/test_real_aws.py` (gated by env var, runs only with explicit opt-in) hits both `adf-erp` and `adf-pranapr` for sanity check during development.
- **Defensibility test:** scan every emitted Finding, assert `rule_id` is non-null and resolves to a known rule registry.

## Rollout

### Build order (becomes the implementation plan)

1. `whitebox/profiles.py` + `whitebox/cache/manifest.py` (foundation)
2. `whitebox/inventory/` (collector, Route53, normalizer)
3. `whitebox/audit/prowler_runner.py` (wraps Prowler)
4. `whitebox/exposure/` (SG/exposure tagger)
5. `whitebox/iam/` (PMapper wrapper + graph queries)
6. `whitebox/secrets/` (multi-source scanner)
7. `whitebox/correlator/` (asset join, chain builder, severity promotion)
8. `whitebox/brain/` (orchestrator, prompts, trace)
9. `whitebox/reporting/` (posture chapter, inline correlation)
10. `whitebox/cloud_hunt.py` (top-level CLI)
11. `vikramaditya.py` integration
12. `hunt.py` consume asset feed
13. `reporter.py` integration
14. End-to-end test on `adf-erp` + `adf-pranapr`

### Risks & mitigations

| Risk | Mitigation |
|---|---|
| Prowler version drift breaks OCSF parser | Pin Prowler version in `requirements.txt`; parser tests against fixed fixtures |
| PMapper graph build too slow on large accounts | 30-min timeout, fall back to Prowler IAM only, document in report |
| Secrets scan exposes real client secrets in evidence files | Mode 0600, dedicated `cloud/secrets/` dir, `.gitignore` enforced, redaction in HTML |
| Brain hallucinates findings | Architecture forbids brain emitting findings — only narrates findings emitted by deterministic rules. Tested via defensibility test. |
| `secretsmanager:GetSecretValue` denied → silent gap | Permission probe at startup + explicit "permission gap" line in report |
| Cross-account scope bleed | Route53 zone enumeration per account, `--scope-lock` flag, every finding tagged with source `account_id` |
| AWS throttling during full scan | Exponential backoff, sequential phase execution, optional `--regions` flag to narrow |

## Out of Scope

- Other cloud providers (GCP, Azure) — design intentionally AWS-only for v1.
- Write actions on AWS — strictly read-only audit; no remediation, no test-fix-verify.
- Container runtime introspection (kube-bench, falco) — Phase 2 if needed.
- CloudTrail anomaly detection — only ingest GuardDuty findings via Prowler in v1.
- Cost analysis — out of scope.

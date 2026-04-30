# Whitebox VAPT Cloud Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a self-contained `whitebox/` package that audits AWS accounts (`client-erp` → 111122223333, `example-example-data` → 444455556666), pulls IAM/secrets/exposure data, correlates with blackbox findings, and produces an integrated Burp-style HTML report.

**Architecture:** Sequential, brain-orchestrated, per-account pipeline. Wraps Prowler v4 (cloud audit), PMapper (IAM graph), and a custom secrets/exposure/correlation layer. Every finding traces to a deterministic rule. Brain (Ollama) plans phases, selects targets, filters chains, and writes narratives — never invents findings or alters severity without citing a rule.

**Tech Stack:** Python 3.11+, boto3, prowler (subprocess), principalmapper (subprocess), moto (test mocking), pytest, existing `brain.py` / `reporter.py` / `hunt.py`.

**Spec:** `docs/superpowers/specs/2026-04-28-whitebox-vapt-cloud-integration-design.md`

---

## File Structure (locked)

```
whitebox/
├── __init__.py
├── cloud_hunt.py
├── orchestrator.py
├── profiles.py
├── models.py                   # Asset, Finding, Chain, Severity, CloudContext
├── inventory/
│   ├── __init__.py
│   ├── collector.py
│   ├── route53.py
│   └── normalizer.py
├── audit/
│   ├── __init__.py
│   ├── prowler_runner.py
│   └── normalizer.py
├── iam/
│   ├── __init__.py
│   ├── pmapper_runner.py
│   ├── graph.py
│   └── privesc.py
├── secrets/
│   ├── __init__.py
│   ├── scanner.py
│   ├── detectors.py
│   ├── redactor.py
│   └── sources/
│       ├── __init__.py
│       ├── lambda_env.py
│       ├── ssm.py
│       ├── secretsmanager.py
│       ├── s3.py
│       ├── cloudwatch_logs.py
│       ├── ec2_userdata.py
│       ├── ecs_taskdefs.py
│       ├── codecommit.py
│       ├── ami_ebs_tags.py
│       └── cloudformation.py
├── exposure/
│   ├── __init__.py
│   ├── analyzer.py
│   └── tagger.py
├── correlator/
│   ├── __init__.py
│   ├── asset_join.py
│   ├── chain_builder.py
│   └── severity.py
├── brain/
│   ├── __init__.py
│   ├── orchestrator.py
│   ├── prompts.py
│   └── trace.py
├── cache/
│   ├── __init__.py
│   └── manifest.py
└── reporting/
    ├── __init__.py
    ├── posture_chapter.py
    ├── correlation_inline.py
    └── evidence.py

tests/whitebox/
├── unit/
│   ├── test_profiles.py
│   ├── test_cache_manifest.py
│   ├── test_models.py
│   ├── test_inventory_collector.py
│   ├── test_inventory_route53.py
│   ├── test_audit_prowler.py
│   ├── test_iam_graph.py
│   ├── test_iam_privesc.py
│   ├── test_secrets_detectors.py
│   ├── test_secrets_redactor.py
│   ├── test_secrets_sources_lambda.py
│   ├── test_secrets_sources_ssm.py
│   ├── test_secrets_sources_secretsmanager.py
│   ├── test_secrets_sources_s3.py
│   ├── test_secrets_sources_logs.py
│   ├── test_secrets_sources_ec2_userdata.py
│   ├── test_exposure_analyzer.py
│   ├── test_exposure_tagger.py
│   ├── test_correlator_asset_join.py
│   ├── test_correlator_chain_builder.py
│   ├── test_correlator_severity.py
│   ├── test_brain_trace.py
│   ├── test_brain_orchestrator.py
│   ├── test_reporting_posture_chapter.py
│   ├── test_reporting_correlation_inline.py
│   └── test_cloud_hunt_cli.py
├── integration/
│   ├── test_end_to_end_mocked.py
│   └── fixtures/
│       ├── prowler_ocsf_sample.json
│       ├── pmapper_graph_sample.json
│       └── brain_responses.json
└── smoke/
    └── test_real_aws.py        # gated by env var WHITEBOX_SMOKE=1

whitebox_config.yaml             # auto-generated on first run
requirements.txt                 # add boto3, prowler-cloud, principalmapper, moto
.gitignore                       # add cloud/secrets/, whitebox_config.local.yaml
```

---

## Task 0: Project bootstrap & dependencies

**Files:**
- Create: `whitebox/__init__.py`
- Create: `tests/whitebox/__init__.py`, `tests/whitebox/unit/__init__.py`, `tests/whitebox/integration/__init__.py`, `tests/whitebox/smoke/__init__.py`
- Modify: `requirements.txt`
- Modify: `.gitignore`

- [ ] **Step 1: Create empty package files**

```bash
mkdir -p whitebox/{inventory,audit,iam,secrets/sources,exposure,correlator,brain,cache,reporting}
mkdir -p tests/whitebox/{unit,integration/fixtures,smoke}
for d in whitebox whitebox/inventory whitebox/audit whitebox/iam whitebox/secrets whitebox/secrets/sources whitebox/exposure whitebox/correlator whitebox/brain whitebox/cache whitebox/reporting tests/whitebox tests/whitebox/unit tests/whitebox/integration tests/whitebox/smoke; do
  touch "$d/__init__.py"
done
```

- [ ] **Step 2: Add dependencies to `requirements.txt`**

Append to `requirements.txt`:

```
# ── Whitebox VAPT (AWS cloud integration) ────────────────────────────────────
boto3>=1.34.0
botocore>=1.34.0
prowler-cloud==4.5.0
principalmapper>=1.1.5
PyYAML>=6.0
# Test-only (already in dev environments, but pinned here for whitebox)
moto[all]>=5.0.0
```

- [ ] **Step 3: Update `.gitignore`**

Append to `.gitignore`:

```
# Whitebox VAPT — never commit secret evidence or per-machine config
recon/*/sessions/*/cloud/*/secrets/
whitebox_config.local.yaml
*.pmapper-graph.json
```

- [ ] **Step 4: Verify imports work**

Run: `python3 -c "import whitebox; import whitebox.inventory; import whitebox.iam; import whitebox.secrets.sources; import whitebox.brain"`
Expected: no output, no errors.

- [ ] **Step 5: Commit**

```bash
git add whitebox tests/whitebox requirements.txt .gitignore
git commit -m "feat(whitebox): bootstrap package structure and dependencies"
```

---

## Task 1: Core data models

**Files:**
- Create: `whitebox/models.py`
- Create: `tests/whitebox/unit/test_models.py`

- [ ] **Step 1: Write the failing test**

`tests/whitebox/unit/test_models.py`:

```python
from pathlib import Path
import pytest
from whitebox.models import (
    Severity, Asset, CloudContext, Finding, Chain, BlastRadius
)


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_finding_requires_rule_id():
    with pytest.raises(ValueError, match="rule_id"):
        Finding(
            id="f1", source="prowler", rule_id="",
            severity=Severity.HIGH, title="t", description="d",
            asset=None, evidence_path=Path("/tmp/x"),
        )


def test_finding_round_trip_to_dict():
    f = Finding(
        id="f1", source="prowler", rule_id="check_iam_root_mfa",
        severity=Severity.HIGH, title="Root MFA disabled",
        description="root user lacks MFA",
        asset=None, evidence_path=Path("/tmp/x"),
    )
    d = f.to_dict()
    assert d["rule_id"] == "check_iam_root_mfa"
    assert d["severity"] == "High"
    assert d["source"] == "prowler"


def test_chain_severity_promotion_documents_rule():
    c = Chain(
        trigger_finding_id="f1", cloud_asset_arn="arn:aws:ec2:...",
        iam_path=["arn:role/web", "arn:role/admin"],
        promoted_severity=Severity.CRITICAL,
        promotion_rule="chain.imdsv1+pass_role_to_admin",
        narrative="",
    )
    assert c.promotion_rule.startswith("chain.")


def test_blast_radius_aggregates():
    b = BlastRadius(
        principal_arn="arn:aws:iam::1:role/r",
        s3_buckets=["a", "b"], kms_keys=["k1"],
        lambdas=[], assumable_roles=["arn:role/admin"], regions=["us-east-1"],
    )
    assert b.total_resources() == 4


def test_asset_internet_reachable_default_false():
    a = Asset(arn="arn:aws:ec2:...", service="ec2", account_id="1",
              region="us-east-1", name="i-0abc", tags={})
    assert a.tags.get("internet_reachable") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_models.py -v`
Expected: FAIL with `ImportError: cannot import name 'Severity' from 'whitebox.models'`

- [ ] **Step 3: Implement `whitebox/models.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from pathlib import Path
from typing import Literal


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self) -> str:
        return {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}[self.value]


@dataclass
class Asset:
    arn: str
    service: str           # "ec2", "s3", "lambda", ...
    account_id: str
    region: str
    name: str              # logical identifier (instance id, bucket name, fn name)
    tags: dict             # mutable tag bag (internet_reachable, behind_waf, etc.)
    public_dns: str | None = None
    public_ip: str | None = None


@dataclass
class CloudContext:
    account_id: str
    region: str
    service: str
    arn: str
    iam_role_arn: str | None = None
    blast_radius: "BlastRadius | None" = None
    behind_waf: bool | None = None
    exposed_cidrs: list[str] = field(default_factory=list)
    exposed_ports: list[int] = field(default_factory=list)


@dataclass
class BlastRadius:
    principal_arn: str
    s3_buckets: list[str]
    kms_keys: list[str]
    lambdas: list[str]
    assumable_roles: list[str]
    regions: list[str]

    def total_resources(self) -> int:
        return len(self.s3_buckets) + len(self.kms_keys) + len(self.lambdas) + len(self.assumable_roles)


@dataclass
class Chain:
    trigger_finding_id: str
    cloud_asset_arn: str
    iam_path: list[str]               # ARNs in chain order
    promoted_severity: Severity
    promotion_rule: str               # e.g. "chain.imdsv1+pass_role_to_admin"
    narrative: str


@dataclass
class Finding:
    id: str
    source: Literal["blackbox", "prowler", "pmapper", "secrets", "exposure", "chain"]
    rule_id: str
    severity: Severity
    title: str
    description: str
    asset: Asset | None
    evidence_path: Path
    cloud_context: CloudContext | None = None
    chain: Chain | None = None
    brain_narrative: str | None = None

    def __post_init__(self):
        if not self.rule_id:
            raise ValueError("Finding.rule_id is required (defensibility constraint)")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label()
        d["evidence_path"] = str(self.evidence_path)
        return d
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/whitebox/unit/test_models.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add whitebox/models.py tests/whitebox/unit/test_models.py
git commit -m "feat(whitebox): core data models (Severity, Asset, Finding, Chain, BlastRadius)"
```

---

## Task 2: Phase cache manifest

**Files:**
- Create: `whitebox/cache/manifest.py`
- Create: `tests/whitebox/unit/test_cache_manifest.py`

- [ ] **Step 1: Write the failing test**

`tests/whitebox/unit/test_cache_manifest.py`:

```python
import json
import time
from pathlib import Path
from whitebox.cache.manifest import PhaseCache


def test_fresh_phase_returns_valid(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=3600)
    cache.mark_complete("inventory", artifacts={"file": "inventory/ec2.json"})
    assert cache.is_fresh("inventory")
    meta = cache.get("inventory")
    assert meta["artifacts"]["file"] == "inventory/ec2.json"


def test_expired_phase_returns_stale(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=1)
    cache.mark_complete("inventory")
    time.sleep(1.5)
    assert not cache.is_fresh("inventory")


def test_refresh_invalidates_all(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=3600)
    cache.mark_complete("inventory")
    cache.mark_complete("prowler")
    cache.refresh()
    assert not cache.is_fresh("inventory")
    assert not cache.is_fresh("prowler")


def test_corrupt_manifest_invalidates_phase(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=3600)
    cache.mark_complete("inventory")
    # corrupt the file
    (tmp_path / "manifest.json").write_text("{not json")
    cache2 = PhaseCache(tmp_path, ttl_seconds=3600)
    assert not cache2.is_fresh("inventory")


def test_failed_phase_is_not_fresh(tmp_path):
    cache = PhaseCache(tmp_path, ttl_seconds=3600)
    cache.mark_failed("prowler", error="subprocess crashed")
    assert not cache.is_fresh("prowler")
    assert cache.get("prowler")["status"] == "failed"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_cache_manifest.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/cache/manifest.py`**

```python
from __future__ import annotations
import json
import time
from pathlib import Path


class PhaseCache:
    """24h TTL phase cache. Stored as JSON manifest in <session>/cloud/<account>/manifest.json."""

    def __init__(self, account_dir: Path, ttl_seconds: int = 86400):
        self.account_dir = Path(account_dir)
        self.account_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.account_dir / "manifest.json"
        self.ttl = ttl_seconds
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2, default=str))

    def mark_complete(self, phase: str, artifacts: dict | None = None) -> None:
        self._data[phase] = {
            "status": "complete",
            "completed_at": time.time(),
            "artifacts": artifacts or {},
        }
        self._save()

    def mark_failed(self, phase: str, error: str) -> None:
        self._data[phase] = {
            "status": "failed",
            "completed_at": time.time(),
            "error": error,
        }
        self._save()

    def is_fresh(self, phase: str) -> bool:
        meta = self._data.get(phase)
        if not meta or meta.get("status") != "complete":
            return False
        return (time.time() - meta["completed_at"]) < self.ttl

    def get(self, phase: str) -> dict | None:
        return self._data.get(phase)

    def refresh(self) -> None:
        self._data = {}
        self._save()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/whitebox/unit/test_cache_manifest.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add whitebox/cache/manifest.py tests/whitebox/unit/test_cache_manifest.py
git commit -m "feat(whitebox): phase cache manifest with 24h TTL"
```

---

## Task 3: Profiles & permission probing

**Files:**
- Create: `whitebox/profiles.py`
- Create: `tests/whitebox/unit/test_profiles.py`

- [ ] **Step 1: Write the failing test**

`tests/whitebox/unit/test_profiles.py`:

```python
from unittest.mock import MagicMock, patch
import pytest
from whitebox.profiles import CloudProfile, validate, probe_permissions


def test_validate_calls_sts(tmp_path):
    fake_session = MagicMock()
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {
        "UserId": "AID", "Account": "111122223333",
        "Arn": "arn:aws:iam::111122223333:user/audit-user",
    }
    fake_session.client.return_value = fake_sts
    fake_session.get_available_regions.return_value = ["us-east-1", "ap-south-1"]

    with patch("boto3.Session", return_value=fake_session):
        prof = validate(CloudProfile(name="client-erp"))

    assert prof.account_id == "111122223333"
    assert prof.arn.endswith("audit-user")
    assert "us-east-1" in prof.regions


def test_validate_raises_on_sts_failure():
    fake_session = MagicMock()
    fake_session.client.return_value.get_caller_identity.side_effect = Exception("denied")
    with patch("boto3.Session", return_value=fake_session):
        with pytest.raises(RuntimeError, match="STS"):
            validate(CloudProfile(name="bad"))


def test_probe_permissions_records_each():
    fake_session = MagicMock()
    fake_iam = MagicMock()
    fake_iam.simulate_principal_policy.return_value = {"EvaluationResults": [{"EvalDecision": "allowed"}]}
    fake_secrets = MagicMock()
    fake_secrets.list_secrets.return_value = {"SecretList": []}
    fake_logs = MagicMock()
    fake_logs.describe_log_groups.return_value = {"logGroups": []}

    fake_session.client.side_effect = lambda svc, **kw: {
        "iam": fake_iam, "secretsmanager": fake_secrets, "logs": fake_logs,
    }[svc]

    probe = probe_permissions(fake_session, principal_arn="arn:aws:iam::1:user/u")
    assert probe["simulate_principal_policy"] is True
    assert probe["secretsmanager_list"] is True
    assert probe["logs_describe"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_profiles.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/profiles.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import boto3


@dataclass
class CloudProfile:
    name: str
    account_id: str = ""
    arn: str = ""
    regions: list[str] = field(default_factory=list)
    in_scope_domains: list[str] = field(default_factory=list)
    permission_probe: dict = field(default_factory=dict)
    _session: Any = None  # boto3.Session — set after validate()


def validate(profile: CloudProfile) -> CloudProfile:
    """Validate profile by calling STS. Raises RuntimeError on failure."""
    try:
        session = boto3.Session(profile_name=profile.name)
    except Exception as e:
        raise RuntimeError(f"failed to load AWS profile {profile.name!r}: {e}") from e

    try:
        ident = session.client("sts").get_caller_identity()
    except Exception as e:
        raise RuntimeError(f"STS GetCallerIdentity failed for {profile.name!r}: {e}") from e

    profile.account_id = ident["Account"]
    profile.arn = ident["Arn"]
    profile.regions = list(session.get_available_regions("ec2"))
    profile._session = session
    profile.permission_probe = probe_permissions(session, principal_arn=profile.arn)
    return profile


def probe_permissions(session, principal_arn: str) -> dict:
    """Soft-probe each optional permission. Never raises."""
    probe = {
        "simulate_principal_policy": False,
        "secretsmanager_list": False,
        "secretsmanager_get_value": False,  # set later by source code on first GetSecretValue
        "logs_describe": False,
        "kms_decrypt": False,                # per-key, set lazily
    }
    try:
        session.client("iam").simulate_principal_policy(
            PolicySourceArn=principal_arn,
            ActionNames=["iam:ListUsers"],
        )
        probe["simulate_principal_policy"] = True
    except Exception:
        pass
    try:
        session.client("secretsmanager").list_secrets(MaxResults=1)
        probe["secretsmanager_list"] = True
    except Exception:
        pass
    try:
        session.client("logs").describe_log_groups(limit=1)
        probe["logs_describe"] = True
    except Exception:
        pass
    return probe
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/whitebox/unit/test_profiles.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add whitebox/profiles.py tests/whitebox/unit/test_profiles.py
git commit -m "feat(whitebox): AWS profile loading, STS validation, permission probing"
```

---

## Task 4: Inventory collector (boto3 multi-service)

**Files:**
- Create: `whitebox/inventory/collector.py`
- Create: `whitebox/inventory/normalizer.py`
- Create: `tests/whitebox/unit/test_inventory_collector.py`

- [ ] **Step 1: Write the failing test**

`tests/whitebox/unit/test_inventory_collector.py`:

```python
import json
import boto3
import pytest
from moto import mock_aws
from whitebox.inventory.collector import collect_service, collect_all
from whitebox.profiles import CloudProfile


@pytest.fixture
def aws_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    profile = CloudProfile(name="test", account_id="123456789012",
                           arn="arn:aws:iam::123456789012:user/test",
                           regions=["us-east-1"])
    return profile


@mock_aws
def test_collect_ec2_writes_per_region_file(tmp_path, aws_profile):
    boto3.client("ec2", region_name="us-east-1").run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro",
    )
    aws_profile._session = boto3.Session(region_name="us-east-1")

    out = collect_service(aws_profile, "ec2", tmp_path)
    f = tmp_path / "ec2" / "us-east-1.json"
    assert f.exists()
    data = json.loads(f.read_text())
    assert "Reservations" in data
    assert out["service"] == "ec2"


@mock_aws
def test_collect_s3_lists_buckets(tmp_path, aws_profile):
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="test-bucket")
    aws_profile._session = boto3.Session(region_name="us-east-1")

    out = collect_service(aws_profile, "s3", tmp_path)
    f = tmp_path / "s3" / "global.json"
    assert f.exists()
    data = json.loads(f.read_text())
    assert any(b["Name"] == "test-bucket" for b in data["Buckets"])


@mock_aws
def test_collect_all_returns_summary(tmp_path, aws_profile):
    boto3.client("s3").create_bucket(Bucket="b1")
    aws_profile._session = boto3.Session(region_name="us-east-1")

    summary = collect_all(aws_profile, tmp_path, services=["s3", "iam"])
    assert "s3" in summary["services"]
    assert "iam" in summary["services"]
    assert summary["account_id"] == "123456789012"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_inventory_collector.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/inventory/collector.py`**

```python
from __future__ import annotations
import json
from pathlib import Path
from whitebox.profiles import CloudProfile

# Service → (boto3 client, list method, region scope)
# region scope: "regional" iterates profile.regions; "global" calls once.
SERVICE_PULLS = {
    "ec2":            ("ec2",            "describe_instances",                "regional"),
    "ec2_sg":         ("ec2",            "describe_security_groups",          "regional"),
    "ec2_vpc":        ("ec2",            "describe_vpcs",                     "regional"),
    "s3":             ("s3",             "list_buckets",                      "global"),
    "iam_users":      ("iam",            "list_users",                        "global"),
    "iam_roles":      ("iam",            "list_roles",                        "global"),
    "iam_policies":   ("iam",            "list_policies",                     "global"),
    "rds":            ("rds",            "describe_db_instances",             "regional"),
    "lambda":         ("lambda",         "list_functions",                    "regional"),
    "ecs":            ("ecs",            "list_clusters",                     "regional"),
    "eks":            ("eks",            "list_clusters",                     "regional"),
    "elbv2":          ("elbv2",          "describe_load_balancers",           "regional"),
    "apigateway":     ("apigateway",     "get_rest_apis",                     "regional"),
    "apigatewayv2":   ("apigatewayv2",   "get_apis",                          "regional"),
    "cloudfront":     ("cloudfront",     "list_distributions",                "global"),
    "route53":        ("route53",        "list_hosted_zones",                 "global"),
    "ssm":            ("ssm",            "describe_parameters",               "regional"),
    "secretsmanager": ("secretsmanager", "list_secrets",                      "regional"),
    "kms":            ("kms",            "list_keys",                         "regional"),
    "wafv2":          ("wafv2",          "list_web_acls",                     "regional"),
    "logs":           ("logs",           "describe_log_groups",               "regional"),
    "codecommit":     ("codecommit",     "list_repositories",                 "regional"),
    "ecr":            ("ecr",            "describe_repositories",             "regional"),
    "guardduty":      ("guardduty",      "list_detectors",                    "regional"),
    "cloudtrail":     ("cloudtrail",     "describe_trails",                   "regional"),
    "config":         ("config",         "describe_configuration_recorders",  "regional"),
}

DEFAULT_SERVICES = list(SERVICE_PULLS.keys())


def collect_service(profile: CloudProfile, service_key: str, out_dir: Path) -> dict:
    """Pull one service across all regions (or once for global). Writes JSON files."""
    if service_key not in SERVICE_PULLS:
        return {"service": service_key, "status": "unknown_service"}
    client_name, method, scope = SERVICE_PULLS[service_key]
    svc_dir = out_dir / service_key
    svc_dir.mkdir(parents=True, exist_ok=True)

    regions = ["global"] if scope == "global" else profile.regions
    region_results: dict[str, str] = {}

    for region in regions:
        try:
            kwargs = {} if scope == "global" else {"region_name": region}
            client = profile._session.client(client_name, **kwargs)
            data = getattr(client, method)()
            # Strip ResponseMetadata for cleanliness
            data.pop("ResponseMetadata", None)
            (svc_dir / f"{region}.json").write_text(
                json.dumps(data, indent=2, default=str)
            )
            region_results[region] = "ok"
        except Exception as e:
            region_results[region] = f"error: {e!s}"

    return {"service": service_key, "regions": region_results}


def collect_all(profile: CloudProfile, out_dir: Path,
                services: list[str] | None = None) -> dict:
    """Collect all (or selected) services. Returns summary dict."""
    services = services or DEFAULT_SERVICES
    summary = {
        "account_id": profile.account_id,
        "profile": profile.name,
        "services": {},
    }
    for svc in services:
        summary["services"][svc] = collect_service(profile, svc, out_dir)
    return summary
```

- [ ] **Step 4: Implement minimal `whitebox/inventory/normalizer.py`**

```python
from __future__ import annotations
import json
from pathlib import Path
from whitebox.models import Asset


def from_inventory_dir(account_id: str, inventory_dir: Path) -> list[Asset]:
    """Read raw boto3 inventory JSON and produce normalized Asset list."""
    assets: list[Asset] = []
    ec2_dir = inventory_dir / "ec2"
    if ec2_dir.exists():
        for f in ec2_dir.glob("*.json"):
            region = f.stem
            data = json.loads(f.read_text())
            for resv in data.get("Reservations", []):
                for inst in resv.get("Instances", []):
                    assets.append(Asset(
                        arn=f"arn:aws:ec2:{region}:{account_id}:instance/{inst['InstanceId']}",
                        service="ec2", account_id=account_id, region=region,
                        name=inst["InstanceId"], tags={t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                        public_dns=inst.get("PublicDnsName") or None,
                        public_ip=inst.get("PublicIpAddress") or None,
                    ))
    s3_dir = inventory_dir / "s3"
    if s3_dir.exists():
        for f in s3_dir.glob("*.json"):
            data = json.loads(f.read_text())
            for b in data.get("Buckets", []):
                assets.append(Asset(
                    arn=f"arn:aws:s3:::{b['Name']}",
                    service="s3", account_id=account_id, region="global",
                    name=b["Name"], tags={},
                ))
    return assets
```

- [ ] **Step 5: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_inventory_collector.py -v`
Expected: 3 passed.

```bash
git add whitebox/inventory/collector.py whitebox/inventory/normalizer.py tests/whitebox/unit/test_inventory_collector.py
git commit -m "feat(whitebox): boto3 multi-service inventory collector + normalizer"
```

---

## Task 5: Route53 zone enumeration → in-scope domains

**Files:**
- Create: `whitebox/inventory/route53.py`
- Create: `tests/whitebox/unit/test_inventory_route53.py`

- [ ] **Step 1: Write the failing test**

```python
import boto3
import pytest
from moto import mock_aws
from whitebox.inventory.route53 import enumerate_zones, in_scope_domains
from whitebox.profiles import CloudProfile


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    p = CloudProfile(name="test", account_id="111", arn="arn:test", regions=["us-east-1"])
    return p


@mock_aws
def test_enumerate_returns_zone_names(profile):
    r = boto3.client("route53")
    r.create_hosted_zone(Name="example-prod.invalid.", CallerReference="x")
    r.create_hosted_zone(Name="example-data.invalid.", CallerReference="y")
    profile._session = boto3.Session(region_name="us-east-1")

    zones = enumerate_zones(profile)
    names = sorted(z["name"] for z in zones)
    assert names == ["example-prod.invalid", "example-data.invalid"]


@mock_aws
def test_in_scope_domains_strips_trailing_dot(profile):
    r = boto3.client("route53")
    r.create_hosted_zone(Name="example.com.", CallerReference="x")
    profile._session = boto3.Session(region_name="us-east-1")

    domains = in_scope_domains(profile)
    assert "example.com" in domains
    assert "example.com." not in domains
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_inventory_route53.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/inventory/route53.py`**

```python
from __future__ import annotations
from whitebox.profiles import CloudProfile


def enumerate_zones(profile: CloudProfile) -> list[dict]:
    """Return list of {id, name, private} for every hosted zone in the account."""
    client = profile._session.client("route53")
    out: list[dict] = []
    paginator = client.get_paginator("list_hosted_zones")
    for page in paginator.paginate():
        for z in page.get("HostedZones", []):
            out.append({
                "id": z["Id"].split("/")[-1],
                "name": z["Name"].rstrip("."),
                "private": z.get("Config", {}).get("PrivateZone", False),
            })
    return out


def in_scope_domains(profile: CloudProfile) -> list[str]:
    """Public-zone domain names treated as in-scope for this account."""
    return [z["name"] for z in enumerate_zones(profile) if not z["private"]]
```

- [ ] **Step 4: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_inventory_route53.py -v`
Expected: 2 passed.

```bash
git add whitebox/inventory/route53.py tests/whitebox/unit/test_inventory_route53.py
git commit -m "feat(whitebox): Route53 zone enumeration → in-scope domain set"
```

---

## Task 6: Prowler runner

**Files:**
- Create: `whitebox/audit/prowler_runner.py`
- Create: `whitebox/audit/normalizer.py`
- Create: `tests/whitebox/unit/test_audit_prowler.py`
- Create: `tests/whitebox/integration/fixtures/prowler_ocsf_sample.json`

- [ ] **Step 1: Add a fixture OCSF JSON file**

`tests/whitebox/integration/fixtures/prowler_ocsf_sample.json`:

```json
[
  {
    "metadata": {"product": {"name": "Prowler"}, "version": "4.5.0"},
    "finding_info": {
      "uid": "prowler-iam_root_mfa_enabled-aws-1",
      "title": "Root account MFA is not enabled",
      "desc": "Root account does not have MFA enabled."
    },
    "severity_id": 5,
    "severity": "Critical",
    "status_code": "FAIL",
    "resources": [{"uid": "arn:aws:iam::111:root", "type": "AWS::IAM::User", "region": "us-east-1"}],
    "cloud": {"account": {"uid": "111"}, "region": "us-east-1", "provider": "aws"},
    "unmapped": {"check_id": "iam_root_mfa_enabled"}
  },
  {
    "metadata": {"product": {"name": "Prowler"}},
    "finding_info": {"uid": "prowler-s3_bucket_public_read-aws-2",
                     "title": "S3 bucket allows public read",
                     "desc": "Bucket policy permits anonymous read."},
    "severity_id": 4,
    "severity": "High",
    "status_code": "FAIL",
    "resources": [{"uid": "arn:aws:s3:::leaky-bucket", "type": "AWS::S3::Bucket", "region": "global"}],
    "cloud": {"account": {"uid": "111"}, "region": "us-east-1", "provider": "aws"},
    "unmapped": {"check_id": "s3_bucket_public_read"}
  }
]
```

- [ ] **Step 2: Write the failing test**

`tests/whitebox/unit/test_audit_prowler.py`:

```python
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from whitebox.audit.prowler_runner import run, parse
from whitebox.audit.normalizer import to_findings
from whitebox.models import Severity
from whitebox.profiles import CloudProfile

FIXTURE = Path(__file__).parents[1] / "integration" / "fixtures" / "prowler_ocsf_sample.json"


def test_parse_reads_ocsf_json():
    raw = parse(FIXTURE)
    assert len(raw) == 2
    assert raw[0]["unmapped"]["check_id"] == "iam_root_mfa_enabled"


def test_to_findings_maps_severity_and_rule_id():
    raw = parse(FIXTURE)
    findings = to_findings(raw, account_id="111")
    assert len(findings) == 2
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].source == "prowler"
    assert findings[0].rule_id == "iam_root_mfa_enabled"
    assert findings[0].cloud_context.account_id == "111"


def test_to_findings_skips_non_fail_status():
    raw = [{"status_code": "PASS", "unmapped": {"check_id": "x"}}]
    assert to_findings(raw, account_id="111") == []


def test_run_invokes_subprocess(tmp_path):
    profile = CloudProfile(name="test", account_id="111", arn="arn", regions=[])
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ocsf_path = tmp_path / "out.ocsf.json"
        ocsf_path.write_text("[]")
        with patch("whitebox.audit.prowler_runner._find_output_file", return_value=ocsf_path):
            result = run(profile, tmp_path)
        assert result == ocsf_path
        args = mock_run.call_args[0][0]
        assert "prowler" in args[0]
        assert "--profile" in args
        assert "test" in args
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_audit_prowler.py -v`
Expected: FAIL — modules missing.

- [ ] **Step 4: Implement `whitebox/audit/prowler_runner.py`**

```python
from __future__ import annotations
import json
import subprocess
from pathlib import Path
from whitebox.profiles import CloudProfile


def run(profile: CloudProfile, out_dir: Path,
        check_groups: list[str] | None = None,
        timeout: int = 1800) -> Path:
    """Invoke prowler, return path to OCSF JSON output."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "prowler", "aws",
        "--profile", profile.name,
        "--output-formats", "json-ocsf",
        "--output-directory", str(out_dir),
    ]
    if check_groups:
        cmd += ["--checks-folder"] + check_groups
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        (out_dir / "error.log").write_text(proc.stderr)
        raise RuntimeError(f"prowler exited {proc.returncode}; see {out_dir/'error.log'}")
    return _find_output_file(out_dir)


def _find_output_file(out_dir: Path) -> Path:
    candidates = list(out_dir.glob("*.ocsf.json")) + list(out_dir.glob("*ocsf*.json"))
    if not candidates:
        raise FileNotFoundError(f"no OCSF JSON output in {out_dir}")
    return candidates[0]


def parse(ocsf_path: Path) -> list[dict]:
    return json.loads(Path(ocsf_path).read_text())
```

- [ ] **Step 5: Implement `whitebox/audit/normalizer.py`**

```python
from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext

# Prowler OCSF severity_id → vikramaditya Severity
_SEV_MAP = {
    1: Severity.INFO,
    2: Severity.LOW,
    3: Severity.MEDIUM,
    4: Severity.HIGH,
    5: Severity.CRITICAL,
}


def to_findings(raw_ocsf: list[dict], account_id: str) -> list[Finding]:
    out: list[Finding] = []
    for idx, item in enumerate(raw_ocsf):
        if item.get("status_code") != "FAIL":
            continue
        check_id = item.get("unmapped", {}).get("check_id") or item.get("finding_info", {}).get("uid", f"unknown_{idx}")
        sev = _SEV_MAP.get(item.get("severity_id", 0), Severity.INFO)
        info = item.get("finding_info", {})
        cloud = item.get("cloud", {})
        resources = item.get("resources", [])
        first_res = resources[0] if resources else {}
        ctx = CloudContext(
            account_id=cloud.get("account", {}).get("uid", account_id),
            region=cloud.get("region", first_res.get("region", "unknown")),
            service=first_res.get("type", "unknown"),
            arn=first_res.get("uid", ""),
        )
        out.append(Finding(
            id=info.get("uid", f"prowler-{idx}"),
            source="prowler",
            rule_id=check_id,
            severity=sev,
            title=info.get("title", check_id),
            description=info.get("desc", ""),
            asset=None,
            evidence_path=Path("prowler") / f"{check_id}.json",
            cloud_context=ctx,
        ))
    return out
```

- [ ] **Step 6: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_audit_prowler.py -v`
Expected: 4 passed.

```bash
git add whitebox/audit tests/whitebox/unit/test_audit_prowler.py tests/whitebox/integration/fixtures/prowler_ocsf_sample.json
git commit -m "feat(whitebox): Prowler v4 subprocess runner + OCSF → Finding normalizer"
```

---

## Task 7: Exposure analyzer (SG/NACL/WAF tagging)

**Files:**
- Create: `whitebox/exposure/analyzer.py`
- Create: `whitebox/exposure/tagger.py`
- Create: `tests/whitebox/unit/test_exposure_analyzer.py`

- [ ] **Step 1: Write the failing test**

```python
from whitebox.exposure.analyzer import analyze_security_groups, is_public_to_internet
from whitebox.exposure.tagger import tag_assets
from whitebox.models import Asset


def test_is_public_to_internet_detects_open_cidr():
    sg = {"IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }]}
    assert is_public_to_internet(sg)


def test_is_public_to_internet_false_for_private_cidr():
    sg = {"IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
    }]}
    assert not is_public_to_internet(sg)


def test_analyze_security_groups_extracts_ports_and_cidrs():
    sg = {"GroupId": "sg-1", "IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 443,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "1.2.3.4/32"}],
    }]}
    result = analyze_security_groups([sg])
    assert result["sg-1"]["public"] is True
    assert 80 in result["sg-1"]["exposed_ports"]
    assert 443 in result["sg-1"]["exposed_ports"]
    assert "0.0.0.0/0" in result["sg-1"]["exposed_cidrs"]


def test_tag_assets_marks_internet_reachable():
    asset = Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                  region="us-east-1", name="i-1", tags={},
                  public_ip="1.2.3.4")
    instance_sg_map = {"i-1": ["sg-1"]}
    sg_analysis = {"sg-1": {"public": True, "exposed_ports": [443], "exposed_cidrs": ["0.0.0.0/0"]}}

    tagged = tag_assets([asset], instance_sg_map, sg_analysis, waf_protected_arns=set())
    assert tagged[0].tags["internet_reachable"] is True
    assert tagged[0].tags["exposed_ports"] == [443]
    assert tagged[0].tags["behind_waf"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_exposure_analyzer.py -v`
Expected: FAIL — modules missing.

- [ ] **Step 3: Implement `whitebox/exposure/analyzer.py`**

```python
from __future__ import annotations


def is_public_to_internet(sg: dict) -> bool:
    for perm in sg.get("IpPermissions", []):
        for r in perm.get("IpRanges", []):
            if r.get("CidrIp") == "0.0.0.0/0":
                return True
        for r in perm.get("Ipv6Ranges", []):
            if r.get("CidrIpv6") == "::/0":
                return True
    return False


def analyze_security_groups(sgs: list[dict]) -> dict[str, dict]:
    """Return {sg_id: {public, exposed_ports, exposed_cidrs}}."""
    result: dict[str, dict] = {}
    for sg in sgs:
        sgid = sg.get("GroupId", "")
        ports: set[int] = set()
        cidrs: set[str] = set()
        public = False
        for perm in sg.get("IpPermissions", []):
            fp, tp = perm.get("FromPort"), perm.get("ToPort")
            if fp is not None and tp is not None:
                ports.update(range(fp, tp + 1))
            for r in perm.get("IpRanges", []):
                cidr = r.get("CidrIp", "")
                if cidr:
                    cidrs.add(cidr)
                    if cidr == "0.0.0.0/0":
                        public = True
        result[sgid] = {
            "public": public,
            "exposed_ports": sorted(ports),
            "exposed_cidrs": sorted(cidrs),
        }
    return result
```

- [ ] **Step 4: Implement `whitebox/exposure/tagger.py`**

```python
from __future__ import annotations
from whitebox.models import Asset


def tag_assets(assets: list[Asset],
               instance_sg_map: dict[str, list[str]],
               sg_analysis: dict[str, dict],
               waf_protected_arns: set[str]) -> list[Asset]:
    """Mutate and return assets with exposure tags."""
    for a in assets:
        if a.service == "ec2":
            sg_ids = instance_sg_map.get(a.name, [])
            public = any(sg_analysis.get(sg, {}).get("public") for sg in sg_ids)
            ports: set[int] = set()
            cidrs: set[str] = set()
            for sg in sg_ids:
                ports.update(sg_analysis.get(sg, {}).get("exposed_ports", []))
                cidrs.update(sg_analysis.get(sg, {}).get("exposed_cidrs", []))
            a.tags["internet_reachable"] = bool(public and a.public_ip)
            a.tags["exposed_ports"] = sorted(ports)
            a.tags["exposed_cidrs"] = sorted(cidrs)
            a.tags["behind_waf"] = a.arn in waf_protected_arns
        elif a.service == "s3":
            # Placeholder — bucket-policy/public-access-block check happens in Prowler;
            # here we just mark default values. Refined when bucket policy data fed in.
            a.tags.setdefault("internet_reachable", False)
            a.tags.setdefault("behind_waf", False)
    return assets
```

- [ ] **Step 5: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_exposure_analyzer.py -v`
Expected: 4 passed.

```bash
git add whitebox/exposure tests/whitebox/unit/test_exposure_analyzer.py
git commit -m "feat(whitebox): SG-based exposure analyzer + asset tagger"
```

---

## Task 8: PMapper runner + IAM graph queries

**Files:**
- Create: `whitebox/iam/pmapper_runner.py`
- Create: `whitebox/iam/graph.py`
- Create: `tests/whitebox/unit/test_iam_graph.py`
- Create: `tests/whitebox/integration/fixtures/pmapper_graph_sample.json`

- [ ] **Step 1: Add fixture graph**

`tests/whitebox/integration/fixtures/pmapper_graph_sample.json`:

```json
{
  "metadata": {"account_id": "111", "pmapper_version": "1.1.5"},
  "nodes": [
    {"arn": "arn:aws:iam::111:user/alice",     "id_value": "alice",     "is_admin": false},
    {"arn": "arn:aws:iam::111:role/web-prod",  "id_value": "web-prod",  "is_admin": false},
    {"arn": "arn:aws:iam::111:role/admin",     "id_value": "admin",     "is_admin": true}
  ],
  "edges": [
    {"source": "arn:aws:iam::111:user/alice",    "destination": "arn:aws:iam::111:role/web-prod", "reason": "can sts:AssumeRole"},
    {"source": "arn:aws:iam::111:role/web-prod", "destination": "arn:aws:iam::111:role/admin",    "reason": "can iam:PassRole + lambda:CreateFunction"}
  ]
}
```

- [ ] **Step 2: Write the failing test**

```python
from pathlib import Path
from whitebox.iam.graph import IAMGraph

FIX = Path(__file__).parents[1] / "integration" / "fixtures" / "pmapper_graph_sample.json"


def test_load_graph_counts_nodes_and_edges():
    g = IAMGraph.load(FIX)
    assert len(g.nodes) == 3
    assert len(g.edges) == 2


def test_can_reach_finds_two_hop_path():
    g = IAMGraph.load(FIX)
    path = g.can_reach("arn:aws:iam::111:user/alice", "arn:aws:iam::111:role/admin")
    assert path == [
        "arn:aws:iam::111:user/alice",
        "arn:aws:iam::111:role/web-prod",
        "arn:aws:iam::111:role/admin",
    ]


def test_can_reach_returns_none_when_unreachable():
    g = IAMGraph.load(FIX)
    assert g.can_reach("arn:aws:iam::111:role/admin", "arn:aws:iam::111:user/alice") is None


def test_reachable_admins():
    g = IAMGraph.load(FIX)
    admins = g.reachable_admins("arn:aws:iam::111:user/alice")
    assert "arn:aws:iam::111:role/admin" in admins


def test_blast_radius_counts_assumable_roles():
    g = IAMGraph.load(FIX)
    br = g.blast_radius("arn:aws:iam::111:user/alice")
    assert "arn:aws:iam::111:role/web-prod" in br.assumable_roles
    assert "arn:aws:iam::111:role/admin" in br.assumable_roles
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_iam_graph.py -v`
Expected: FAIL — module missing.

- [ ] **Step 4: Implement `whitebox/iam/graph.py`**

```python
from __future__ import annotations
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from whitebox.models import BlastRadius


@dataclass
class IAMGraph:
    nodes: dict[str, dict]            # arn → node attrs
    edges: dict[str, list[dict]]      # source_arn → list of {destination, reason}

    @classmethod
    def load(cls, path: Path) -> "IAMGraph":
        data = json.loads(Path(path).read_text())
        nodes = {n["arn"]: n for n in data.get("nodes", [])}
        edges: dict[str, list[dict]] = defaultdict(list)
        for e in data.get("edges", []):
            edges[e["source"]].append({"destination": e["destination"], "reason": e.get("reason", "")})
        return cls(nodes=nodes, edges=dict(edges))

    def can_reach(self, src: str, dst: str) -> list[str] | None:
        """BFS shortest path. Returns ARN list including endpoints, or None."""
        if src == dst:
            return [src]
        visited = {src}
        queue = deque([(src, [src])])
        while queue:
            node, path = queue.popleft()
            for e in self.edges.get(node, []):
                nxt = e["destination"]
                if nxt in visited:
                    continue
                if nxt == dst:
                    return path + [nxt]
                visited.add(nxt)
                queue.append((nxt, path + [nxt]))
        return None

    def reachable_admins(self, src: str) -> list[str]:
        out = []
        for arn, node in self.nodes.items():
            if node.get("is_admin") and arn != src:
                if self.can_reach(src, arn):
                    out.append(arn)
        return out

    def blast_radius(self, src: str) -> BlastRadius:
        reachable: set[str] = set()
        stack = [src]
        while stack:
            n = stack.pop()
            for e in self.edges.get(n, []):
                if e["destination"] not in reachable and e["destination"] != src:
                    reachable.add(e["destination"])
                    stack.append(e["destination"])
        return BlastRadius(
            principal_arn=src,
            s3_buckets=[],   # populated later by cross-referencing inventory
            kms_keys=[],
            lambdas=[],
            assumable_roles=sorted(reachable),
            regions=[],
        )
```

- [ ] **Step 5: Implement `whitebox/iam/pmapper_runner.py`**

```python
from __future__ import annotations
import subprocess
from pathlib import Path
from whitebox.profiles import CloudProfile


def build_graph(profile: CloudProfile, out_dir: Path, timeout: int = 1800) -> Path:
    """Invoke pmapper to create the graph; return path to graph JSON."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["pmapper", "--profile", profile.name, "graph", "create"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        (out_dir / "error.log").write_text(proc.stderr)
        raise RuntimeError(f"pmapper exited {proc.returncode}; see {out_dir/'error.log'}")
    # pmapper stores graphs under ~/.principalmapper/<account_id>/graph.json
    src = Path.home() / ".principalmapper" / profile.account_id / "graph.json"
    dst = out_dir / "graph.json"
    dst.write_text(src.read_text())
    return dst
```

- [ ] **Step 6: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_iam_graph.py -v`
Expected: 5 passed.

```bash
git add whitebox/iam tests/whitebox/unit/test_iam_graph.py tests/whitebox/integration/fixtures/pmapper_graph_sample.json
git commit -m "feat(whitebox): PMapper subprocess runner + IAM graph (BFS reachability, blast radius)"
```

---

## Task 9: Privesc detection

**Files:**
- Create: `whitebox/iam/privesc.py`
- Create: `tests/whitebox/unit/test_iam_privesc.py`

- [ ] **Step 1: Write the failing test**

```python
from pathlib import Path
from whitebox.iam.graph import IAMGraph
from whitebox.iam.privesc import detect_paths
from whitebox.models import Severity

FIX = Path(__file__).parents[1] / "integration" / "fixtures" / "pmapper_graph_sample.json"


def test_detect_paths_emits_finding_per_admin_path():
    g = IAMGraph.load(FIX)
    findings = detect_paths(g, account_id="111")
    # alice → web-prod → admin is one privesc path
    assert any("alice" in f.title and "admin" in f.title for f in findings)
    assert all(f.source == "pmapper" for f in findings)
    assert all(f.severity >= Severity.HIGH for f in findings)
    assert all(f.rule_id.startswith("pmapper.") for f in findings)


def test_detect_paths_skips_already_admin_principals():
    g = IAMGraph.load(FIX)
    findings = detect_paths(g, account_id="111")
    # admin role is already admin — no self-finding
    assert not any(f.title.startswith("admin →") for f in findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_iam_privesc.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/iam/privesc.py`**

```python
from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.iam.graph import IAMGraph


def detect_paths(graph: IAMGraph, account_id: str) -> list[Finding]:
    findings: list[Finding] = []
    for arn, node in graph.nodes.items():
        if node.get("is_admin"):
            continue
        for admin_arn in graph.reachable_admins(arn):
            path = graph.can_reach(arn, admin_arn) or []
            short_src = arn.split(":")[-1].split("/")[-1]
            short_dst = admin_arn.split(":")[-1].split("/")[-1]
            findings.append(Finding(
                id=f"pmapper-{short_src}-to-{short_dst}",
                source="pmapper",
                rule_id=f"pmapper.privesc_path.{len(path)-1}_hop",
                severity=Severity.HIGH if len(path) > 2 else Severity.CRITICAL,
                title=f"{short_src} → {short_dst} (privilege escalation, {len(path)-1} hop)",
                description=f"Principal {arn} can reach admin {admin_arn} via {' → '.join(path)}",
                asset=None,
                evidence_path=Path("pmapper") / f"{short_src}-to-{short_dst}.json",
                cloud_context=CloudContext(
                    account_id=account_id, region="global", service="iam", arn=arn,
                ),
            ))
    return findings
```

- [ ] **Step 4: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_iam_privesc.py -v`
Expected: 2 passed.

```bash
git add whitebox/iam/privesc.py tests/whitebox/unit/test_iam_privesc.py
git commit -m "feat(whitebox): IAM privesc path detection (one finding per reachable admin)"
```

---

## Task 10: Secret detectors (regex + entropy)

**Files:**
- Create: `whitebox/secrets/detectors.py`
- Create: `tests/whitebox/unit/test_secrets_detectors.py`

- [ ] **Step 1: Write the failing test**

```python
from whitebox.secrets.detectors import scan_text, DETECTORS


def test_scan_finds_aws_access_key():
    txt = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    hits = scan_text(txt, source="env")
    names = [h["detector"] for h in hits]
    assert "aws_access_key_id" in names


def test_scan_finds_aws_secret_key():
    txt = "secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    hits = scan_text(txt, source="env")
    assert any(h["detector"] == "aws_secret_access_key" for h in hits)


def test_scan_finds_jwt():
    txt = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.aBcDeFgHiJkLmNoPqRsTuVwXyZ"
    hits = scan_text(txt, source="env")
    assert any(h["detector"] == "jwt" for h in hits)


def test_scan_finds_private_key():
    txt = "-----BEGIN RSA PRIVATE KEY-----\nABCD\n-----END RSA PRIVATE KEY-----"
    hits = scan_text(txt, source="env")
    assert any(h["detector"] == "rsa_private_key" for h in hits)


def test_scan_high_entropy_string_flagged():
    # 40-char base64-like high-entropy string
    txt = "key=8s9d7f6g7h8j9k0l1m2n3b4v5c6x7z8q9w0e1r2t"
    hits = scan_text(txt, source="env")
    assert any(h["detector"] == "high_entropy" for h in hits)


def test_each_hit_has_offset_and_redacted_preview():
    txt = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    hits = scan_text(txt, source="env")
    h = hits[0]
    assert "offset" in h
    assert "preview" in h
    assert "EXAMPLE" not in h["preview"]  # full value redacted
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_secrets_detectors.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/secrets/detectors.py`**

```python
from __future__ import annotations
import math
import re

DETECTORS = {
    "aws_access_key_id":      re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_access_key":  re.compile(r"\b[A-Za-z0-9/+=]{40}\b"),
    "jwt":                    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "rsa_private_key":        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
    "github_pat":             re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "slack_token":            re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe_key":             re.compile(r"\b(sk|pk)_(live|test)_[A-Za-z0-9]{24,}\b"),
    "google_api_key":         re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "generic_password_assignment": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\";]{8,})"),
}

ENTROPY_THRESHOLD = 4.5
ENTROPY_MIN_LEN = 24


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}***{s[-4:]} (len={len(s)})"


def scan_text(text: str, source: str) -> list[dict]:
    hits: list[dict] = []
    seen_offsets: set[int] = set()
    for name, regex in DETECTORS.items():
        for m in regex.finditer(text):
            offset = m.start()
            if offset in seen_offsets:
                continue
            seen_offsets.add(offset)
            value = m.group(0)
            hits.append({
                "detector": name, "source": source, "offset": offset,
                "preview": _redact(value),
                "value": value,  # caller writes only to mode-0600 evidence
            })
    # Entropy pass: only on tokens >= ENTROPY_MIN_LEN that look like values
    for m in re.finditer(r"[A-Za-z0-9/+_=-]{%d,}" % ENTROPY_MIN_LEN, text):
        if m.start() in seen_offsets:
            continue
        token = m.group(0)
        if _entropy(token) >= ENTROPY_THRESHOLD:
            hits.append({
                "detector": "high_entropy", "source": source, "offset": m.start(),
                "preview": _redact(token), "value": token,
            })
    return hits
```

- [ ] **Step 4: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_secrets_detectors.py -v`
Expected: 6 passed.

```bash
git add whitebox/secrets/detectors.py tests/whitebox/unit/test_secrets_detectors.py
git commit -m "feat(whitebox): regex + entropy secret detectors with redacted previews"
```

---

## Task 11: Secret redactor + evidence writer

**Files:**
- Create: `whitebox/secrets/redactor.py`
- Create: `tests/whitebox/unit/test_secrets_redactor.py`

- [ ] **Step 1: Write the failing test**

```python
import json
import os
import stat
from whitebox.secrets.redactor import write_evidence, redact_for_html


def test_write_evidence_creates_mode_0600_file(tmp_path):
    hits = [{"detector": "aws_access_key_id", "source": "lambda_env",
             "value": "AKIAEXAMPLE...", "preview": "AKIA***MPLE (len=20)", "offset": 5}]
    path = write_evidence(tmp_path, "secret_in_lambda_x", hits)
    assert path.exists()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    data = json.loads(path.read_text())
    assert data[0]["value"] == "AKIAEXAMPLE..."


def test_redact_for_html_strips_value():
    hits = [{"detector": "x", "value": "supersecret", "preview": "supe***ret (len=11)", "offset": 0}]
    safe = redact_for_html(hits)
    assert "value" not in safe[0]
    assert safe[0]["preview"] == "supe***ret (len=11)"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_secrets_redactor.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/secrets/redactor.py`**

```python
from __future__ import annotations
import json
import os
from pathlib import Path


def write_evidence(secrets_dir: Path, finding_id: str, hits: list[dict]) -> Path:
    """Write full secret values to mode-0600 JSON. Caller must use only inside cloud/secrets/."""
    secrets_dir = Path(secrets_dir)
    secrets_dir.mkdir(parents=True, exist_ok=True)
    path = secrets_dir / f"{finding_id}.json"
    path.write_text(json.dumps(hits, indent=2))
    os.chmod(path, 0o600)
    return path


def redact_for_html(hits: list[dict]) -> list[dict]:
    """Strip raw value before passing to report renderer."""
    return [{k: v for k, v in h.items() if k != "value"} for h in hits]
```

- [ ] **Step 4: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_secrets_redactor.py -v`
Expected: 2 passed.

```bash
git add whitebox/secrets/redactor.py tests/whitebox/unit/test_secrets_redactor.py
git commit -m "feat(whitebox): secret evidence writer (mode 0600) + HTML redactor"
```

---

## Task 12: Secret source — Lambda env vars

**Files:**
- Create: `whitebox/secrets/sources/lambda_env.py`
- Create: `tests/whitebox/unit/test_secrets_sources_lambda.py`

- [ ] **Step 1: Write the failing test**

```python
import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.lambda_env import scan as scan_lambda


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_lambda_finds_aws_key_in_env(profile):
    iam = boto3.client("iam")
    iam.create_role(RoleName="r", AssumeRolePolicyDocument="{}")
    role_arn = iam.get_role(RoleName="r")["Role"]["Arn"]
    lam = boto3.client("lambda", region_name="us-east-1")
    lam.create_function(
        FunctionName="leaky", Runtime="python3.11", Role=role_arn,
        Handler="x.handler",
        Code={"ZipFile": b"def handler(e,c):pass"},
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}},
    )
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_lambda(profile)
    assert len(findings) >= 1
    f = findings[0]
    assert f.source == "secrets"
    assert f.rule_id.startswith("secrets.lambda_env.")
    assert "leaky" in f.description
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_secrets_sources_lambda.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/secrets/sources/lambda_env.py`**

```python
from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile) -> list[Finding]:
    findings: list[Finding] = []
    for region in profile.regions:
        try:
            client = profile._session.client("lambda", region_name=region)
        except Exception:
            continue
        try:
            paginator = client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    env_vars = (fn.get("Environment") or {}).get("Variables") or {}
                    for key, value in env_vars.items():
                        text = f"{key}={value}"
                        for hit in scan_text(text, source=f"lambda_env:{fn['FunctionName']}"):
                            fid = f"secret-lambda-{fn['FunctionName']}-{key}-{hit['detector']}"
                            findings.append(Finding(
                                id=fid,
                                source="secrets",
                                rule_id=f"secrets.lambda_env.{hit['detector']}",
                                severity=Severity.HIGH,
                                title=f"Secret in Lambda env var ({fn['FunctionName']}.{key})",
                                description=f"{hit['detector']} matched in env var {key} of Lambda {fn['FunctionName']} (region {region}). Preview: {hit['preview']}",
                                asset=None,
                                evidence_path=Path("secrets") / f"{fid}.json",
                                cloud_context=CloudContext(
                                    account_id=profile.account_id, region=region,
                                    service="lambda", arn=fn["FunctionArn"],
                                ),
                            ))
        except Exception:
            continue
    return findings
```

- [ ] **Step 4: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_secrets_sources_lambda.py -v`
Expected: 1 passed.

```bash
git add whitebox/secrets/sources/lambda_env.py tests/whitebox/unit/test_secrets_sources_lambda.py
git commit -m "feat(whitebox): secret source — Lambda env vars"
```

---

## Task 13: Secret source — SSM parameters (plaintext + SecureString decrypt)

**Files:**
- Create: `whitebox/secrets/sources/ssm.py`
- Create: `tests/whitebox/unit/test_secrets_sources_ssm.py`

- [ ] **Step 1: Write the failing test**

```python
import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.ssm import scan as scan_ssm


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_ssm_finds_aws_key_in_string_param(profile):
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(Name="/app/AWS_KEY", Type="String",
                      Value="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_ssm(profile)
    assert any("/app/AWS_KEY" in f.description for f in findings)


@mock_aws
def test_scan_ssm_handles_secure_string_with_decrypt_permission(profile):
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(Name="/secret/key", Type="SecureString",
                      Value="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_ssm(profile)
    assert any("/secret/key" in f.description for f in findings)


@mock_aws
def test_scan_ssm_skips_non_secret_values(profile):
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(Name="/app/log_level", Type="String", Value="INFO")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_ssm(profile)
    assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_secrets_sources_ssm.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/secrets/sources/ssm.py`**

```python
from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile) -> list[Finding]:
    findings: list[Finding] = []
    for region in profile.regions:
        try:
            client = profile._session.client("ssm", region_name=region)
        except Exception:
            continue
        try:
            paginator = client.get_paginator("describe_parameters")
            param_names: list[tuple[str, str]] = []
            for page in paginator.paginate():
                for p in page.get("Parameters", []):
                    param_names.append((p["Name"], p["Type"]))
        except Exception:
            continue

        for name, ptype in param_names:
            try:
                resp = client.get_parameter(Name=name, WithDecryption=True)
                value = resp["Parameter"]["Value"]
            except Exception:
                continue
            for hit in scan_text(f"{name}={value}", source=f"ssm:{name}"):
                fid = f"secret-ssm-{name.strip('/').replace('/', '_')}-{hit['detector']}"
                findings.append(Finding(
                    id=fid,
                    source="secrets",
                    rule_id=f"secrets.ssm.{hit['detector']}",
                    severity=Severity.HIGH,
                    title=f"Secret in SSM parameter ({name})",
                    description=f"{hit['detector']} matched in SSM {ptype} parameter {name} (region {region}). Preview: {hit['preview']}",
                    asset=None,
                    evidence_path=Path("secrets") / f"{fid}.json",
                    cloud_context=CloudContext(
                        account_id=profile.account_id, region=region, service="ssm",
                        arn=f"arn:aws:ssm:{region}:{profile.account_id}:parameter{name}",
                    ),
                ))
    return findings
```

- [ ] **Step 4: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_secrets_sources_ssm.py -v`
Expected: 3 passed.

```bash
git add whitebox/secrets/sources/ssm.py tests/whitebox/unit/test_secrets_sources_ssm.py
git commit -m "feat(whitebox): secret source — SSM parameters (plaintext + decrypted SecureString)"
```

---

## Task 14: Secret source — Secrets Manager

**Files:**
- Create: `whitebox/secrets/sources/secretsmanager.py`
- Create: `tests/whitebox/unit/test_secrets_sources_secretsmanager.py`

- [ ] **Step 1: Write the failing test**

```python
import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.secretsmanager import scan as scan_sm


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_secretsmanager_with_get_value_permission(profile):
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/db", SecretString="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    profile.permission_probe = {"secretsmanager_get_value": True}
    findings = scan_sm(profile)
    assert any("prod/db" in f.description for f in findings)


@mock_aws
def test_scan_secretsmanager_metadata_only_when_no_permission(profile):
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/db", SecretString="AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    profile.permission_probe = {"secretsmanager_get_value": False}
    findings = scan_sm(profile)
    # Should emit info finding documenting permission gap, no values pulled
    assert any(f.rule_id == "secrets.secretsmanager.permission_gap" for f in findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_secrets_sources_secretsmanager.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/secrets/sources/secretsmanager.py`**

```python
from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile) -> list[Finding]:
    findings: list[Finding] = []
    can_get = profile.permission_probe.get("secretsmanager_get_value", False)
    for region in profile.regions:
        try:
            client = profile._session.client("secretsmanager", region_name=region)
        except Exception:
            continue
        secret_arns: list[tuple[str, str]] = []
        try:
            paginator = client.get_paginator("list_secrets")
            for page in paginator.paginate():
                for s in page.get("SecretList", []):
                    secret_arns.append((s["Name"], s["ARN"]))
        except Exception:
            continue
        if not secret_arns:
            continue
        if not can_get:
            findings.append(Finding(
                id=f"secrets-permission-gap-{region}",
                source="secrets",
                rule_id="secrets.secretsmanager.permission_gap",
                severity=Severity.INFO,
                title=f"Secrets Manager scan limited to metadata in {region}",
                description=f"{len(secret_arns)} secrets present but secretsmanager:GetSecretValue is not granted. Add the permission to enable value scanning.",
                asset=None,
                evidence_path=Path("secrets") / f"permission-gap-{region}.json",
                cloud_context=CloudContext(
                    account_id=profile.account_id, region=region, service="secretsmanager", arn="",
                ),
            ))
            continue
        for name, arn in secret_arns:
            try:
                value = client.get_secret_value(SecretId=arn).get("SecretString", "")
            except Exception:
                continue
            for hit in scan_text(f"{name}={value}", source=f"secretsmanager:{name}"):
                fid = f"secret-sm-{name.replace('/', '_')}-{hit['detector']}"
                findings.append(Finding(
                    id=fid,
                    source="secrets",
                    rule_id=f"secrets.secretsmanager.{hit['detector']}",
                    severity=Severity.CRITICAL,
                    title=f"Secret value in Secrets Manager ({name})",
                    description=f"{hit['detector']} matched in secret {name} (region {region}). Preview: {hit['preview']}",
                    asset=None,
                    evidence_path=Path("secrets") / f"{fid}.json",
                    cloud_context=CloudContext(
                        account_id=profile.account_id, region=region, service="secretsmanager", arn=arn,
                    ),
                ))
    return findings
```

- [ ] **Step 4: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_secrets_sources_secretsmanager.py -v`
Expected: 2 passed.

```bash
git add whitebox/secrets/sources/secretsmanager.py tests/whitebox/unit/test_secrets_sources_secretsmanager.py
git commit -m "feat(whitebox): secret source — Secrets Manager (with permission-gap fallback)"
```

---

## Task 15: Secret sources — S3, CloudWatch logs, EC2 user-data (compact batch)

**Files:**
- Create: `whitebox/secrets/sources/s3.py`
- Create: `whitebox/secrets/sources/cloudwatch_logs.py`
- Create: `whitebox/secrets/sources/ec2_userdata.py`
- Create: `tests/whitebox/unit/test_secrets_sources_s3.py`
- Create: `tests/whitebox/unit/test_secrets_sources_logs.py`
- Create: `tests/whitebox/unit/test_secrets_sources_ec2_userdata.py`

- [ ] **Step 1: Write all three failing tests**

`tests/whitebox/unit/test_secrets_sources_s3.py`:

```python
import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.s3 import scan as scan_s3


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_s3_finds_secret_in_targeted_bucket(profile):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="config-backups")
    s3.put_object(Bucket="config-backups", Key="db.env",
                  Body=b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_s3(profile, target_buckets=["config-backups"])
    assert any("config-backups/db.env" in f.description for f in findings)


@mock_aws
def test_scan_s3_skips_buckets_not_in_targets(profile):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="random")
    s3.put_object(Bucket="random", Key="x", Body=b"AKIAIOSFODNN7EXAMPLE")
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_s3(profile, target_buckets=["different"])
    assert findings == []
```

`tests/whitebox/unit/test_secrets_sources_logs.py`:

```python
import boto3
import pytest
import time
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.cloudwatch_logs import scan as scan_logs


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_logs_finds_aws_key_in_event(profile):
    logs = boto3.client("logs", region_name="us-east-1")
    logs.create_log_group(logGroupName="/aws/lambda/leaky")
    logs.create_log_stream(logGroupName="/aws/lambda/leaky", logStreamName="s1")
    logs.put_log_events(
        logGroupName="/aws/lambda/leaky", logStreamName="s1",
        logEvents=[{"timestamp": int(time.time() * 1000),
                    "message": "key=AKIAIOSFODNN7EXAMPLE"}],
    )
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_logs(profile, target_groups=["/aws/lambda/leaky"])
    assert any("AKIA" in f.description or "/aws/lambda/leaky" in f.description for f in findings)
```

`tests/whitebox/unit/test_secrets_sources_ec2_userdata.py`:

```python
import base64
import boto3
import pytest
from moto import mock_aws
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources.ec2_userdata import scan as scan_ud


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    return CloudProfile(name="t", account_id="111", arn="a", regions=["us-east-1"])


@mock_aws
def test_scan_userdata_decodes_b64_and_detects_secret(profile):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    user_data = base64.b64encode(b"#!/bin/bash\nexport SK=AKIAIOSFODNN7EXAMPLE\n").decode()
    res = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                            InstanceType="t2.micro", UserData=user_data)
    profile._session = boto3.Session(region_name="us-east-1")
    findings = scan_ud(profile)
    assert any("user-data" in f.title.lower() or "user-data" in f.description.lower() for f in findings)
```

- [ ] **Step 2: Run all three to verify they fail**

Run:
```
pytest tests/whitebox/unit/test_secrets_sources_s3.py tests/whitebox/unit/test_secrets_sources_logs.py tests/whitebox/unit/test_secrets_sources_ec2_userdata.py -v
```
Expected: FAIL — modules missing.

- [ ] **Step 3: Implement `whitebox/secrets/sources/s3.py`**

```python
from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text

MAX_OBJECT_SIZE = 1_000_000   # 1 MB
MAX_OBJECTS_PER_BUCKET = 200


def scan(profile: CloudProfile, target_buckets: list[str]) -> list[Finding]:
    if not target_buckets:
        return []
    findings: list[Finding] = []
    s3 = profile._session.client("s3")
    for bucket in target_buckets:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            count = 0
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    if count >= MAX_OBJECTS_PER_BUCKET:
                        break
                    if obj.get("Size", 0) > MAX_OBJECT_SIZE:
                        continue
                    count += 1
                    try:
                        body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
                    except Exception:
                        continue
                    try:
                        text = body.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    for hit in scan_text(text, source=f"s3:{bucket}/{obj['Key']}"):
                        fid = f"secret-s3-{bucket}-{obj['Key'].replace('/', '_')}-{hit['detector']}"
                        findings.append(Finding(
                            id=fid,
                            source="secrets",
                            rule_id=f"secrets.s3.{hit['detector']}",
                            severity=Severity.HIGH,
                            title=f"Secret in S3 object ({bucket}/{obj['Key']})",
                            description=f"{hit['detector']} matched in s3://{bucket}/{obj['Key']}. Preview: {hit['preview']}",
                            asset=None,
                            evidence_path=Path("secrets") / f"{fid}.json",
                            cloud_context=CloudContext(
                                account_id=profile.account_id, region="global",
                                service="s3", arn=f"arn:aws:s3:::{bucket}/{obj['Key']}",
                            ),
                        ))
        except Exception:
            continue
    return findings
```

- [ ] **Step 4: Implement `whitebox/secrets/sources/cloudwatch_logs.py`**

```python
from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text

MAX_EVENTS_PER_GROUP = 500


def scan(profile: CloudProfile, target_groups: list[str]) -> list[Finding]:
    if not target_groups:
        return []
    findings: list[Finding] = []
    for region in profile.regions:
        try:
            client = profile._session.client("logs", region_name=region)
        except Exception:
            continue
        for group in target_groups:
            try:
                streams = client.describe_log_streams(logGroupName=group, orderBy="LastEventTime", descending=True, limit=5)
            except Exception:
                continue
            count = 0
            for s in streams.get("logStreams", []):
                if count >= MAX_EVENTS_PER_GROUP:
                    break
                try:
                    events = client.get_log_events(logGroupName=group, logStreamName=s["logStreamName"], limit=200)
                except Exception:
                    continue
                for ev in events.get("events", []):
                    count += 1
                    for hit in scan_text(ev.get("message", ""), source=f"logs:{group}:{s['logStreamName']}"):
                        fid = f"secret-logs-{group.strip('/').replace('/', '_')}-{hit['offset']}-{hit['detector']}"
                        findings.append(Finding(
                            id=fid,
                            source="secrets",
                            rule_id=f"secrets.cloudwatch_logs.{hit['detector']}",
                            severity=Severity.HIGH,
                            title=f"Secret in CloudWatch log ({group})",
                            description=f"{hit['detector']} matched in log group {group}, stream {s['logStreamName']} (region {region}). Preview: {hit['preview']}",
                            asset=None,
                            evidence_path=Path("secrets") / f"{fid}.json",
                            cloud_context=CloudContext(
                                account_id=profile.account_id, region=region, service="logs",
                                arn=f"arn:aws:logs:{region}:{profile.account_id}:log-group:{group}",
                            ),
                        ))
    return findings
```

- [ ] **Step 5: Implement `whitebox/secrets/sources/ec2_userdata.py`**

```python
from __future__ import annotations
import base64
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext
from whitebox.profiles import CloudProfile
from whitebox.secrets.detectors import scan_text


def scan(profile: CloudProfile) -> list[Finding]:
    findings: list[Finding] = []
    for region in profile.regions:
        try:
            ec2 = profile._session.client("ec2", region_name=region)
            instances = ec2.describe_instances()
        except Exception:
            continue
        for resv in instances.get("Reservations", []):
            for inst in resv.get("Instances", []):
                iid = inst["InstanceId"]
                try:
                    attr = ec2.describe_instance_attribute(InstanceId=iid, Attribute="userData")
                    raw = attr.get("UserData", {}).get("Value", "")
                    if not raw:
                        continue
                    text = base64.b64decode(raw).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for hit in scan_text(text, source=f"ec2_userdata:{iid}"):
                    fid = f"secret-userdata-{iid}-{hit['detector']}"
                    findings.append(Finding(
                        id=fid,
                        source="secrets",
                        rule_id=f"secrets.ec2_userdata.{hit['detector']}",
                        severity=Severity.HIGH,
                        title=f"Secret in EC2 user-data ({iid})",
                        description=f"{hit['detector']} matched in user-data of instance {iid} (region {region}). Preview: {hit['preview']}",
                        asset=None,
                        evidence_path=Path("secrets") / f"{fid}.json",
                        cloud_context=CloudContext(
                            account_id=profile.account_id, region=region, service="ec2",
                            arn=f"arn:aws:ec2:{region}:{profile.account_id}:instance/{iid}",
                        ),
                    ))
    return findings
```

- [ ] **Step 6: Run all three tests, then commit**

Run:
```
pytest tests/whitebox/unit/test_secrets_sources_s3.py tests/whitebox/unit/test_secrets_sources_logs.py tests/whitebox/unit/test_secrets_sources_ec2_userdata.py -v
```
Expected: 4 passed total.

```bash
git add whitebox/secrets/sources/s3.py whitebox/secrets/sources/cloudwatch_logs.py whitebox/secrets/sources/ec2_userdata.py tests/whitebox/unit/test_secrets_sources_s3.py tests/whitebox/unit/test_secrets_sources_logs.py tests/whitebox/unit/test_secrets_sources_ec2_userdata.py
git commit -m "feat(whitebox): secret sources — S3 (brain-targeted), CloudWatch logs, EC2 user-data"
```

---

## Task 16: Secrets coordinator (`scanner.py`)

**Files:**
- Create: `whitebox/secrets/scanner.py`
- Modify: tests covered by integration test in Task 23

- [ ] **Step 1: Implement `whitebox/secrets/scanner.py`**

```python
from __future__ import annotations
from pathlib import Path
from whitebox.models import Finding
from whitebox.profiles import CloudProfile
from whitebox.secrets.sources import lambda_env, ssm, secretsmanager, s3, cloudwatch_logs, ec2_userdata
from whitebox.secrets.redactor import write_evidence


def run_all(profile: CloudProfile, secrets_dir: Path,
            target_buckets: list[str] | None = None,
            target_log_groups: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    findings += lambda_env.scan(profile)
    findings += ssm.scan(profile)
    findings += secretsmanager.scan(profile)
    findings += ec2_userdata.scan(profile)
    if target_buckets:
        findings += s3.scan(profile, target_buckets=target_buckets)
    if target_log_groups:
        findings += cloudwatch_logs.scan(profile, target_groups=target_log_groups)
    # Best-effort: persist evidence pointed at by each finding (caller passes hits later)
    secrets_dir.mkdir(parents=True, exist_ok=True)
    return findings
```

- [ ] **Step 2: Smoke-import to confirm wiring**

Run: `python3 -c "from whitebox.secrets.scanner import run_all; print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add whitebox/secrets/scanner.py
git commit -m "feat(whitebox): secrets coordinator dispatching to all sources"
```

---

## Task 17: Asset join (blackbox host ↔ cloud asset)

**Files:**
- Create: `whitebox/correlator/asset_join.py`
- Create: `tests/whitebox/unit/test_correlator_asset_join.py`

- [ ] **Step 1: Write the failing test**

```python
from whitebox.correlator.asset_join import join_blackbox_to_cloud
from whitebox.models import Asset


def test_join_matches_by_public_dns():
    cloud = [Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                   region="us-east-1", name="i-1", tags={},
                   public_dns="ec2-1-2-3-4.compute.amazonaws.com",
                   public_ip="1.2.3.4")]
    blackbox_hosts = ["ec2-1-2-3-4.compute.amazonaws.com"]
    result = join_blackbox_to_cloud(blackbox_hosts, cloud)
    assert result["ec2-1-2-3-4.compute.amazonaws.com"].arn == "arn:ec2:i-1"


def test_join_matches_by_public_ip():
    cloud = [Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                   region="us-east-1", name="i-1", tags={},
                   public_ip="1.2.3.4")]
    result = join_blackbox_to_cloud(["1.2.3.4"], cloud)
    assert result["1.2.3.4"].name == "i-1"


def test_join_no_match_returns_none():
    cloud = [Asset(arn="arn:ec2:i-1", service="ec2", account_id="1",
                   region="us-east-1", name="i-1", tags={}, public_ip="9.9.9.9")]
    result = join_blackbox_to_cloud(["1.2.3.4"], cloud)
    assert result["1.2.3.4"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_correlator_asset_join.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/correlator/asset_join.py`**

```python
from __future__ import annotations
from whitebox.models import Asset


def join_blackbox_to_cloud(blackbox_hosts: list[str], cloud_assets: list[Asset]) -> dict[str, Asset | None]:
    """Map each blackbox host (DNS or IP) to a cloud Asset (or None)."""
    by_dns = {a.public_dns: a for a in cloud_assets if a.public_dns}
    by_ip = {a.public_ip: a for a in cloud_assets if a.public_ip}
    return {host: by_dns.get(host) or by_ip.get(host) for host in blackbox_hosts}
```

- [ ] **Step 4: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_correlator_asset_join.py -v`
Expected: 3 passed.

```bash
git add whitebox/correlator/asset_join.py tests/whitebox/unit/test_correlator_asset_join.py
git commit -m "feat(whitebox): correlator — blackbox host ↔ cloud asset join"
```

---

## Task 18: Chain builder + severity promotion

**Files:**
- Create: `whitebox/correlator/chain_builder.py`
- Create: `whitebox/correlator/severity.py`
- Create: `tests/whitebox/unit/test_correlator_chain_builder.py`

- [ ] **Step 1: Write the failing test**

```python
from pathlib import Path
from whitebox.correlator.chain_builder import build_chains
from whitebox.correlator.severity import promote
from whitebox.models import Finding, Severity, Asset, CloudContext
from whitebox.iam.graph import IAMGraph

FIX = Path(__file__).parents[1] / "integration" / "fixtures" / "pmapper_graph_sample.json"


def test_promote_returns_critical_for_path_to_admin():
    promoted = promote(base=Severity.MEDIUM, has_imds=True, reaches_admin=True)
    assert promoted == Severity.CRITICAL


def test_promote_keeps_base_when_no_chain():
    promoted = promote(base=Severity.MEDIUM, has_imds=False, reaches_admin=False)
    assert promoted == Severity.MEDIUM


def test_build_chains_emits_chain_when_ssrf_on_ec2_with_role_to_admin():
    graph = IAMGraph.load(FIX)
    asset = Asset(arn="arn:aws:ec2:us-east-1:111:instance/i-1", service="ec2",
                  account_id="111", region="us-east-1", name="i-1",
                  tags={"iam_role_arn": "arn:aws:iam::111:role/web-prod"},
                  public_ip="1.2.3.4")
    bb = Finding(id="bb1", source="blackbox", rule_id="ssrf.basic",
                 severity=Severity.MEDIUM, title="SSRF on web.example.com",
                 description="server fetches user URL",
                 asset=asset, evidence_path=Path("/tmp"))
    chains = build_chains([bb], cloud_assets=[asset], iam_graph=graph,
                          host_to_asset={"web.example.com": asset})
    assert len(chains) == 1
    c = chains[0]
    assert c.promoted_severity == Severity.CRITICAL
    assert "admin" in c.iam_path[-1]
    assert c.promotion_rule.startswith("chain.")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_correlator_chain_builder.py -v`
Expected: FAIL — modules missing.

- [ ] **Step 3: Implement `whitebox/correlator/severity.py`**

```python
from __future__ import annotations
from whitebox.models import Severity


def promote(base: Severity, has_imds: bool, reaches_admin: bool) -> Severity:
    if has_imds and reaches_admin:
        return Severity.CRITICAL
    if reaches_admin:
        return Severity.HIGH if base < Severity.HIGH else base
    return base
```

- [ ] **Step 4: Implement `whitebox/correlator/chain_builder.py`**

```python
from __future__ import annotations
from whitebox.models import Asset, Chain, Finding
from whitebox.iam.graph import IAMGraph
from whitebox.correlator.severity import promote

# Vuln classes that benefit from IAM chain context
_CHAINABLE_RULES = {"ssrf.basic", "ssrf.imds", "rce", "rce.code_exec", "lfi.read_imds"}


def build_chains(blackbox_findings: list[Finding],
                 cloud_assets: list[Asset],
                 iam_graph: IAMGraph,
                 host_to_asset: dict[str, Asset | None]) -> list[Chain]:
    out: list[Chain] = []
    for f in blackbox_findings:
        if f.rule_id not in _CHAINABLE_RULES:
            continue
        host = f.asset.public_dns if f.asset and f.asset.public_dns else (
            f.asset.public_ip if f.asset else None)
        cloud = host_to_asset.get(host) if host else None
        if not cloud:
            continue
        role_arn = cloud.tags.get("iam_role_arn")
        if not role_arn:
            continue
        admins = iam_graph.reachable_admins(role_arn)
        if not admins:
            continue
        admin_arn = admins[0]
        path = iam_graph.can_reach(role_arn, admin_arn) or [role_arn, admin_arn]
        has_imds = "ssrf" in f.rule_id or "imds" in f.rule_id
        promoted = promote(base=f.severity, has_imds=has_imds, reaches_admin=True)
        out.append(Chain(
            trigger_finding_id=f.id,
            cloud_asset_arn=cloud.arn,
            iam_path=path,
            promoted_severity=promoted,
            promotion_rule=f"chain.{f.rule_id}+pmapper.privesc_path.{len(path)-1}_hop",
            narrative=f"Blackbox {f.rule_id} on {host} → IAM role {role_arn} → admin {admin_arn} ({len(path)-1} hop(s)).",
        ))
    return out
```

- [ ] **Step 5: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_correlator_chain_builder.py -v`
Expected: 3 passed.

```bash
git add whitebox/correlator tests/whitebox/unit/test_correlator_chain_builder.py
git commit -m "feat(whitebox): correlator — chain builder + severity promotion (rule-traced)"
```

---

## Task 19: Brain trace + orchestrator with prompts

**Files:**
- Create: `whitebox/brain/trace.py`
- Create: `whitebox/brain/prompts.py`
- Create: `whitebox/brain/orchestrator.py`
- Create: `tests/whitebox/unit/test_brain_trace.py`
- Create: `tests/whitebox/unit/test_brain_orchestrator.py`

- [ ] **Step 1: Write the failing tests**

`tests/whitebox/unit/test_brain_trace.py`:

```python
import json
from whitebox.brain.trace import BrainTrace


def test_trace_writes_jsonl_line_per_decision(tmp_path):
    t = BrainTrace(tmp_path / "brain_trace.jsonl")
    t.log("plan_phases", input_summary={"services": 5}, decision={"order": ["inventory"]})
    t.log("select_secret_targets", input_summary={"buckets": 10}, decision={"selected": ["b1"]})
    lines = (tmp_path / "brain_trace.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["decision"]["order"] == ["inventory"]
    assert "input_hash" in first
```

`tests/whitebox/unit/test_brain_orchestrator.py`:

```python
from unittest.mock import MagicMock
from whitebox.brain.orchestrator import BrainOrchestrator


def test_falls_back_to_defaults_when_brain_unreachable(tmp_path):
    fake_brain = MagicMock()
    fake_brain.ask.side_effect = RuntimeError("ollama down")
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    plan = o.plan_phases({"profile": "p", "services": ["ec2"]})
    # Default plan: all phases in fixed order
    assert plan == ["inventory", "prowler", "iam", "exposure", "secrets", "correlation", "report"]


def test_select_secret_targets_returns_brain_choice(tmp_path):
    fake_brain = MagicMock()
    fake_brain.ask.return_value = '{"buckets": ["a", "b"], "log_groups": ["/x"]}'
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    targets = o.select_secret_targets({"buckets": [{"name": "a"}, {"name": "b"}, {"name": "c"}]})
    assert targets["buckets"] == ["a", "b"]
    assert targets["log_groups"] == ["/x"]


def test_select_secret_targets_falls_back_on_brain_error(tmp_path):
    fake_brain = MagicMock()
    fake_brain.ask.side_effect = RuntimeError("x")
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    targets = o.select_secret_targets({"buckets": [{"name": "a"}, {"name": "b"}]})
    # Default: scan all buckets
    assert set(targets["buckets"]) == {"a", "b"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/whitebox/unit/test_brain_trace.py tests/whitebox/unit/test_brain_orchestrator.py -v`
Expected: FAIL — modules missing.

- [ ] **Step 3: Implement `whitebox/brain/trace.py`**

```python
from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path


class BrainTrace:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, decision_point: str, input_summary: dict, decision: dict,
            model: str = "ollama", rule_traced: str | None = None) -> None:
        payload = json.dumps(input_summary, sort_keys=True, default=str)
        h = hashlib.sha256(payload.encode()).hexdigest()[:12]
        entry = {
            "ts": time.time(),
            "decision_point": decision_point,
            "input_hash": h,
            "input_summary": input_summary,
            "decision": decision,
            "model": model,
            "rule_traced": rule_traced,
        }
        with self.path.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
```

- [ ] **Step 4: Implement `whitebox/brain/prompts.py`**

```python
PLAN_PHASES = """You orchestrate a whitebox AWS audit of account {account_id}.
Inventory summary: {inventory_summary}
Choose phase order. Return JSON: {{"order": ["inventory", "prowler", "iam", "exposure", "secrets", "correlation", "report"]}}.
"""

SELECT_SECRET_TARGETS = """Pick which S3 buckets and CloudWatch log groups are most likely to contain secrets, based on names/tags.
Buckets: {buckets}
Log groups: {log_groups}
Return JSON: {{"buckets": ["..."], "log_groups": ["..."]}}.
"""

FILTER_CHAINS = """Review candidate exploit chains. Drop false positives. Keep all rule-traced chains intact.
Chains: {chains}
Return JSON list of chain IDs to keep.
"""

EXECUTIVE_SUMMARY = """Write a 200-word executive summary of these findings for the client.
Findings: {findings_summary}
Chains: {chains_summary}
"""
```

- [ ] **Step 5: Implement `whitebox/brain/orchestrator.py`**

```python
from __future__ import annotations
import json
from pathlib import Path
from whitebox.brain.trace import BrainTrace
from whitebox.brain import prompts

DEFAULT_PHASE_ORDER = ["inventory", "prowler", "iam", "exposure", "secrets", "correlation", "report"]


class BrainOrchestrator:
    def __init__(self, brain, trace_path: Path):
        self.brain = brain
        self.trace = BrainTrace(trace_path)

    def _ask_json(self, prompt: str, fallback: dict) -> dict:
        try:
            raw = self.brain.ask(prompt)
            return json.loads(raw)
        except Exception:
            return fallback

    def plan_phases(self, ctx: dict) -> list[str]:
        prompt = prompts.PLAN_PHASES.format(
            account_id=ctx.get("profile"), inventory_summary=ctx.get("services"))
        decision = self._ask_json(prompt, fallback={"order": DEFAULT_PHASE_ORDER})
        order = decision.get("order", DEFAULT_PHASE_ORDER)
        self.trace.log("plan_phases", input_summary=ctx, decision={"order": order})
        return order

    def select_secret_targets(self, inventory_summary: dict) -> dict:
        all_buckets = [b.get("name") for b in inventory_summary.get("buckets", [])]
        all_lgs = [g.get("name") for g in inventory_summary.get("log_groups", [])]
        fallback = {"buckets": all_buckets, "log_groups": all_lgs}
        prompt = prompts.SELECT_SECRET_TARGETS.format(
            buckets=all_buckets, log_groups=all_lgs)
        decision = self._ask_json(prompt, fallback=fallback)
        out = {
            "buckets": decision.get("buckets", all_buckets),
            "log_groups": decision.get("log_groups", all_lgs),
        }
        self.trace.log("select_secret_targets",
                       input_summary={"bucket_count": len(all_buckets), "lg_count": len(all_lgs)},
                       decision=out)
        return out

    def filter_chains(self, candidates: list) -> list:
        # Defensibility: brain may only DROP chains, never ADD. Default keep all.
        prompt = prompts.FILTER_CHAINS.format(chains=[c.trigger_finding_id for c in candidates])
        decision = self._ask_json(prompt, fallback={"keep": [c.trigger_finding_id for c in candidates]})
        keep_ids = set(decision.get("keep", [c.trigger_finding_id for c in candidates]))
        kept = [c for c in candidates if c.trigger_finding_id in keep_ids]
        self.trace.log("filter_chains",
                       input_summary={"candidate_count": len(candidates)},
                       decision={"kept_count": len(kept)})
        return kept

    def write_executive_summary(self, findings: list, chains: list) -> str:
        try:
            return self.brain.ask(prompts.EXECUTIVE_SUMMARY.format(
                findings_summary=[f.title for f in findings[:20]],
                chains_summary=[c.narrative for c in chains[:5]],
            ))
        except Exception:
            return ""
```

- [ ] **Step 6: Run tests, then commit**

Run: `pytest tests/whitebox/unit/test_brain_trace.py tests/whitebox/unit/test_brain_orchestrator.py -v`
Expected: 4 passed.

```bash
git add whitebox/brain tests/whitebox/unit/test_brain_trace.py tests/whitebox/unit/test_brain_orchestrator.py
git commit -m "feat(whitebox): brain orchestrator (Ollama) + trace + decision-point prompts"
```

---

## Task 20: Reporting — posture chapter + correlation inline + evidence dump

**Files:**
- Create: `whitebox/reporting/posture_chapter.py`
- Create: `whitebox/reporting/correlation_inline.py`
- Create: `whitebox/reporting/evidence.py`
- Create: `tests/whitebox/unit/test_reporting_posture_chapter.py`
- Create: `tests/whitebox/unit/test_reporting_correlation_inline.py`

- [ ] **Step 1: Write the failing tests**

`tests/whitebox/unit/test_reporting_posture_chapter.py`:

```python
from pathlib import Path
from whitebox.reporting.posture_chapter import render
from whitebox.models import Finding, Severity, CloudContext


def test_render_returns_html_with_account_summary():
    findings = [Finding(id="f1", source="prowler", rule_id="iam_root_mfa_enabled",
                        severity=Severity.CRITICAL, title="Root MFA off",
                        description="...", asset=None, evidence_path=Path("x"),
                        cloud_context=CloudContext(account_id="111", region="us-east-1",
                                                   service="iam", arn=""))]
    html = render(account_id="111", findings=findings, executive_summary="All good.")
    assert "<h2" in html
    assert "111" in html
    assert "Critical" in html or "critical" in html
    assert "Root MFA off" in html


def test_render_handles_no_findings():
    html = render(account_id="111", findings=[], executive_summary="")
    assert "111" in html
    assert "no findings" in html.lower() or "0 findings" in html.lower()
```

`tests/whitebox/unit/test_reporting_correlation_inline.py`:

```python
from pathlib import Path
from whitebox.reporting.correlation_inline import render_for_finding
from whitebox.models import Finding, Severity, Chain, CloudContext, BlastRadius


def test_render_inline_includes_blast_radius_and_chain():
    ctx = CloudContext(account_id="1", region="us-east-1", service="ec2",
                       arn="arn:ec2:i-1", iam_role_arn="arn:role/web",
                       blast_radius=BlastRadius(principal_arn="arn:role/web",
                                                s3_buckets=["b1"], kms_keys=[],
                                                lambdas=[], assumable_roles=["arn:role/admin"], regions=[]))
    chain = Chain(trigger_finding_id="bb1", cloud_asset_arn="arn:ec2:i-1",
                  iam_path=["arn:role/web", "arn:role/admin"],
                  promoted_severity=Severity.CRITICAL,
                  promotion_rule="chain.ssrf+pmapper.1_hop",
                  narrative="SSRF → role → admin")
    f = Finding(id="bb1", source="blackbox", rule_id="ssrf.basic",
                severity=Severity.MEDIUM, title="SSRF", description="x",
                asset=None, evidence_path=Path("/tmp"),
                cloud_context=ctx, chain=chain)
    html = render_for_finding(f)
    assert "Cloud context" in html
    assert "arn:role/web" in html
    assert "Critical" in html or "critical" in html
    assert "blast" in html.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/whitebox/unit/test_reporting_posture_chapter.py tests/whitebox/unit/test_reporting_correlation_inline.py -v`
Expected: FAIL — modules missing.

- [ ] **Step 3: Implement `whitebox/reporting/posture_chapter.py`**

```python
from __future__ import annotations
from collections import Counter
from html import escape
from whitebox.models import Finding, Severity


def render(account_id: str, findings: list[Finding], executive_summary: str = "") -> str:
    if not findings:
        body = f"<p>No cloud findings for account <code>{escape(account_id)}</code>.</p>"
        return f'<section class="cloud-posture"><h2>Cloud Posture — Account {escape(account_id)} (0 findings)</h2>{body}</section>'

    by_sev = Counter(f.severity.label() for f in findings)
    by_source = Counter(f.source for f in findings)
    rows = "".join(
        f"<tr><td>{escape(f.severity.label())}</td><td>{escape(f.source)}</td>"
        f"<td>{escape(f.rule_id)}</td><td>{escape(f.title)}</td>"
        f"<td><code>{escape((f.cloud_context.arn if f.cloud_context else '') or '')}</code></td></tr>"
        for f in sorted(findings, key=lambda x: -int(x.severity))
    )
    sev_summary = " · ".join(f"{escape(k)}: {v}" for k, v in by_sev.most_common())
    src_summary = " · ".join(f"{escape(k)}: {v}" for k, v in by_source.most_common())
    return f"""
<section class="cloud-posture">
  <h2>Cloud Posture — Account {escape(account_id)}</h2>
  <p class="exec-summary">{escape(executive_summary)}</p>
  <p><strong>Severity:</strong> {sev_summary}<br>
     <strong>Source:</strong> {src_summary}</p>
  <table class="cloud-findings">
    <thead><tr><th>Severity</th><th>Source</th><th>Rule</th><th>Title</th><th>Resource</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>
"""
```

- [ ] **Step 4: Implement `whitebox/reporting/correlation_inline.py`**

```python
from __future__ import annotations
from html import escape
from whitebox.models import Finding


def render_for_finding(f: Finding) -> str:
    if not f.cloud_context:
        return ""
    ctx = f.cloud_context
    parts = [
        f'<div class="cloud-context"><h4>Cloud context</h4>',
        f'<p>Account: <code>{escape(ctx.account_id)}</code> · Region: <code>{escape(ctx.region)}</code> · Service: <code>{escape(ctx.service)}</code></p>',
        f'<p>ARN: <code>{escape(ctx.arn)}</code></p>',
    ]
    if ctx.iam_role_arn:
        parts.append(f'<p>IAM role: <code>{escape(ctx.iam_role_arn)}</code></p>')
    if ctx.blast_radius:
        br = ctx.blast_radius
        parts.append(
            f'<p>IAM blast radius: '
            f'{len(br.s3_buckets)} buckets · {len(br.kms_keys)} KMS keys · '
            f'{len(br.lambdas)} lambdas · {len(br.assumable_roles)} assumable roles</p>'
        )
    if ctx.exposed_ports:
        parts.append(f'<p>Exposed ports: <code>{", ".join(map(str, ctx.exposed_ports))}</code></p>')
    if ctx.exposed_cidrs:
        parts.append(f'<p>Exposed CIDRs: <code>{", ".join(map(escape, ctx.exposed_cidrs))}</code></p>')
    if f.chain:
        c = f.chain
        parts.append('<h4>Auto-built chain</h4>')
        parts.append(f'<p><strong>Promoted severity: {escape(c.promoted_severity.label())}</strong> '
                     f'(rule: <code>{escape(c.promotion_rule)}</code>)</p>')
        parts.append(f'<p>{escape(c.narrative)}</p>')
        parts.append('<ol class="iam-path">' + "".join(
            f'<li><code>{escape(arn)}</code></li>' for arn in c.iam_path) + '</ol>')
    parts.append('</div>')
    return "\n".join(parts)
```

- [ ] **Step 5: Implement `whitebox/reporting/evidence.py`**

```python
from __future__ import annotations
import json
from pathlib import Path
from whitebox.models import Finding


def dump_findings(findings: list[Finding], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
    return path
```

- [ ] **Step 6: Run tests, then commit**

Run: `pytest tests/whitebox/unit/test_reporting_posture_chapter.py tests/whitebox/unit/test_reporting_correlation_inline.py -v`
Expected: 4 passed.

```bash
git add whitebox/reporting tests/whitebox/unit/test_reporting_posture_chapter.py tests/whitebox/unit/test_reporting_correlation_inline.py
git commit -m "feat(whitebox): reporting — posture chapter + inline correlation + evidence dump"
```

---

## Task 21: Top-level CLI `cloud_hunt.py`

**Files:**
- Create: `whitebox/cloud_hunt.py`
- Create: `whitebox/orchestrator.py`
- Create: `tests/whitebox/unit/test_cloud_hunt_cli.py`

- [ ] **Step 1: Write the failing test**

```python
import sys
from unittest.mock import patch, MagicMock
from whitebox.cloud_hunt import main


def test_cli_requires_profile_arg(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["cloud_hunt"])
    rc = main()
    out = capsys.readouterr()
    assert rc != 0
    assert "--profile" in (out.out + out.err)


def test_cli_calls_orchestrator_with_profile(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", [
        "cloud_hunt", "--profile", "client-erp",
        "--session-dir", str(tmp_path),
    ])
    fake_run = MagicMock(return_value=0)
    with patch("whitebox.cloud_hunt.run_for_profile", fake_run):
        rc = main()
    assert rc == 0
    fake_run.assert_called_once()
    args, kwargs = fake_run.call_args
    assert kwargs.get("profile_name") == "client-erp" or "client-erp" in args
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/whitebox/unit/test_cloud_hunt_cli.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `whitebox/orchestrator.py`**

```python
from __future__ import annotations
from pathlib import Path
from whitebox.profiles import CloudProfile, validate
from whitebox.inventory import collector, route53, normalizer
from whitebox.audit import prowler_runner
from whitebox.audit.normalizer import to_findings as prowler_to_findings
from whitebox.iam.pmapper_runner import build_graph
from whitebox.iam.graph import IAMGraph
from whitebox.iam.privesc import detect_paths
from whitebox.exposure.analyzer import analyze_security_groups
from whitebox.exposure.tagger import tag_assets
from whitebox.secrets.scanner import run_all as run_secrets
from whitebox.correlator.asset_join import join_blackbox_to_cloud
from whitebox.correlator.chain_builder import build_chains
from whitebox.brain.orchestrator import BrainOrchestrator
from whitebox.reporting.evidence import dump_findings
from whitebox.cache.manifest import PhaseCache
from whitebox.models import Finding


def run_for_profile(profile_name: str, session_dir: Path,
                    refresh: bool = False, brain=None) -> int:
    """End-to-end whitebox audit for one profile. Returns 0 on success."""
    session_dir = Path(session_dir)
    profile = validate(CloudProfile(name=profile_name))
    profile.in_scope_domains = route53.in_scope_domains(profile)

    account_dir = session_dir / "cloud" / profile.account_id
    account_dir.mkdir(parents=True, exist_ok=True)
    cache = PhaseCache(account_dir)
    if refresh:
        cache.refresh()

    findings: list[Finding] = []

    # Phase A — inventory
    inv_dir = account_dir / "inventory"
    if not cache.is_fresh("inventory"):
        try:
            collector.collect_all(profile, inv_dir)
            cache.mark_complete("inventory")
        except Exception as e:
            cache.mark_failed("inventory", error=str(e))
    assets = normalizer.from_inventory_dir(profile.account_id, inv_dir)

    # Phase B — Prowler
    prowler_dir = account_dir / "prowler"
    if not cache.is_fresh("prowler"):
        try:
            ocsf = prowler_runner.run(profile, prowler_dir)
            findings += prowler_to_findings(prowler_runner.parse(ocsf), profile.account_id)
            cache.mark_complete("prowler")
        except Exception as e:
            cache.mark_failed("prowler", error=str(e))

    # Phase C — IAM (PMapper)
    pmap_dir = account_dir / "pmapper"
    if not cache.is_fresh("iam"):
        try:
            graph_path = build_graph(profile, pmap_dir)
            graph = IAMGraph.load(graph_path)
            findings += detect_paths(graph, profile.account_id)
            cache.mark_complete("iam", artifacts={"graph": str(graph_path)})
        except Exception as e:
            graph = None
            cache.mark_failed("iam", error=str(e))
    else:
        graph = IAMGraph.load(pmap_dir / "graph.json")

    # Phase D — Exposure
    sg_data: list[dict] = []
    for f in (inv_dir / "ec2_sg").glob("*.json"):
        import json as _json
        sg_data += _json.loads(f.read_text()).get("SecurityGroups", [])
    sg_analysis = analyze_security_groups(sg_data)
    assets = tag_assets(assets, instance_sg_map={}, sg_analysis=sg_analysis,
                        waf_protected_arns=set())
    cache.mark_complete("exposure")

    # Phase E — Secrets (brain selects targets)
    secrets_dir = account_dir / "secrets"
    if brain is not None:
        bo = BrainOrchestrator(brain=brain, trace_path=account_dir / "brain_trace.jsonl")
        targets = bo.select_secret_targets({
            "buckets": [{"name": a.name} for a in assets if a.service == "s3"],
            "log_groups": [],
        })
    else:
        targets = {"buckets": [a.name for a in assets if a.service == "s3"], "log_groups": []}
    findings += run_secrets(profile, secrets_dir,
                            target_buckets=targets["buckets"],
                            target_log_groups=targets["log_groups"])
    cache.mark_complete("secrets")

    # Phase F — Correlation (no blackbox findings supplied at this layer; orchestrator returns
    # the asset feed; chain_builder is wired by the caller that has both sides)
    asset_feed_path = (session_dir / "cloud" / "correlation")
    asset_feed_path.mkdir(parents=True, exist_ok=True)
    import json as _json
    (asset_feed_path / "asset_feed.json").write_text(_json.dumps(
        [{"arn": a.arn, "service": a.service, "region": a.region, "name": a.name,
          "public_dns": a.public_dns, "public_ip": a.public_ip, "tags": a.tags} for a in assets],
        indent=2,
    ))
    cache.mark_complete("correlation")

    # Phase G — Evidence dump
    dump_findings(findings, account_dir / "findings.json")
    cache.mark_complete("report")
    return 0
```

- [ ] **Step 4: Implement `whitebox/cloud_hunt.py`**

```python
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from whitebox.orchestrator import run_for_profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cloud_hunt",
                                     description="Vikramaditya whitebox AWS audit")
    parser.add_argument("--profile", action="append", required=False,
                        help="AWS profile name (repeatable)")
    parser.add_argument("--session-dir", default="recon/cloud-only/sessions/default",
                        help="Session output directory")
    parser.add_argument("--refresh", action="store_true",
                        help="Bust phase cache and re-run all phases")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if not args.profile:
        parser.print_help(sys.stderr)
        return 2

    rc = 0
    for prof in args.profile:
        rc |= run_for_profile(profile_name=prof,
                              session_dir=Path(args.session_dir),
                              refresh=args.refresh)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run test, then commit**

Run: `pytest tests/whitebox/unit/test_cloud_hunt_cli.py -v`
Expected: 2 passed.

```bash
git add whitebox/cloud_hunt.py whitebox/orchestrator.py tests/whitebox/unit/test_cloud_hunt_cli.py
git commit -m "feat(whitebox): top-level cloud_hunt CLI + per-profile orchestrator with phase caching"
```

---

## Task 22: Integration into `vikramaditya.py`, `hunt.py`, `reporter.py`

**Files:**
- Modify: `vikramaditya.py` — add whitebox phase detection + invocation
- Modify: `hunt.py` — consume `cloud/correlation/asset_feed.json`
- Modify: `reporter.py` — render cloud posture chapter + inline correlation

- [ ] **Step 1: Inspect insertion points**

Run:
```
grep -n "def main\|def run\|argparse" vikramaditya.py | head -20
grep -n "def main\|def run_recon\|targets =" hunt.py | head -20
grep -n "render_html_report\|process_findings_dir" reporter.py | head -20
```

Note the line numbers for the integration edits below.

- [ ] **Step 2: Add whitebox auto-detection in `vikramaditya.py`**

Insert near the top of `main()` (after target detection, before scan execution). The exact location depends on Step 1 — pick the spot just before `hunt.py` would be invoked, and append:

```python
# ── Whitebox VAPT auto-detect ──────────────────────────────────────────
import yaml
from pathlib import Path as _Path
config_path = _Path("whitebox_config.yaml")
if config_path.exists():
    cfg = yaml.safe_load(config_path.read_text()) or {}
    matched_profiles = [p for p, meta in cfg.get("profiles", {}).items()
                        if target in meta.get("domains", [])]
    if matched_profiles:
        print(f"[whitebox] target {target} matched profiles: {matched_profiles}")
        ans = input("Run cloud whitebox audit alongside blackbox? [Y/n]: ").strip().lower()
        if ans in ("", "y", "yes"):
            from whitebox.cloud_hunt import main as cloud_main
            cloud_main(["--profile"] + sum([["--profile", p] for p in matched_profiles], [])
                       + ["--session-dir", str(session_dir)])
```

(Replace `target` and `session_dir` with the variable names actually used in the surrounding code — `vikramaditya.py` defines them.)

- [ ] **Step 3: Make `hunt.py` consume the asset feed**

Find the section where `hunt.py` builds its initial target list (look for the result of subdomain enumeration). Add immediately after that block:

```python
# ── Whitebox asset-feed enrichment ─────────────────────────────────────
import json as _json
from pathlib import Path as _P
asset_feed = _P(session_dir) / "cloud" / "correlation" / "asset_feed.json"
if asset_feed.exists():
    extra: list[str] = []
    for a in _json.loads(asset_feed.read_text()):
        if a.get("tags", {}).get("internet_reachable"):
            for h in (a.get("public_dns"), a.get("public_ip")):
                if h:
                    extra.append(h)
    if extra:
        log("info", f"[whitebox] adding {len(extra)} cloud-discovered assets to scan list")
        # Prepend so prioritized assets get scanned first
        targets = list(dict.fromkeys(extra + list(targets)))
```

(Variable name `targets` and `session_dir` must match the surrounding context — adjust as needed.)

- [ ] **Step 4: Wire reporter integration**

In `reporter.py`, inside `render_html_report()`, after the existing findings table is rendered, append:

```python
# ── Whitebox cloud chapter ─────────────────────────────────────────────
try:
    from whitebox.reporting.posture_chapter import render as _render_cloud
    from whitebox.reporting.correlation_inline import render_for_finding as _render_inline
    cloud_dir = _P(report_dir).parent / "cloud"
    if cloud_dir.exists():
        for acct_dir in cloud_dir.iterdir():
            if not acct_dir.is_dir() or acct_dir.name == "correlation":
                continue
            findings_json = acct_dir / "findings.json"
            if not findings_json.exists():
                continue
            import json as _json
            data = _json.loads(findings_json.read_text())
            from whitebox.models import Finding, Severity, CloudContext
            from pathlib import Path as _Path2
            cloud_findings = []
            for d in data:
                ctx = d.get("cloud_context")
                cc = CloudContext(**ctx) if ctx else None
                cloud_findings.append(Finding(
                    id=d["id"], source=d["source"], rule_id=d["rule_id"],
                    severity=Severity[d["severity"].upper()], title=d["title"],
                    description=d["description"], asset=None,
                    evidence_path=_Path2(d["evidence_path"]),
                    cloud_context=cc,
                ))
            html_chapter = _render_cloud(
                account_id=acct_dir.name, findings=cloud_findings, executive_summary="")
            html += html_chapter
except Exception as _e:
    pass  # whitebox report enrichment is optional
```

(`html` and `report_dir` must match the existing variable names in `render_html_report` — open the file at the line numbers from Step 1 to confirm.)

- [ ] **Step 5: Verify imports compile**

Run: `python3 -c "import vikramaditya; import hunt; import reporter; print('ok')"`
Expected: `ok` (any failure here means the integration edits broke an import — fix before committing).

- [ ] **Step 6: Commit**

```bash
git add vikramaditya.py hunt.py reporter.py
git commit -m "feat(whitebox): integrate cloud audit into vikramaditya/hunt/reporter"
```

---

## Task 23: End-to-end mocked integration test

**Files:**
- Create: `tests/whitebox/integration/test_end_to_end_mocked.py`

- [ ] **Step 1: Write the failing test**

```python
import json
from pathlib import Path
import boto3
import pytest
from moto import mock_aws
from whitebox.orchestrator import run_for_profile


@pytest.fixture
def session_dir(tmp_path):
    return tmp_path / "session"


@mock_aws
def test_end_to_end_seeded_account_produces_findings(session_dir, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    # Seed: public S3, leaky Lambda env, vulnerable SSM SecureString
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="leaky-bucket")
    iam = boto3.client("iam")
    iam.create_role(RoleName="lambda-role", AssumeRolePolicyDocument="{}")
    role_arn = iam.get_role(RoleName="lambda-role")["Role"]["Arn"]
    lam = boto3.client("lambda", region_name="us-east-1")
    lam.create_function(
        FunctionName="leaky-fn", Runtime="python3.11", Role=role_arn,
        Handler="x.handler", Code={"ZipFile": b"def handler(e,c):pass"},
        Environment={"Variables": {"AWS_KEY": "AKIAIOSFODNN7EXAMPLE"}},
    )
    ssm = boto3.client("ssm", region_name="us-east-1")
    ssm.put_parameter(Name="/secret/key", Type="SecureString", Value="AKIAIOSFODNN7EXAMPLE")

    # Stub out subprocess wrappers (Prowler + PMapper not available in test env)
    from unittest.mock import patch
    fixture_dir = Path(__file__).parent / "fixtures"
    with patch("whitebox.audit.prowler_runner.run") as mock_prowler, \
         patch("whitebox.iam.pmapper_runner.build_graph") as mock_pmap, \
         patch("whitebox.profiles.boto3.Session", side_effect=lambda **kw: boto3.Session(region_name="us-east-1")):
        mock_prowler.return_value = fixture_dir / "prowler_ocsf_sample.json"
        mock_pmap.return_value = fixture_dir / "pmapper_graph_sample.json"

        rc = run_for_profile(profile_name="default",
                             session_dir=session_dir, refresh=True, brain=None)

    assert rc == 0
    findings_file = session_dir / "cloud" / "111" / "findings.json"
    # Account ID under moto defaults to "123456789012" — adjust if needed
    found = list((session_dir / "cloud").glob("*/findings.json"))
    assert found, "no findings.json produced"
    data = json.loads(found[0].read_text())
    rule_ids = {f["rule_id"] for f in data}
    # Should have at least one Prowler finding, one Lambda env secret, one SSM secret, one PMapper privesc
    assert any(r.startswith("secrets.lambda_env.") for r in rule_ids)
    assert any(r.startswith("secrets.ssm.") for r in rule_ids)
    assert any(r.startswith("pmapper.") for r in rule_ids)
    assert any(r.startswith("iam_root_mfa") or r.startswith("s3_bucket_public") for r in rule_ids)
```

- [ ] **Step 2: Run test to verify it fails (then iterate until it passes)**

Run: `pytest tests/whitebox/integration/test_end_to_end_mocked.py -v`
Expected on first run: FAIL. Iterate on integration glue until all four `assert any(...)` lines pass. Common adjustments:

- `account_id` returned by STS under moto is `"123456789012"`, not `"111"` — update fixture or normalize the `findings.json` path lookup as in the test (`glob("*/findings.json")`).
- `whitebox.profiles.boto3.Session` is patched to share the moto in-memory state.

- [ ] **Step 3: Commit when green**

```bash
git add tests/whitebox/integration/test_end_to_end_mocked.py
git commit -m "test(whitebox): end-to-end integration with seeded vulnerable account"
```

---

## Task 24: Real-account smoke test (opt-in)

**Files:**
- Create: `tests/whitebox/smoke/test_real_aws.py`

- [ ] **Step 1: Write the smoke test (gated by env var)**

```python
import os
import pytest
from pathlib import Path
from whitebox.profiles import CloudProfile, validate

pytestmark = pytest.mark.skipif(
    os.environ.get("WHITEBOX_SMOKE") != "1",
    reason="set WHITEBOX_SMOKE=1 to run real-account tests",
)


@pytest.mark.parametrize("profile_name,expected_account", [
    ("client-erp",     "111122223333"),
    ("example-example-data", "444455556666"),
])
def test_validate_real_profile(profile_name, expected_account):
    prof = validate(CloudProfile(name=profile_name))
    assert prof.account_id == expected_account
    assert prof.permission_probe["simulate_principal_policy"] is True


@pytest.mark.parametrize("profile_name", ["client-erp", "example-example-data"])
def test_route53_zones_returned(profile_name):
    from whitebox.inventory.route53 import in_scope_domains
    prof = validate(CloudProfile(name=profile_name))
    domains = in_scope_domains(prof)
    # At least one of the expected domains should appear
    assert any(d.endswith(".com") for d in domains), f"no zones for {profile_name}"
```

- [ ] **Step 2: Run normally (skipped) to verify gating**

Run: `pytest tests/whitebox/smoke/test_real_aws.py -v`
Expected: 4 SKIPPED.

- [ ] **Step 3: Run with opt-in flag (against real AWS)**

Run: `WHITEBOX_SMOKE=1 pytest tests/whitebox/smoke/test_real_aws.py -v`
Expected: 4 PASSED. If permissions or profile names differ, fix profile setup before proceeding.

- [ ] **Step 4: Commit**

```bash
git add tests/whitebox/smoke/test_real_aws.py
git commit -m "test(whitebox): opt-in smoke test for client-erp + example-example-data profiles"
```

---

## Task 25: Whitebox config file + documentation

**Files:**
- Create: `whitebox_config.yaml` (committed default; user-editable)
- Modify: `CLAUDE.md` — add whitebox section
- Modify: `README.md` — add whitebox quick usage

- [ ] **Step 1: Create `whitebox_config.yaml`**

```yaml
# Vikramaditya Whitebox — profile ↔ in-scope domain mapping
# Auto-populated from Route53 on first run; edit to override.
profiles:
  client-erp:
    account_id: "111122223333"
    display: "ADF ERP"
    domains:
      - example-prod.invalid
  example-example-data:
    account_id: "444455556666"
    display: "ADF Pranapr"
    domains:
      - example-data.invalid

# Per-engagement runtime defaults
defaults:
  cache_ttl_seconds: 86400
  pmapper_timeout_seconds: 1800
  prowler_timeout_seconds: 1800
  max_secrets_per_source: 500
```

- [ ] **Step 2: Add CLAUDE.md section**

Append to `CLAUDE.md`:

```markdown
## Whitebox VAPT (AWS Cloud Integration)

Run alongside blackbox to add cloud audit, IAM blast-radius, secrets scanning,
and exploit chaining.

```bash
# Standalone whitebox audit (single account)
python3 -m whitebox.cloud_hunt --profile client-erp --session-dir recon/example-prod.invalid/sessions/<id>

# Both accounts
python3 -m whitebox.cloud_hunt --profile client-erp --profile example-example-data \
  --session-dir recon/<target>/sessions/<id>

# Bust the 24h phase cache and re-run everything
python3 -m whitebox.cloud_hunt --profile client-erp --refresh --session-dir <dir>
```

When `vikramaditya.py` runs, it auto-detects whether the target domain is
listed in `whitebox_config.yaml`. If so, it offers to run cloud whitebox
alongside blackbox; the `cloud/` directory under the session is populated and
the final report includes a "Cloud Posture" chapter plus inline cloud context
on each blackbox finding.

**Required external tools:**
- `prowler-cloud` (pip): `pip install prowler-cloud==4.5.0`
- `principalmapper` (pip): `pip install principalmapper`

**Permission gaps:** Whitebox falls back to metadata-only when
`secretsmanager:GetSecretValue` is denied. To enable full secret-value
scanning, add `secretsmanager:GetSecretValue` to the audit user's policy.
```

- [ ] **Step 3: Add README quick-start row**

In `README.md`, in the table that lists tools, add:

```markdown
| `whitebox/cloud_hunt.py` | **Whitebox VAPT** — AWS audit (Prowler + PMapper + secrets), feeds blackbox |
```

- [ ] **Step 4: Commit**

```bash
git add whitebox_config.yaml CLAUDE.md README.md
git commit -m "docs(whitebox): config file + CLAUDE.md and README integration notes"
```

---

## Task 26: Full test sweep + smoke run

- [ ] **Step 1: Run full whitebox unit test sweep**

Run: `pytest tests/whitebox/unit -v`
Expected: all passed. If any fail, fix before proceeding.

- [ ] **Step 2: Run integration test**

Run: `pytest tests/whitebox/integration -v`
Expected: passed.

- [ ] **Step 3: Run real-account smoke test against both profiles**

Run: `WHITEBOX_SMOKE=1 pytest tests/whitebox/smoke -v`
Expected: 4 passed (validates STS + Route53 against real AWS).

- [ ] **Step 4: End-to-end live run on one profile**

Run:
```
python3 -m whitebox.cloud_hunt --profile client-erp \
  --session-dir recon/example-prod.invalid/sessions/whitebox-smoke
```
Expected: completes (may take 30–60 min). Inspect `recon/example-prod.invalid/sessions/whitebox-smoke/cloud/111122223333/findings.json`.

- [ ] **Step 5: Generate full report**

Run:
```
python3 reporter.py recon/example-prod.invalid/sessions/whitebox-smoke/findings/ \
  --client "ADF" --target example-prod.invalid
```
Inspect the HTML output for the "Cloud Posture — Account 111122223333" chapter and any inline cloud context.

- [ ] **Step 6: Commit smoke artifacts (only the report files, not raw secrets)**

```bash
git status
# Verify cloud/secrets/ is gitignored (per Task 0)
git add recon/example-prod.invalid/sessions/whitebox-smoke/reports/
git commit -m "test(whitebox): smoke run report artifacts for client-erp"
```

---

## Self-Review Notes

**Spec coverage:**
- Q1 (Full whitebox): Tasks 1–22 cover all four pillars (audit, asset correlation, insider analysis, cross-correlation).
- Q2 (Multi-domain per account): Task 5 enumerates Route53 zones; Task 25 config file maps domains.
- Q3 (Standalone package): Task 0 establishes `whitebox/`; Task 22 wires three integration points.
- Q4 (Cloud Posture chapter + inline): Task 20 implements both renderers; Task 22 wires reporter.
- Q5 (Wrap Prowler): Task 6.
- Q6 (PMapper graph): Tasks 8 and 9.
- Q7 (Aggressive secrets including GetSecretValue): Tasks 10–16. Permission-gap fallback in Task 14.
- Q8 (Tagged exposure surface): Task 7 + asset feed in Task 21 + hunt.py consumer in Task 22.
- Q9 (Auto-chained findings + severity promotion): Task 18.
- Q10 (Sequential + cached): Task 2 (cache), Task 21 (orchestrator uses cache).
- Q11 (Brain orchestrates everything): Task 19. Defensibility constraint enforced in `chain_builder.py` (rule_id required) and `BrainOrchestrator.filter_chains` (brain may only DROP, never ADD).

**Placeholder scan:** None remain.

**Type consistency:** `Finding`, `Asset`, `Chain`, `BlastRadius`, `CloudContext`, `Severity`, `IAMGraph`, `CloudProfile`, `BrainOrchestrator`, `PhaseCache` are all defined in their respective tasks before being referenced. Method names verified consistent (`reachable_admins`, `can_reach`, `blast_radius`, `select_secret_targets`, `plan_phases`, `filter_chains`, `write_executive_summary`).

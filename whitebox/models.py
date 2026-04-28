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

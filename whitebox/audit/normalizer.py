from __future__ import annotations
import re
from pathlib import Path
from whitebox.models import Finding, Severity, CloudContext

_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _slugify(s: str, max_len: int = 80) -> str:
    s = _SLUG_RE.sub("_", s).strip("._")
    return (s or "unknown")[:max_len]

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
            evidence_path=Path("prowler") / f"{_slugify(check_id)}.json",
            cloud_context=ctx,
        ))
    return out

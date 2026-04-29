"""Normalize raw boto3 inventory JSON into typed Asset objects.

Intentional starter set: EC2 instances and S3 buckets only. Extend this
module before Task 17 (asset_join) — it will need ELBv2 load balancers,
Lambda functions, EKS clusters, RDS instances, and CloudFront distributions
to join blackbox-discovered hosts to their cloud asset records.
"""
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
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    iam_profile = inst.get("IamInstanceProfile") or {}
                    iam_arn = iam_profile.get("Arn", "")
                    if iam_arn:
                        if ":instance-profile/" in iam_arn:
                            tags["iam_role_arn"] = iam_arn.replace(":instance-profile/", ":role/", 1)
                        else:
                            tags["iam_role_arn"] = iam_arn
                    assets.append(Asset(
                        arn=f"arn:aws:ec2:{region}:{account_id}:instance/{inst['InstanceId']}",
                        service="ec2", account_id=account_id, region=region,
                        name=inst["InstanceId"], tags=tags,
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

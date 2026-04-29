"""Verify the default no-brain secret-source heuristic."""
from pathlib import Path
from unittest.mock import patch
import json
import pytest
import boto3


@pytest.fixture
def session_dir(tmp_path):
    return tmp_path / "session"


def _make_inventory(inv_dir: Path, buckets: list, log_groups: list) -> None:
    """Seed minimal inventory JSON files."""
    s3_dir = inv_dir / "s3"
    s3_dir.mkdir(parents=True, exist_ok=True)
    (s3_dir / "global.json").write_text(json.dumps({
        "Buckets": [{"Name": b} for b in buckets],
    }))
    logs_dir = inv_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "us-east-1.json").write_text(json.dumps({
        "logGroups": [{"logGroupName": lg} for lg in log_groups],
    }))


def test_default_heuristic_filters_secret_buckets(session_dir, monkeypatch):
    """No brain → run_secrets must receive only buckets/groups whose names hint at secrets."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    from whitebox.orchestrator import run_for_profile

    # Pre-build inventory directly
    inv_dir = session_dir / "cloud" / "123456789012" / "inventory"
    _make_inventory(inv_dir, buckets=[
        "company-website",          # NOT a secret target
        "config-backups",           # secret target (config + backup)
        "user-uploads",             # NOT
        "infra-terraform-state",    # secret target (infra/terraform)
        "dev-env-dumps",            # secret target (dev/env/dump)
    ], log_groups=[
        "/aws/lambda/web-handler",     # NOT
        "/aws/lambda/secret-rotator",  # secret target
    ])

    captured = {}

    def fake_run_secrets(profile, secrets_dir, target_buckets=None, target_log_groups=None):
        captured["buckets"] = target_buckets
        captured["log_groups"] = target_log_groups
        return []

    def fake_validate(profile):
        import boto3
        profile.account_id = "123456789012"
        profile.arn = "arn:aws:iam::123456789012:user/test"
        profile.regions = ["us-east-1"]
        profile._session = boto3.Session(region_name="us-east-1")
        profile.permission_probe = {"simulate_principal_policy": True}
        return profile

    with patch("whitebox.orchestrator.validate", side_effect=fake_validate), \
         patch("whitebox.orchestrator.collector.collect_all"), \
         patch("whitebox.orchestrator.prowler_runner.run", side_effect=Exception("skip")), \
         patch("whitebox.orchestrator.build_graph", side_effect=Exception("skip")), \
         patch("whitebox.orchestrator.run_secrets", side_effect=fake_run_secrets), \
         patch("whitebox.orchestrator.route53.in_scope_domains", return_value=["test.local"]):
        run_for_profile(profile_name="test", session_dir=session_dir,
                        refresh=False, brain=None, authorized_allowlist=["*"])

    assert "config-backups" in captured["buckets"]
    assert "infra-terraform-state" in captured["buckets"]
    assert "dev-env-dumps" in captured["buckets"]
    assert "company-website" not in captured["buckets"]
    assert "user-uploads" not in captured["buckets"]
    assert "/aws/lambda/secret-rotator" in captured["log_groups"]
    assert "/aws/lambda/web-handler" not in captured["log_groups"]


def test_heuristic_records_coverage_in_manifest(session_dir, monkeypatch):
    """secrets phase manifest must record how many buckets/groups were skipped vs scanned."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    from whitebox.orchestrator import run_for_profile

    inv_dir = session_dir / "cloud" / "123456789012" / "inventory"
    _make_inventory(inv_dir, buckets=["company-website", "config-backups"], log_groups=[])

    def fake_validate(profile):
        profile.account_id = "123456789012"
        profile.arn = "arn:aws:iam::123456789012:user/test"
        profile.regions = ["us-east-1"]
        profile._session = boto3.Session(region_name="us-east-1")
        profile.permission_probe = {"simulate_principal_policy": True}
        return profile

    with patch("whitebox.orchestrator.validate", side_effect=fake_validate), \
         patch("whitebox.orchestrator.collector.collect_all"), \
         patch("whitebox.orchestrator.prowler_runner.run", side_effect=Exception("skip")), \
         patch("whitebox.orchestrator.build_graph", side_effect=Exception("skip")), \
         patch("whitebox.orchestrator.run_secrets", return_value=[]), \
         patch("whitebox.orchestrator.route53.in_scope_domains", return_value=["test.local"]):
        run_for_profile(profile_name="test", session_dir=session_dir,
                        refresh=False, brain=None, authorized_allowlist=["*"])

    manifest = json.loads((session_dir / "cloud" / "123456789012" / "manifest.json").read_text())
    secrets_artifacts = manifest["secrets"]["artifacts"]
    assert secrets_artifacts["selection_mode"] == "heuristic"
    assert secrets_artifacts["buckets_total"] == 2
    assert secrets_artifacts["buckets_scanned"] == 1     # only config-backups passes
    assert secrets_artifacts["buckets_skipped"] == 1     # company-website skipped

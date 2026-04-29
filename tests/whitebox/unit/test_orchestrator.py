from unittest.mock import patch
import pytest
from pathlib import Path
from whitebox.orchestrator import run_for_profile


def test_run_for_profile_requires_allowlist():
    with pytest.raises(ValueError, match="authorized_allowlist"):
        run_for_profile(profile_name="x", session_dir=Path("/tmp/none"),
                        authorized_allowlist=None)


def test_refresh_cleans_stale_phase_artifacts(tmp_path):
    """--refresh must wipe stale phase artifact dirs, not just bust the cache."""
    import boto3

    account_dir = tmp_path / "session" / "cloud" / "123456789012"
    # Seed stale artifacts
    (account_dir / "secrets").mkdir(parents=True)
    (account_dir / "secrets" / "stale_secret.json").write_text("{}")
    (account_dir / "prowler").mkdir()
    (account_dir / "prowler" / "old_output.json").write_text("[]")
    (account_dir / "phase_prowler_findings.json").write_text("[]")

    def fake_validate(profile):
        profile.account_id = "123456789012"
        profile.arn = "arn:aws:iam::123456789012:user/test"
        profile.regions = []
        profile._session = boto3.Session(region_name="us-east-1")
        profile.permission_probe = {"simulate_principal_policy": True}
        return profile

    with patch("whitebox.orchestrator.validate", side_effect=fake_validate), \
         patch("whitebox.orchestrator.collector.collect_all"), \
         patch("whitebox.orchestrator.prowler_runner.run", side_effect=Exception("skip")), \
         patch("whitebox.orchestrator.build_graph", side_effect=Exception("skip")), \
         patch("whitebox.orchestrator.run_secrets", return_value=[]), \
         patch("whitebox.orchestrator.route53.in_scope_domains", return_value=["test.local"]):
        run_for_profile(profile_name="test", session_dir=tmp_path / "session",
                        refresh=True, brain=None, authorized_allowlist=["*"])

    # Stale files must be gone
    assert not (account_dir / "secrets" / "stale_secret.json").exists()
    assert not (account_dir / "prowler" / "old_output.json").exists()
    assert not (account_dir / "phase_prowler_findings.json").exists()

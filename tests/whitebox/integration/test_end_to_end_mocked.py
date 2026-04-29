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
    """Seed a moto account with vulnerable config and assert the orchestrator produces
    expected findings (Lambda env secret + SSM SecureString secret + PMapper privesc).

    Prowler subprocess and PMapper subprocess are stubbed out (not invokable in test env);
    fixtures provide canned OCSF JSON and a pmapper graph directory for normalization.
    """
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
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/db", SecretString="aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    fixture_dir = Path(__file__).parent / "fixtures"

    # Stub Prowler + PMapper subprocess wrappers (not available in unit env)
    from unittest.mock import patch

    fake_session = boto3.Session(region_name="us-east-1")

    def fake_validate(profile):
        # Bypass real STS (moto handles this) but ensure the session attaches
        profile.account_id = "123456789012"
        profile.arn = "arn:aws:iam::123456789012:user/test"
        profile.regions = ["us-east-1"]
        profile._session = fake_session
        profile.permission_probe = {
            "simulate_principal_policy": True,
            "secretsmanager_list": True,
            "secretsmanager_get_value": False,  # lazy, will be flipped on first success
            "logs_describe": True,
            "kms_decrypt": False,
        }
        return profile

    with patch("whitebox.orchestrator.validate", side_effect=fake_validate), \
         patch("whitebox.orchestrator.prowler_runner.run") as mock_prowler, \
         patch("whitebox.orchestrator.build_graph") as mock_pmap, \
         patch("whitebox.orchestrator.route53.in_scope_domains", return_value=["test.local"]):

        mock_prowler.return_value = fixture_dir / "prowler_ocsf_sample.json"
        mock_pmap.return_value = fixture_dir / "pmapper_graph_sample.json"

        rc = run_for_profile(
            profile_name="test",
            session_dir=session_dir,
            refresh=True,
            brain=None,
            authorized_allowlist=["*"],
        )

    # rc may be nonzero if some phases (e.g. prowler subprocess) failed; we focus on
    # findings that should still emit.
    findings_files = list((session_dir / "cloud").glob("*/findings.json"))
    assert findings_files, "no findings.json produced"
    data = json.loads(findings_files[0].read_text())
    rule_ids = {f["rule_id"] for f in data}

    # Assertions: at least one finding from each major phase
    assert any(r.startswith("secrets.lambda_env.") for r in rule_ids), \
        f"expected lambda_env secret finding, got: {sorted(rule_ids)}"
    assert any(r.startswith("secrets.ssm.") for r in rule_ids), \
        f"expected ssm secret finding, got: {sorted(rule_ids)}"
    assert any(r.startswith("pmapper.") for r in rule_ids), \
        f"expected pmapper privesc finding, got: {sorted(rule_ids)}"
    # Prowler output is from a fixture; rule_ids include iam_root_mfa_enabled etc
    assert any(r in {"iam_root_mfa_enabled", "s3_bucket_public_read"} for r in rule_ids), \
        f"expected prowler finding, got: {sorted(rule_ids)}"


@mock_aws
def test_end_to_end_secretsmanager_value_scanned_when_get_works(session_dir, monkeypatch):
    """Verify the Secrets Manager scanner flips its lazy probe flag and scans values."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/api", SecretString="aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    fake_session = boto3.Session(region_name="us-east-1")

    from unittest.mock import patch

    def fake_validate(profile):
        profile.account_id = "123456789012"
        profile.arn = "arn:aws:iam::123456789012:user/test"
        profile.regions = ["us-east-1"]
        profile._session = fake_session
        # Default probe state — lazy False; scanner should flip on success
        profile.permission_probe = {
            "simulate_principal_policy": True, "secretsmanager_list": True,
            "secretsmanager_get_value": False, "logs_describe": True, "kms_decrypt": False,
        }
        return profile

    fixture_dir = Path(__file__).parent / "fixtures"

    with patch("whitebox.orchestrator.validate", side_effect=fake_validate), \
         patch("whitebox.orchestrator.prowler_runner.run", side_effect=Exception("skipped in test")), \
         patch("whitebox.orchestrator.build_graph", side_effect=Exception("skipped in test")), \
         patch("whitebox.orchestrator.route53.in_scope_domains", return_value=["test.local"]):

        run_for_profile(
            profile_name="test", session_dir=session_dir,
            refresh=True, brain=None, authorized_allowlist=["*"],
        )

    findings_files = list((session_dir / "cloud").glob("*/findings.json"))
    assert findings_files
    data = json.loads(findings_files[0].read_text())
    rule_ids = {f["rule_id"] for f in data}
    # Lazy probe must have flipped to True and scanner found the AWS key in the secret value
    assert any(r.startswith("secrets.secretsmanager.") and "permission_gap" not in r
               for r in rule_ids), \
        f"expected secretsmanager value scan finding, got: {sorted(rule_ids)}"

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
    with patch("whitebox.audit.prowler_runner._has_prowler", return_value=True), \
         patch("subprocess.run") as mock_run:
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


def test_to_findings_slugifies_check_id_in_evidence_path():
    raw = [{
        "status_code": "FAIL", "severity_id": 3,
        "finding_info": {"uid": "x", "title": "t", "desc": "d"},
        "cloud": {"account": {"uid": "111"}, "region": "us-east-1"},
        "resources": [{"uid": "arn:y", "type": "AWS::Y", "region": "us-east-1"}],
        "unmapped": {"check_id": "../../etc/passwd"},
    }]
    findings = to_findings(raw, account_id="111")
    assert ".." not in str(findings[0].evidence_path)
    assert "/" not in str(findings[0].evidence_path.name)
    # rule_id stays as the original (defensibility)
    assert findings[0].rule_id == "../../etc/passwd"


def test_run_raises_friendly_error_when_prowler_missing(tmp_path):
    profile = CloudProfile(name="t", account_id="111", arn="a", regions=[])
    with patch("shutil.which", return_value=None):
        with pytest.raises(FileNotFoundError, match="pip install prowler-cloud"):
            run(profile, tmp_path)

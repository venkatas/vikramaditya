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


def test_write_evidence_rejects_path_traversal(tmp_path):
    import pytest
    with pytest.raises(ValueError, match="path characters"):
        write_evidence(tmp_path, "../escape", [{"value": "x"}])
    with pytest.raises(ValueError, match="path characters"):
        write_evidence(tmp_path, "/abs/path", [{"value": "x"}])


def test_write_evidence_parent_dir_is_0700(tmp_path):
    write_evidence(tmp_path, "ok", [{"value": "x"}])
    parent_mode = stat.S_IMODE(os.stat(tmp_path).st_mode)
    assert parent_mode == 0o700

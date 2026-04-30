import sys
from unittest.mock import patch, MagicMock
from whitebox.cloud_hunt import main


def test_cli_requires_profile_arg(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["cloud_hunt"])
    rc = main()
    out = capsys.readouterr()
    assert rc != 0
    assert "--profile" in (out.out + out.err)


def test_cli_requires_scope_lock_decision(capsys, monkeypatch):
    """Without --allowlist or --no-scope-lock, must refuse."""
    monkeypatch.setattr(sys, "argv", ["cloud_hunt", "--profile", "p"])
    rc = main()
    out = capsys.readouterr()
    assert rc != 0
    assert "--allowlist" in out.err or "--no-scope-lock" in out.err


def test_cli_calls_orchestrator_with_profile_and_allowlist(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", [
        "cloud_hunt", "--profile", "client-erp",
        "--session-dir", str(tmp_path),
        "--allowlist", "example-prod.invalid",
    ])
    fake_run = MagicMock(return_value=0)
    with patch("whitebox.cloud_hunt.run_for_profile", fake_run):
        rc = main()
    assert rc == 0
    fake_run.assert_called_once()
    _, kwargs = fake_run.call_args
    assert kwargs.get("profile_name") == "client-erp"
    assert kwargs.get("authorized_allowlist") == ["example-prod.invalid"]


def test_cli_no_scope_lock_passes_wildcard(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", [
        "cloud_hunt", "--profile", "p",
        "--session-dir", str(tmp_path),
        "--no-scope-lock",
    ])
    fake_run = MagicMock(return_value=0)
    with patch("whitebox.cloud_hunt.run_for_profile", fake_run):
        rc = main()
    assert rc == 0
    _, kwargs = fake_run.call_args
    assert kwargs.get("authorized_allowlist") == ["*"]

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
        "cloud_hunt", "--profile", "adf-erp",
        "--session-dir", str(tmp_path),
    ])
    fake_run = MagicMock(return_value=0)
    with patch("whitebox.cloud_hunt.run_for_profile", fake_run):
        rc = main()
    assert rc == 0
    fake_run.assert_called_once()
    args, kwargs = fake_run.call_args
    assert kwargs.get("profile_name") == "adf-erp" or "adf-erp" in args

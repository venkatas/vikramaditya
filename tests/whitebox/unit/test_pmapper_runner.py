import os
import pytest
from pathlib import Path
from unittest.mock import patch
from whitebox.iam.pmapper_runner import build_graph, _resolve_pmapper_binary
from whitebox.profiles import CloudProfile


def test_resolve_pmapper_honours_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "pmapper"
    fake.write_text("#!/bin/sh\necho ok\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PMAPPER_BIN", str(fake))
    assert _resolve_pmapper_binary() == str(fake)


def test_resolve_pmapper_returns_none_when_nothing_found(monkeypatch):
    monkeypatch.delenv("PMAPPER_BIN", raising=False)
    with patch("whitebox.iam.pmapper_runner._PMAPPER_PATH_CANDIDATES", ()), \
         patch("shutil.which", return_value=None):
        assert _resolve_pmapper_binary() is None


def test_build_graph_raises_friendly_error_when_pmapper_missing(tmp_path, monkeypatch):
    profile = CloudProfile(name="t", account_id="111", arn="a", regions=[])
    monkeypatch.delenv("PMAPPER_BIN", raising=False)
    with patch("whitebox.iam.pmapper_runner._resolve_pmapper_binary", return_value=None):
        with pytest.raises(FileNotFoundError, match="principalmapper"):
            build_graph(profile, tmp_path)


def test_build_graph_skips_pythonnousersite_for_path_install(tmp_path, monkeypatch):
    """A PATH-discovered pip --user PMapper must NOT get PYTHONNOUSERSITE=1
    (which would break its own user-site import)."""
    profile = CloudProfile(name="t", account_id="111", arn="a", regions=[])
    monkeypatch.delenv("PMAPPER_BIN", raising=False)
    fake = "/usr/local/bin/pmapper"  # not in candidates, not env override
    captured = {}

    def fake_subprocess_run(cmd, **kw):
        captured["env"] = kw.get("env", {})
        from unittest.mock import MagicMock
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("whitebox.iam.pmapper_runner._resolve_pmapper_binary", return_value=fake), \
         patch("subprocess.run", side_effect=fake_subprocess_run):
        # Will fail when looking for graph storage but we only care that
        # subprocess was called with the right env
        try:
            build_graph(profile, tmp_path)
        except Exception:
            pass
    assert "PYTHONNOUSERSITE" not in captured["env"]
    assert captured["env"]["PYTHONWARNINGS"] == "ignore::DeprecationWarning"


def test_build_graph_sets_pythonnousersite_for_isolated_venv(tmp_path, monkeypatch):
    """An isolated-venv install MUST get PYTHONNOUSERSITE=1 to suppress
    distutils-hack startup noise."""
    profile = CloudProfile(name="t", account_id="111", arn="a", regions=[])
    monkeypatch.delenv("PMAPPER_BIN", raising=False)
    from whitebox.iam.pmapper_runner import _PMAPPER_PATH_CANDIDATES
    isolated = str(_PMAPPER_PATH_CANDIDATES[0])
    captured = {}

    def fake_subprocess_run(cmd, **kw):
        captured["env"] = kw.get("env", {})
        from unittest.mock import MagicMock
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("whitebox.iam.pmapper_runner._resolve_pmapper_binary", return_value=isolated), \
         patch("subprocess.run", side_effect=fake_subprocess_run):
        try:
            build_graph(profile, tmp_path)
        except Exception:
            pass
    assert captured["env"].get("PYTHONNOUSERSITE") == "1"


def test_build_graph_passes_PMAPPER_REGIONS(tmp_path, monkeypatch):
    """PMAPPER_REGIONS env → --include-regions r1 r2 ... AFTER graph create subcommand."""
    profile = CloudProfile(name="t", account_id="111", arn="a", regions=[])
    monkeypatch.setenv("PMAPPER_REGIONS", "us-east-1, ap-south-1 , eu-west-1")
    fake = "/fake/pmapper"
    captured = {}

    def fake_subprocess_run(cmd, **kw):
        captured["cmd"] = cmd
        from unittest.mock import MagicMock
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("whitebox.iam.pmapper_runner._resolve_pmapper_binary", return_value=fake), \
         patch("subprocess.run", side_effect=fake_subprocess_run):
        try:
            from whitebox.iam.pmapper_runner import build_graph
            build_graph(profile, tmp_path)
        except Exception:
            pass  # fails after subprocess looking for graph storage; we only assert cmd
    cmd = captured["cmd"]
    assert "--include-regions" in cmd
    assert "us-east-1" in cmd
    assert "ap-south-1" in cmd
    assert "eu-west-1" in cmd
    # --include-regions is a subcommand-level flag, must come AFTER 'graph create'
    create_idx = cmd.index("create")
    inc_idx = cmd.index("--include-regions")
    assert inc_idx > create_idx, "--include-regions must come after 'graph create' subcommand"
    # And the regions must appear consecutively after --include-regions (nargs='*')
    assert cmd[inc_idx + 1] == "us-east-1"
    assert cmd[inc_idx + 2] == "ap-south-1"
    assert cmd[inc_idx + 3] == "eu-west-1"


def test_build_graph_no_region_flags_when_env_unset(tmp_path, monkeypatch):
    """No PMAPPER_REGIONS → no --region flags (preserves current default behaviour)."""
    profile = CloudProfile(name="t", account_id="111", arn="a", regions=[])
    monkeypatch.delenv("PMAPPER_REGIONS", raising=False)
    fake = "/fake/pmapper"
    captured = {}

    def fake_subprocess_run(cmd, **kw):
        captured["cmd"] = cmd
        from unittest.mock import MagicMock
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("whitebox.iam.pmapper_runner._resolve_pmapper_binary", return_value=fake), \
         patch("subprocess.run", side_effect=fake_subprocess_run):
        try:
            from whitebox.iam.pmapper_runner import build_graph
            build_graph(profile, tmp_path)
        except Exception:
            pass
    assert "--include-regions" not in captured["cmd"]

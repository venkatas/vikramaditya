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

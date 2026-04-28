from unittest.mock import patch
import pytest
from pathlib import Path
from whitebox.orchestrator import run_for_profile


def test_run_for_profile_requires_allowlist():
    with pytest.raises(ValueError, match="authorized_allowlist"):
        run_for_profile(profile_name="x", session_dir=Path("/tmp/none"),
                        authorized_allowlist=None)

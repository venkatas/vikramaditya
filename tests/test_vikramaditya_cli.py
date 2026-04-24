import subprocess
import sys


def test_vikramaditya_help_exits_without_prompt():
    result = subprocess.run(
        [sys.executable, "vikramaditya.py", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert "--creds" in result.stdout
    assert "Enter target" not in result.stdout

from pathlib import Path
from types import SimpleNamespace

import environment_readiness as readiness


ROOT = Path(__file__).resolve().parents[1]


def _result(returncode=0, stdout="No broken requirements found.\n", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_clean_environment_is_ready():
    gaps = readiness.check_environment_readiness(
        which=lambda tool: f"/bin/{tool}",
        runner=lambda *args, **kwargs: _result(),
    )
    assert gaps == []


def test_pip_check_conflict_is_a_readiness_gap():
    conflict = (
        "joserfc 1.6.4 has requirement cryptography>=45.0.1, "
        "but you have cryptography 43.0.1.\n"
    )
    gaps = readiness.check_environment_readiness(
        which=lambda tool: f"/bin/{tool}",
        runner=lambda *args, **kwargs: _result(1, conflict),
    )
    assert gaps == [{"tool": "python-dependencies", "reason": conflict.strip()}]


def test_missing_required_runtime_command_is_not_ready():
    gaps = readiness.check_environment_readiness(
        required_tools=("uro",),
        which=lambda tool: None,
        runner=lambda *args, **kwargs: _result(),
    )
    assert gaps == [
        {
            "tool": "uro",
            "reason": "required runtime command not found on PATH: uro",
        }
    ]


def test_pip_check_timeout_fails_closed():
    import subprocess

    def timed_out(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 120)

    gaps = readiness.check_environment_readiness(
        required_tools=(),
        runner=timed_out,
    )
    assert gaps and gaps[0]["tool"] == "python-dependencies"
    assert "could not complete" in gaps[0]["reason"]


def test_requirements_pin_known_compatibility_floors():
    requirements = (ROOT / "requirements.txt").read_text()
    assert "cryptography>=45.0.1,<49" in requirements
    assert "jsonschema>=4.24.0,<5" in requirements
    assert "uro>=1.0.2" in requirements
    assert "prowler-cloud==" not in requirements
    assert "principalmapper>=" not in requirements
    assert "prowler-cloud==4.5.0" in (ROOT / "requirements-prowler.txt").read_text()
    assert "principalmapper>=1.1.5" in (ROOT / "requirements-pmapper.txt").read_text()


def test_setup_installs_uro_as_python_cli_and_fails_closed():
    setup = (ROOT / "setup.sh").read_text()
    assert "github.com/s0md3v/uro" not in setup
    assert '"$VENV_DIR/bin/python" -m pip check' in setup
    assert '"$VENV_DIR/bin/python" "$SCRIPT_DIR/environment_readiness.py"' in setup
    assert "install_isolated_python_tool" in setup
    assert '"$SCRIPT_DIR/requirements-prowler.txt"' in setup
    assert '"$SCRIPT_DIR/requirements-pmapper.txt"' in setup
    assert 'if [ "$MISSING" -gt 0 ] || [ "$READINESS_FAILED" -ne 0 ]; then' in setup
    assert 'log_ok "Installation complete and ready"' in setup
    assert "((INSTALLED++))" not in setup
    assert "((MISSING++))" not in setup

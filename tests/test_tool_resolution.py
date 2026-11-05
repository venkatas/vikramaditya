"""Local executable selection must agree at readiness, execution and shell boundaries."""
import os
from pathlib import Path
import subprocess

import pytest

import hunt
import tool_resolution as tr


def _binary(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o700)
    return str(path)


@pytest.fixture(autouse=True)
def _clean_cache():
    tr._cached_check.cache_clear()
    yield
    tr._cached_check.cache_clear()


def test_healthy_go_install_keeps_precedence(tmp_path, monkeypatch):
    go = tmp_path / "go"
    brew = tmp_path / "brew"
    good = _binary(go / "httpx", 'echo "projectdiscovery httpx"')
    _binary(brew / "opt/httpx/bin/httpx", 'echo "projectdiscovery httpx newer"')
    monkeypatch.setattr(tr, "BREW_PREFIXES", (str(brew),))
    assert tr.resolve("httpx", env={"PATH": ""}, gobin=str(go))[0] == good


def test_crashing_go_tool_falls_back_to_healthy_keg(tmp_path, monkeypatch):
    go = tmp_path / "go"
    brew = tmp_path / "brew"
    _binary(go / "dnsx", 'echo "segfault" >&2; exit 139')
    good = _binary(brew / "opt/dnsx/bin/dnsx", 'echo "projectdiscovery dnsx v1.3.1"')
    monkeypatch.setattr(tr, "BREW_PREFIXES", (str(brew),))
    assert tr.resolve("dnsx", env={"PATH": ""}, gobin=str(go)) == (good, None)


def test_wrong_python_httpx_does_not_shadow_later_path_candidate(tmp_path, monkeypatch):
    bad = tmp_path / "python-bin"
    good = tmp_path / "pd-bin"
    _binary(bad / "httpx", 'echo "python-httpx/0.27"')
    selected = _binary(good / "httpx", 'echo "projectdiscovery httpx v1"')
    monkeypatch.setattr(tr, "BREW_PREFIXES", ())
    assert tr.resolve("httpx", env={"PATH": os.pathsep.join((str(bad), str(good)))},
                      gobin=str(tmp_path / "absent"))[0] == selected


def test_explicit_pin_is_first_but_unhealthy_pin_can_fall_back(tmp_path, monkeypatch):
    pin = _binary(tmp_path / "pinned/httpx", 'echo "projectdiscovery httpx pinned"')
    good = _binary(tmp_path / "go/httpx", 'echo "projectdiscovery httpx"')
    env = {"PATH": "", "VIK_HTTPX_BIN": pin}
    monkeypatch.setattr(tr, "BREW_PREFIXES", ())
    assert tr.resolve("httpx", env=env, gobin=str(tmp_path / "go"))[0] == pin
    Path(pin).write_text("#!/bin/sh\nexit 139\n")
    assert tr.resolve("httpx", env=env, gobin=str(tmp_path / "go"))[0] == good


def test_repair_invalidates_cached_unhealthy_result(tmp_path, monkeypatch):
    binary = _binary(tmp_path / "dnsx", "exit 139")
    assert tr.resolve("dnsx", candidates=[binary])[0] is None
    Path(binary).write_text('#!/bin/sh\necho "projectdiscovery dnsx"\n')
    assert tr.resolve("dnsx", candidates=[binary]) == (binary, None)


def test_repeated_selection_does_not_reprobe_unchanged_executable(tmp_path, monkeypatch):
    binary = _binary(tmp_path / "katana", "exit 0")
    calls = []
    monkeypatch.setattr(tr, "_local_version", lambda path: (calls.append(path) or 0, "projectdiscovery"))
    assert tr.resolve("katana", candidates=[binary])[0] == binary
    assert tr.resolve("katana", candidates=[binary])[0] == binary
    assert calls == [binary]


def test_version_timeout_falls_back_without_hanging(tmp_path):
    bad = _binary(tmp_path / "bad", "exit 0")
    good = _binary(tmp_path / "good", "exit 0")

    def runner(argv, **kwargs):
        assert kwargs["timeout"] == tr.VERSION_TIMEOUT
        if argv[0] == bad:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0, "projectdiscovery", "")

    assert tr.resolve("dnsx", candidates=[bad, good], runner=runner) == (good, None)


def test_nuclei_version_banner_is_accepted_without_ascii_logo(tmp_path):
    binary = _binary(tmp_path / "nuclei", 'echo "[INF] Nuclei Engine Version: v3.8.0"')
    assert tr.resolve("nuclei", candidates=[binary]) == (binary, None)


def test_absent_and_unhealthy_are_distinguished(tmp_path):
    assert tr.resolve("httpx", candidates=[str(tmp_path / "missing")]) == (None, None)
    bad = _binary(tmp_path / "httpx", "exit 139")
    selected, reason = tr.resolve("httpx", candidates=[bad])
    assert selected is None and "139" in reason


def test_hunt_registry_execution_and_environment_agree(tmp_path, monkeypatch):
    go = tmp_path / "go"
    brew = tmp_path / "brew"
    path_dir = tmp_path / "path-bin"
    path_dir.mkdir()
    _binary(go / "dnsx", "exit 139")
    choices = {}
    for name in tr.PD_TOOLS:
        choices[name] = _binary(brew / f"opt/{name}/bin/{name}", f'echo "projectdiscovery {name}"')
        monkeypatch.delenv(tr.env_key(name), raising=False)
    monkeypatch.setattr(tr, "BREW_PREFIXES", (str(brew),))
    monkeypatch.setattr(hunt, "GOBIN", str(go))
    monkeypatch.setenv("PATH", str(path_dir))
    monkeypatch.setattr(hunt, "TOOL_REGISTRY", [(name, str(go / name), "install") for name in tr.PD_TOOLS])
    installed, missing = hunt.check_tools()
    assert set(installed) == set(tr.PD_TOOLS) and missing == []
    env = hunt._tool_env()
    for name, chosen in choices.items():
        assert hunt._tool_bin(name) == chosen
        assert env[tr.env_key(name)] == chosen
        assert Path(chosen).parent.as_posix() in env["PATH"].split(os.pathsep)
    assert hunt._httpx_readiness_reason() is None


def test_unrelated_script_and_missing_explicit_path_semantics_unchanged(tmp_path):
    script = tmp_path / "helper.py"
    script.write_text("print('ok')\n")
    assert hunt._which(str(script))
    assert not hunt._which(str(tmp_path / "not-installed/helper.py"))
    # An arbitrary absolute path is not silently redirected to an installed tool.
    assert not hunt._which(str(tmp_path / "not-installed/nuclei"))


def test_shell_env_is_quoted_and_missing_tools_export_empty_pin(monkeypatch, tmp_path, capsys):
    chosen = _binary(tmp_path / "tools with spaces/httpx", 'echo "projectdiscovery httpx"')
    monkeypatch.setattr(tr, "resolve", lambda name, **kwargs: (chosen, None) if name == "httpx" else (None, None))
    assert tr.main(["--shell-env"]) == 0
    emitted = capsys.readouterr().out
    completed = subprocess.run(["/bin/sh", "-c", emitted + '\nprintf "%s\\n" "$VIK_HTTPX_BIN" "$VIK_DNSX_BIN"'],
                               capture_output=True, text=True, timeout=5)
    assert completed.returncode == 0
    assert completed.stdout.splitlines() == [chosen, ""]

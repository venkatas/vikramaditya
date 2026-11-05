"""Arjun CLI/runtime failures must not masquerade as clean discovery coverage."""
import builtins
import json
import shlex

import pytest

import hunt


@pytest.fixture
def discovery(tmp_path, monkeypatch):
    recon = tmp_path / "recon"
    (recon / "live").mkdir(parents=True)
    (recon / "live/urls.txt").write_text("https://target.invalid/login.html\n")
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    monkeypatch.delenv("SCOPE_LOCK", raising=False)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_which", lambda name: name == "arjun")
    monkeypatch.setattr(hunt, "_lightpanda_bin", lambda: "/fixture/lightpanda")
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", lambda *a, **k: [])
    logs, gaps, phases = [], [], []
    monkeypatch.setattr(hunt, "log", lambda *a, **k: logs.append(a))
    monkeypatch.setattr(hunt, "_mark_degraded", lambda *a, **k: gaps.append(a))
    monkeypatch.setattr(hunt, "_brain_phase_complete", lambda *a, **k: phases.append((a, k)))
    return recon, logs, gaps, phases


def test_generic_explicit_small_wordlist_independent_of_project_imports(discovery, monkeypatch):
    _, _, gaps, phases = discovery
    importer = builtins.__import__

    def no_project_arjun(name, *args, **kwargs):
        if name == "arjun":
            raise ModuleNotFoundError("CLI is installed in isolated pipx environment")
        return importer(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_project_arjun)
    commands = []
    monkeypatch.setattr(hunt, "run_cmd", lambda cmd, **k: commands.append(shlex.split(cmd)) or (True, ""))
    assert hunt.run_param_discovery("target.invalid") is True
    argv = commands[0]
    assert argv[0] == "arjun" and argv[argv.index("-w") + 1] == "small"
    assert "--stable" not in argv
    assert not gaps and phases[-1][0][:2] == ("PARAM DISCOVERY", True)


@pytest.mark.parametrize("partial", [False, True])
def test_generic_failed_arjun_is_degraded_and_phase_unsuccessful(discovery, monkeypatch, partial):
    recon, logs, gaps, phases = discovery

    def run(cmd, **kwargs):
        if partial:
            (recon / "params/arjun.json").write_text(json.dumps({
                "https://target.invalid/login.html": {"params": ["name"]},
            }))
        return False, "TIMEOUT after 900s"

    monkeypatch.setattr(hunt, "run_cmd", run)
    assert hunt.run_param_discovery("target.invalid") is False
    assert any(tool == "arjun" and "command failed or timed out" in reason for tool, reason in gaps)
    assert phases[-1][0][:2] == ("PARAM DISCOVERY", False)
    assert "arjun_failed=1" in phases[-1][1]["detail"]
    assert not any(level == "ok" and "Arjun" in message for level, message in logs)
    if partial:
        assert json.loads((recon / "params/arjun.json").read_text())


def test_generic_successful_zero_matches_is_not_degraded(discovery, monkeypatch):
    recon, _, gaps, phases = discovery

    def run(cmd, **kwargs):
        (recon / "params/arjun.json").write_text("{}")
        return True, "No parameters found"

    monkeypatch.setattr(hunt, "run_cmd", run)
    assert hunt.run_param_discovery("target.invalid") is True
    assert not gaps and phases[-1][0][1] is True


def test_post_uses_supported_method_flag_and_preserves_cookie_quoting(discovery, monkeypatch):
    _, _, gaps, phases = discovery
    commands = []
    monkeypatch.setattr(hunt, "run_cmd", lambda cmd, **k: commands.append(shlex.split(cmd)) or (True, ""))
    assert hunt.run_post_param_discovery("target.invalid", cookies="sid=a b;test=1") is False
    argv = commands[0]
    assert argv[argv.index("-m") + 1] == "POST" and "--method" not in argv
    assert argv[argv.index("--headers") + 1] == "Cookie: sid=a b;test=1"
    assert not gaps and phases[-1][0][:2] == ("POST-PARAMS", True)


@pytest.mark.parametrize("existing_marker", [False, True])
def test_post_failed_arjun_does_not_claim_clean_zero_completion(discovery, monkeypatch, existing_marker):
    recon, logs, gaps, phases = discovery
    marker = recon / "params/post_params_done.marker"
    if existing_marker:
        marker.parent.mkdir()
        marker.write_text("0\n")
    monkeypatch.setattr(hunt, "run_cmd", lambda *a, **k: (False, "usage error or timeout"))

    assert hunt.run_post_param_discovery("target.invalid") is False
    assert not marker.exists()
    assert any(tool == "arjun" and "POST parameter discovery command failed" in reason for tool, reason in gaps)
    assert phases[-1][0][:2] == ("POST-PARAMS", False)
    assert "arjun_failed=1" in phases[-1][1]["detail"]
    assert not any(message == "No POST parameters discovered" for _, message in logs)


def test_post_successful_zero_matches_retains_completion_marker(discovery, monkeypatch):
    recon, _, gaps, phases = discovery
    monkeypatch.setattr(hunt, "run_cmd", lambda *a, **k: (True, "No parameters found"))
    assert hunt.run_post_param_discovery("target.invalid") is False  # Existing API: no endpoints.
    assert (recon / "params/post_params_done.marker").read_text() == "0\n"
    assert not gaps and phases[-1][0][1] is True


@pytest.mark.parametrize("partial_arjun", [False, True])
def test_post_failure_preserves_forms_and_valid_partial_arjun_data(discovery, monkeypatch, partial_arjun):
    recon, _, gaps, phases = discovery
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", lambda *a, **k: [
        {"action": "/submit", "method": "POST", "inputs": ["name"]},
    ])

    def run(cmd, **kwargs):
        if partial_arjun:
            (recon / "params/arjun_post.json").write_text(json.dumps({
                "https://target.invalid/partial": {"params": ["token"]},
                "https://external.invalid/not-allowed": {"params": ["secret"]},
            }))
        return False, "scanner crashed after partial output"

    monkeypatch.setattr(hunt, "run_cmd", run)
    assert hunt.run_post_param_discovery("target.invalid") is True  # Useful data is still available.
    params = json.loads((recon / "params/post_params.json").read_text())
    assert params["https://target.invalid/submit"]["params"] == ["name"]
    assert ("https://target.invalid/partial" in params) is partial_arjun
    assert "https://external.invalid/not-allowed" not in params
    assert not (recon / "params/post_params_done.marker").exists()
    assert gaps and phases[-1][0][:2] == ("POST-PARAMS", False)


def test_post_successful_partial_data_is_normal_completion(discovery, monkeypatch):
    recon, _, gaps, phases = discovery
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", lambda *a, **k: [
        {"action": "/submit", "method": "POST", "inputs": ["name"]},
    ])
    monkeypatch.setattr(hunt, "run_cmd", lambda *a, **k: (True, ""))
    assert hunt.run_post_param_discovery("target.invalid") is True
    assert (recon / "params/post_params.json").exists()
    assert not gaps and phases[-1][0][:2] == ("POST-PARAMS", True)

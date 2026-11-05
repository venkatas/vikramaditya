"""POST scheduling and late-discovery regressions, using local producers only."""
from __future__ import annotations

import json
import shlex
from types import SimpleNamespace

import pytest

import hunt


TARGET = "example.invalid"


@pytest.fixture
def local_session(tmp_path, monkeypatch):
    recon = tmp_path / "recon" / TARGET / "sessions" / "test"
    findings = tmp_path / "findings" / TARGET / "sessions" / "test"
    for path in (recon, findings):
        path.mkdir(parents=True)
    for name in ("scope", "live", "urls", "api", "params"):
        (recon / name).mkdir()
    (recon / "scope/allow.txt").write_text(TARGET + "\n")
    (recon / "live/urls.txt").write_text(f"https://{TARGET}\n")
    (recon / "live/httpx_full.txt").write_text(f"https://{TARGET} [200]\n")
    (recon / "urls/all.txt").write_text(f"https://{TARGET}\n")
    state = SimpleNamespace(
        recon=recon, findings=findings, fetched=[], commands=[],
        forms={}, installed={"arjun"}, command_ok=True,
    )
    for variable in ("SCOPE_ALLOW_FILE", "SCOPE_LOCK", "ARJUN_POST_MAX_URLS", "ARJUN_MAX_URLS"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_SEED_URLS", [])
    monkeypatch.setattr(hunt, "log", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_load_target_state", lambda *a, **k: {})
    monkeypatch.setattr(hunt, "_which", lambda name: name in state.installed)
    monkeypatch.setattr(hunt, "_collect_db_named_candidates", lambda *a, **k: [])
    monkeypatch.setattr(hunt, "_lightpanda_bin", lambda: pytest.fail("scoped form reads probed a renderer"))
    monkeypatch.setattr(hunt, "_install_lightpanda", lambda: pytest.fail("scoped form reads installed a renderer"))

    def forms(url, **kwargs):
        assert kwargs["exact_hosts"] == {TARGET}
        state.fetched.append(url)
        return list(state.forms.get(url, []))

    def command(cmd, **kwargs):
        argv = shlex.split(cmd)
        assert argv[0] in {"arjun", "sqlmap"}, "unexpected external command"
        state.commands.append((argv, kwargs))
        return state.command_ok, "fixture zero matches" if state.command_ok else "fixture timeout"

    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", forms)
    monkeypatch.setattr(hunt, "run_cmd", command)
    hunt._reset_degraded()
    try:
        yield state
    finally:
        hunt._reset_degraded()


def _step(state, step, completed, result):
    return hunt._run_autonomous_step(
        TARGET, step, quick=False, full=False, batch_size=10,
        skip_items=set(), result=result, completed=completed)


def _promote(state, url, mime="text/html"):
    artifact = state.recon / "api/feroxbuster.json"
    artifact.write_text(json.dumps({
        "type": "response", "url": url, "method": "GET", "status": 200,
        "headers": {"content-type": mime}, "wildcard": False,
    }) + "\n")
    return hunt._promote_api_discovery(TARGET, str(artifact), producer_ok=True)


def test_failed_post_not_repeated_by_same_invocation_but_later_preflight_can_retry(local_session):
    state = local_session
    state.installed.add("sqlmap")
    state.command_ok = False
    assert not hunt.run_post_param_discovery(TARGET, scope_lock=True)
    assert len(state.commands) == 1
    assert not (state.recon / "params/post_params_done.marker").exists()
    assert not hunt.run_sqlmap_targeted(TARGET, allow_post_preflight=False)
    assert len(state.commands) == 1 and len(state.fetched) == 1
    # No durable failed-attempt blacklist: an explicitly later invocation retries.
    assert not hunt.run_sqlmap_targeted(TARGET)
    assert len(state.commands) == 2 and len(state.fetched) == 2
    assert not (state.recon / "params/post_params_done.marker").exists()
    assert any("POST parameter discovery command failed" in row["reason"]
               for row in hunt._DEGRADED_CAPABILITIES)


def test_successful_zero_post_marker_still_avoids_unnecessary_preflight(local_session):
    state = local_session
    state.installed.add("sqlmap")
    assert not hunt.run_post_param_discovery(TARGET)
    assert (state.recon / "params/post_params_done.marker").read_text() == "0\n"
    assert not hunt.run_sqlmap_targeted(TARGET)
    assert len(state.commands) == 1


def test_later_explicit_retry_consumes_changed_html_inputs(local_session):
    state = local_session
    state.installed.add("sqlmap")
    state.command_ok = False
    hunt.run_post_param_discovery(TARGET)
    page = f"https://{TARGET}/contact"
    (state.recon / "urls/discovered_html.txt").write_text(page + "\n")
    hunt.run_sqlmap_targeted(TARGET)
    assert page in state.fetched
    assert len(state.commands) == 2


def test_post_small_wordlist_keeps_serial_pacing_and_exact_redirect_guard(local_session):
    state = local_session
    hunt.run_post_param_discovery(TARGET, cookies="sid=a b; x=1")
    argv, options = state.commands[0]
    assert argv[argv.index("-m") + 1] == "POST"
    assert argv[argv.index("-w") + 1] == "small"
    assert "--stable" not in argv
    assert argv[argv.index("-t") + 1] == "1"
    assert argv[argv.index("--rate-limit") + 1] == "1"
    assert argv[argv.index("-d") + 1] == "6"
    assert "--disable-redirects" in argv
    assert argv[argv.index("--headers") + 1] == "Cookie: sid=a b; x=1"
    assert options["timeout"] == 600


@pytest.mark.parametrize("limit, expected_count", [(None, 5), ("2", 2), ("0", 9)])
def test_post_surface_cap_is_explicit_and_prefers_authorized_post_actions(
        local_session, monkeypatch, limit, expected_count):
    state = local_session
    pages = [f"https://{TARGET}/page{i}" for i in range(7)]
    (state.recon / "urls/discovered_html.txt").write_text(
        "\n".join(pages + [f"https://{TARGET}/", "https://outside.invalid/contact"]) + "\n")
    state.forms[f"https://{TARGET}"] = [
        {"action": "/submit", "method": "POST", "inputs": ["name"]},
        {"action": "https://outside.invalid/submit", "method": "POST", "inputs": ["secret"]},
    ]
    if limit is not None:
        monkeypatch.setenv("ARJUN_POST_MAX_URLS", limit)
    assert hunt.run_post_param_discovery(TARGET)
    values = (state.recon / "params/arjun_post_targets.txt").read_text().splitlines()
    assert len(values) == expected_count
    assert values[0] == f"https://{TARGET}/submit"
    assert len(values) == len(set(values)) and all(TARGET in url for url in values)
    assert len(state.fetched) == 8, "passive HTML extraction was incorrectly capped with hidden-param probing"
    capped = [row for row in hunt._DEGRADED_CAPABILITIES if "POST URL surface capped" in row["reason"]]
    assert bool(capped) is (limit != "0")
    if capped:
        assert f"probed {expected_count} of 9 candidate URLs" in capped[0]["reason"]


@pytest.mark.parametrize("value", ["-1", "invalid"])
def test_invalid_post_cap_falls_back_safely_and_records_gap(local_session, monkeypatch, value):
    monkeypatch.setenv("ARJUN_POST_MAX_URLS", value)
    hunt.run_post_param_discovery(TARGET)
    assert any("POST URL limit invalid" in row["reason"] for row in hunt._DEGRADED_CAPABILITIES)


def test_mime_qualified_extensionless_html_is_fetched_but_static_and_offscope_are_not(local_session):
    state = local_session
    state.installed.clear()
    (state.recon / "urls/discovered_html.txt").write_text(
        f"https://{TARGET}/contact\nhttps://{TARGET}/settings?tab=account\n"
        f"https://{TARGET}/app.js\nhttps://{TARGET}/photo.jpg\n"
        "https://outside.invalid/contact\n")
    hunt.run_post_param_discovery(TARGET)
    assert set(state.fetched) == {
        f"https://{TARGET}", f"https://{TARGET}/contact", f"https://{TARGET}/settings?tab=account"}


@pytest.mark.parametrize("url, mime", [
    (f"https://{TARGET}/search?id=1", "text/html"),
    (f"https://{TARGET}/api/users", "application/json"),
])
def test_fresh_query_or_api_input_invalidates_core_scan_and_must_be_consumed(
        local_session, monkeypatch, url, mime):
    state = local_session
    monkeypatch.setattr(hunt, "run_api_fuzz", lambda domain: bool(_promote(state, url, mime)))
    monkeypatch.setattr(hunt, "run_param_discovery", lambda *a, **k: True)
    completed = {"recon", "scan", "param_discovery"}
    result = {"success": True, "scan": True, "param_discovery": True}
    assert _step(state, "api_fuzz", completed, result)
    assert url in (state.recon / "urls/all.txt").read_text().splitlines()
    assert hunt._api_pending_consumers(TARGET) == {"scan", "param_discovery"}
    assert completed == {"recon", "api_fuzz"}
    assert result["scan"] is False
    _, plan = hunt._build_autonomous_plan(TARGET, completed_steps=completed)
    assert {row["step"] for row in plan} == {"scan", "param_discovery"}
    assert plan[0]["step"] == "scan"
    assert _step(state, "param_discovery", completed, result)
    assert hunt._api_pending_consumers(TARGET) == {"scan"}

    def core(domain, **kwargs):
        assert url in (state.recon / "urls/all.txt").read_text().splitlines()
        return True

    monkeypatch.setattr(hunt, "run_vuln_scan", core)
    assert _step(state, "scan", completed, result)
    assert not hunt._api_pending_consumers(TARGET)
    assert hunt._build_autonomous_plan(TARGET, completed_steps=completed)[1] == []


def test_partial_api_phase_still_invalidates_scan_for_fresh_valid_promoted_inputs(local_session, monkeypatch):
    state = local_session

    def api(domain):
        _promote(state, f"https://{TARGET}/search?id=1")
        return False  # Another API subtool failed after the valid producer.

    monkeypatch.setattr(hunt, "run_api_fuzz", api)
    completed = {"recon", "scan", "param_discovery"}
    result = {"success": True, "scan": True, "param_discovery": True}
    assert not _step(state, "api_fuzz", completed, result)
    assert completed == {"recon"} and result["scan"] is False
    assert hunt._api_pending_consumers(TARGET) == {"scan", "param_discovery"}


def test_irrelevant_html_or_js_does_not_invalidate_an_already_completed_core_scan(local_session):
    state = local_session
    _promote(state, f"https://{TARGET}/contact")
    assert hunt._api_pending_consumers(TARGET) == {"param_discovery"}
    hunt._consume_api_discovery(TARGET, "param_discovery")
    _promote(state, f"https://{TARGET}/custom.js", "application/javascript")
    assert hunt._api_pending_consumers(TARGET) == {"js_analysis"}


def test_pending_scan_overrides_old_resume_completion_but_not_exhausted_retry_gate(local_session):
    state = local_session
    _promote(state, f"https://{TARGET}/search?id=1")
    (state.findings / "summary.txt").write_text("prior completed core scan\n")
    session_file = state.recon / "autonomous_session.json"
    session_file.write_text(json.dumps({"completed_steps": ["recon", "scan", "param_discovery"]}))
    from unittest.mock import patch
    with patch.object(hunt, "_autonomous_session_path", return_value=str(session_file)):
        resumed = hunt._load_autonomous_session(TARGET, resume=True, session_id="test")
    assert not {"scan", "param_discovery"}.intersection(resumed["completed_steps"])
    assert "scan" not in hunt._collect_completed_steps(TARGET)
    # The planner is also passed retry-exhausted steps in this set. Pending
    # state must not bypass that explicit bounded-run exclusion.
    _, plan = hunt._build_autonomous_plan(TARGET, completed_steps={"scan", "param_discovery", "api_fuzz"})
    assert not plan

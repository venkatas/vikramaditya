"""Exercise discovery handoff through real orchestration with local producers."""
from __future__ import annotations

import json
import shlex
from types import SimpleNamespace

import pytest

import hunt
from discovery_feedback import normalize_url


def _response(url, *, status=200, mime="text/html"):
    return {"type": "response", "url": url, "status": status, "method": "GET",
            "headers": {"content-type": mime}, "wildcard": False}


@pytest.fixture
def session(tmp_path, monkeypatch):
    recon, findings, reports = [
        tmp_path / tree / "example.invalid" / "sessions" / "test"
        for tree in ("recon", "findings", "reports")]
    for path in (recon, findings, reports):
        path.mkdir(parents=True)
    for directory in ("scope", "live", "urls", "api"):
        (recon / directory).mkdir()
    (recon / "scope/allow.txt").write_text("example.invalid\n")
    (recon / "live/urls.txt").write_text("https://example.invalid\n")
    (recon / "live/httpx_full.txt").write_text("https://example.invalid [200] [Fixture]\n")
    (recon / "urls/all.txt").write_text("https://example.invalid\n")
    state = SimpleNamespace(
        recon=recon, findings=findings, reports=reports,
        installed={"feroxbuster", "arjun"}, producer_ok=True, write_fresh=True,
        rows=[
            {"type": "configuration", "url": "https://outside.invalid/"},
            _response("https://example.invalid/"),
            _response("https://example.invalid/app/contact.html"),
            _response("https://example.invalid/app/custom.js", mime="application/javascript"),
            _response("https://example.invalid/search.html?q=one"),
            _response("https://example.invalid/api/v1/users", mime="application/json"),
            _response("https://example.invalid/api/nonexistent", status=401),
            _response("https://www.example.invalid/external.html"),
            {"type": "statistics", "responses": 7},
        ], events=[], arjun_inputs=[], fetched=[])
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    monkeypatch.delenv("SCOPE_LOCK", raising=False)
    monkeypatch.delenv("ARJUN_MAX_URLS", raising=False)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_SEED_URLS", [])
    monkeypatch.setattr(hunt, "check_tool_readiness", lambda: [])
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(findings))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda *a, **k: str(reports))
    monkeypatch.setattr(hunt, "_activate_recon_session", lambda *a, **k: ("test", str(recon)))
    monkeypatch.setattr(hunt, "_active_recon_session_id", lambda *a: "test")
    monkeypatch.setattr(hunt, "_tool_bin", lambda name: name)
    monkeypatch.setattr(hunt, "_which", lambda name: name.rsplit("/", 1)[-1] in state.installed)
    monkeypatch.setattr(hunt, "_enrich_targets_with_whitebox_asset_feed", lambda *a, **k: [])

    def command(cmd, **kwargs):
        argv = shlex.split(cmd)
        if "feroxbuster" in argv[0]:
            state.events.append("api")
            output = recon / "api/feroxbuster.json"
            assert not output.exists(), "old producer output must be quarantined before rerun"
            if state.write_fresh:
                output.write_text("\n".join(json.dumps(row) for row in state.rows) + "\n")
            return state.producer_ok, "fixture discovery"
        if argv[0] == "arjun":
            mode = "POST" if "POST" in argv else "GET"
            state.events.append(mode)
            seeds = (recon / "params" / ("arjun_post_targets.txt" if mode == "POST" else "top_urls.txt"))
            state.arjun_inputs.append((mode, seeds.read_text().splitlines()))
            return True, "fixture zero hidden parameters"
        if any(part.endswith("api_audit.py") for part in argv):
            return True, "fixture schema audit"
        pytest.fail(f"discovery integration invoked an unexpected command: {argv[0]}")

    monkeypatch.setattr(hunt, "run_cmd", command)

    def forbidden(*args, **kwargs):
        pytest.fail("discovery integration attempted an unrequested phase or renderer")

    for name in ("run_recon", "run_vuln_scan", "generate_reports", "_lightpanda_bin", "_install_lightpanda"):
        monkeypatch.setattr(hunt, name, forbidden)
    hunt._reset_degraded()
    try:
        yield state
    finally:
        hunt._reset_degraded()


def _lines(state, relative):
    path = state.recon / relative
    return path.read_text().splitlines() if path.exists() else []


def test_real_api_fuzz_promotes_fresh_successful_responses_and_tracks_consumers(session):
    state = session
    assert hunt.run_api_fuzz("example.invalid")
    assert _lines(state, "urls/all.txt") == [
        "https://example.invalid", "https://example.invalid/app/contact.html",
        "https://example.invalid/app/custom.js", "https://example.invalid/search.html?q=one",
        "https://example.invalid/api/v1/users"]
    assert _lines(state, "urls/js_files.txt") == ["https://example.invalid/app/custom.js"]
    assert _lines(state, "urls/discovered_html.txt") == [
        "https://example.invalid/", "https://example.invalid/app/contact.html",
        "https://example.invalid/search.html?q=one"]
    assert _lines(state, "urls/with_params.txt") == ["https://example.invalid/search.html?q=one"]
    assert hunt._api_pending_consumers("example.invalid") == {"scan", "js_analysis", "param_discovery"}
    feedback = json.loads((state.recon / "api/discovery_feedback.json").read_text())
    assert feedback["producer_ok"] is True and feedback["changed"] is True
    assert feedback["rejected_count"] == 2
    hunt._consume_api_discovery("example.invalid", "js_analysis")
    assert hunt._api_pending_consumers("example.invalid") == {"scan", "param_discovery"}


@pytest.mark.parametrize("fresh_partial_output", [False, True])
def test_failed_producer_does_not_promote_stale_or_partial_results(session, fresh_partial_output):
    state = session
    stale_url = "https://example.invalid/stale.js"
    (state.recon / "api/feroxbuster.json").write_text(json.dumps(_response(stale_url)) + "\n")
    state.producer_ok = False
    state.write_fresh = fresh_partial_output
    hunt.run_api_fuzz("example.invalid")
    assert _lines(state, "urls/all.txt") == ["https://example.invalid"]
    assert _lines(state, "urls/js_files.txt") == []
    feedback = json.loads((state.recon / "api/discovery_feedback.json").read_text())
    assert feedback["producer_ok"] is False and feedback["changed"] is False
    retained = list((state.recon / "api/stale-evidence").rglob("feroxbuster.json"))
    assert len(retained) == 1 and stale_url in retained[0].read_text()


def test_absent_producer_does_not_promote_an_existing_artifact(session):
    state = session
    state.installed.remove("feroxbuster")
    (state.recon / "api/feroxbuster.json").write_text(json.dumps(_response("https://example.invalid/stale.html")))
    hunt.run_api_fuzz("example.invalid")
    assert _lines(state, "urls/all.txt") == ["https://example.invalid"]
    assert not hunt._api_pending_consumers("example.invalid")


def test_successful_producer_without_fresh_artifact_is_a_coverage_gap(session):
    state = session
    state.write_fresh = False
    hunt.run_api_fuzz("example.invalid")
    feedback = json.loads((state.recon / "api/discovery_feedback.json").read_text())
    assert feedback["errors"] and not feedback["changed"]
    assert any(row["tool"] == "api_discovery" for row in hunt._DEGRADED_CAPABILITIES)
    assert _lines(state, "urls/all.txt") == ["https://example.invalid"]


def test_real_targeted_sync_discovers_before_js_get_and_post_consumers(session, monkeypatch):
    state = session

    def javascript(domain):
        state.events.append("js")
        assert _lines(state, "urls/js_files.txt") == ["https://example.invalid/app/custom.js"]
        return True

    def forms(url, **kwargs):
        state.events.append("form")
        state.fetched.append(url)
        assert kwargs["exact_hosts"] == {"example.invalid"}
        if url.endswith("contact.html"):
            return [{"action": "/app/submit", "method": "POST", "inputs": ["name"]}]
        return []

    monkeypatch.setattr(hunt, "run_js_analysis", javascript)
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", forms)
    monkeypatch.setenv("ARJUN_MAX_URLS", "0")
    result = hunt.hunt_target(
        "example.invalid", api_fuzz=True, js_scan=True, param_discover=True,
        post_param_discover=True, scope_lock=True, resume_session_id="test",
        skip_items={"nextjs_bypass", "email_audit"})
    assert state.events.index("api") < state.events.index("js") < state.events.index("GET")
    assert state.events.index("GET") < state.events.index("form") < state.events.index("POST")
    get_seeds = next(values for mode, values in state.arjun_inputs if mode == "GET")
    assert "https://example.invalid/app/contact.html" in get_seeds
    assert "https://example.invalid/api/v1/users" in get_seeds
    assert "https://example.invalid/search.html" in get_seeds
    assert "https://example.invalid/app/custom.js" not in get_seeds
    assert {normalize_url(url) for url in state.fetched} == {
        "https://example.invalid/", "https://example.invalid/app/contact.html",
        "https://example.invalid/search.html",
        "https://example.invalid/search.html?q=one"}
    assert len(state.fetched) == len({normalize_url(url) for url in state.fetched})
    params = json.loads((state.recon / "params/post_params.json").read_text())
    assert params["https://example.invalid/app/submit"]["params"] == ["name"]
    assert hunt._api_pending_consumers("example.invalid") == {"scan"}
    assert result["api_fuzz"] and result["js_analysis"] and result["param_discovery"] and result["post_params"]


def test_get_surface_cap_counts_normalized_authorized_urls_only(session, monkeypatch):
    state = session
    state.installed = {"arjun"}
    (state.recon / "live/urls.txt").write_text("https://example.invalid\nhttps://example.invalid/\n")
    (state.recon / "urls/discovered_html.txt").write_text(
        "https://example.invalid/\nhttps://example.invalid/a.html\nhttps://example.invalid/b.html\n"
        "https://www.example.invalid/outside.html\n")
    (state.recon / "urls/api_endpoints.txt").write_text("https://example.invalid/api/data\n")
    (state.recon / "urls/with_params.txt").write_text("https://example.invalid/a.html?q=one\n")
    monkeypatch.setenv("ARJUN_MAX_URLS", "2")
    assert hunt.run_param_discovery("example.invalid")
    assert len(state.arjun_inputs) == 1
    values = state.arjun_inputs[0][1]
    assert len(values) == 2 and len({normalize_url(url) for url in values}) == 2
    gaps = [row for row in hunt._DEGRADED_CAPABILITIES if row["tool"] == "arjun"]
    assert len(gaps) == 1 and "probed 2 of 4 " in gaps[0]["reason"]


def test_post_page_cap_counts_deduplicated_in_scope_html_candidates(session, monkeypatch):
    state = session
    state.installed = set()
    pages = [f"https://example.invalid/app/page{index}.html" for index in range(30)]
    (state.recon / "urls/discovered_html.txt").write_text(
        "https://example.invalid/\n" + "\n".join(pages)
        + "\nhttps://www.example.invalid/outside.html\n")
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", lambda url, **k: state.fetched.append(url) or [])
    assert hunt.run_post_param_discovery("example.invalid", scope_lock=True) is False
    assert len(state.fetched) == 30
    assert len({normalize_url(url) for url in state.fetched}) == 30
    assert "https://www.example.invalid/outside.html" not in state.fetched
    assert any("reading 30 of 31 pages" in row["reason"] for row in hunt._DEGRADED_CAPABILITIES)


def test_session_scope_restriction_also_filters_discovered_html(session):
    state = session
    path = state.recon / "urls/discovered_html.txt"
    path.write_text("https://example.invalid/a.html\nhttps://www.example.invalid/outside.html\n")
    allowed = hunt._restrict_session_scope("example.invalid", str(state.recon))
    assert allowed == {"example.invalid"}
    assert path.read_text().splitlines() == ["https://example.invalid/a.html"]


def test_autonomous_legacy_resume_rebinds_exact_scope_before_planning(session, monkeypatch):
    state = session
    (state.recon / "scope/allow.txt").unlink()
    (state.recon / "urls/all.txt").write_text(
        "https://example.invalid/\nhttps://www.example.invalid/outside.html\n")
    (state.recon / "urls/discovered_html.txt").write_text(
        "https://example.invalid/form.html\nhttps://www.example.invalid/outside.html\n")
    session_file = state.recon / "autonomous_session.json"
    monkeypatch.setattr(hunt, "_load_autonomous_session", lambda *a, **k: {
        "target": "example.invalid", "session_id": "test",
        "session_file": str(session_file), "completed_steps": ["recon"],
    })
    monkeypatch.setattr(hunt, "run_prioritize", lambda *a, **k: True)

    def plan(*args, **kwargs):
        assert (state.recon / "scope/allow.txt").read_text() == "example.invalid\n"
        for relative in ("urls/all.txt", "urls/discovered_html.txt"):
            assert "www.example.invalid" not in (state.recon / relative).read_text()
        return {}, []

    monkeypatch.setattr(hunt, "_build_autonomous_plan", plan)
    result = hunt.run_autonomous_hunt("example.invalid", resume=True, scope_lock=True)
    assert result["assessment_status"] == "complete"
    assert json.loads(session_file.read_text())["last_result"]["success"] is True


def test_feedback_scope_error_is_persisted_and_marks_incomplete_coverage(session):
    state = session
    (state.recon / "scope/allow.txt").write_text("")
    hunt.run_api_fuzz("example.invalid")
    assert _lines(state, "urls/all.txt") == ["https://example.invalid"]
    feedback = json.loads((state.recon / "api/discovery_feedback.json").read_text())
    assert feedback["errors"] and not feedback["changed"]
    assert any(row["tool"] == "api_discovery" for row in hunt._DEGRADED_CAPABILITIES)


def test_failed_new_producer_preserves_unconsumed_prior_discovery_inputs(session):
    state = session
    hunt.run_api_fuzz("example.invalid")
    before = (state.recon / "urls/all.txt").read_bytes()
    state.producer_ok = False
    state.write_fresh = False
    hunt.run_api_fuzz("example.invalid")
    assert (state.recon / "urls/all.txt").read_bytes() == before
    assert hunt._api_pending_consumers("example.invalid") == {"scan", "js_analysis", "param_discovery"}


def test_autonomous_discovery_invalidates_only_dependent_completion_bits(session, monkeypatch):
    state = session
    completed = {"recon", "scan", "js_analysis", "param_discovery"}
    result = {"success": True, "scan": True, "js_analysis": True, "param_discovery": True}
    assert hunt._run_autonomous_step(
        "example.invalid", "api_fuzz", quick=False, full=False, batch_size=10,
        skip_items=set(), result=result, completed=completed)
    assert completed == {"recon", "api_fuzz"}
    assert result["scan"] is False
    assert result["js_analysis"] is False and result["param_discovery"] is False
    monkeypatch.setattr(hunt, "run_js_analysis", lambda *a, **k: True)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *a, **k: True)
    for step in ("js_analysis", "param_discovery", "scan"):
        assert hunt._run_autonomous_step(
            "example.invalid", step, quick=False, full=False, batch_size=10,
            skip_items=set(), result=result, completed=completed)
    assert completed == {"recon", "scan", "api_fuzz", "js_analysis", "param_discovery"}
    assert not hunt._api_pending_consumers("example.invalid")
    assert "https://example.invalid/app/contact.html" in state.arjun_inputs[0][1]


@pytest.mark.parametrize("budget", [1, 4])
def test_real_autonomous_replans_late_inputs_and_records_unfinished_budget(session, monkeypatch, budget):
    state = session
    session_file = state.recon / "autonomous_session.json"
    session_file.write_text(json.dumps({
        "completed_steps": ["recon", "js_analysis", "param_discovery"],
        "attempted_steps": [], "last_result": {},
    }))
    monkeypatch.setattr(hunt, "_autonomous_session_path", lambda *a, **k: str(session_file))
    monkeypatch.setattr(hunt, "run_prioritize", lambda *a, **k: True)
    monkeypatch.setattr(hunt, "_update_target_state_from_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_log_best_validation_targets", lambda *a, **k: None)

    def javascript(domain):
        state.events.append("js")
        assert _lines(state, "urls/js_files.txt") == ["https://example.invalid/app/custom.js"]
        return True

    def plan(*args, completed_steps, **kwargs):
        return {}, [{"step": step, "reason": "fixture late discovery"}
                    for step in ("api_fuzz", "js_analysis", "param_discovery", "scan")
                    if step not in completed_steps]

    monkeypatch.setattr(hunt, "run_js_analysis", javascript)
    monkeypatch.setattr(hunt, "run_vuln_scan", lambda *a, **k: state.events.append("scan") or True)
    monkeypatch.setattr(hunt, "_build_autonomous_plan", plan)
    result = hunt.run_autonomous_hunt(
        "example.invalid", resume=True, max_steps=budget, skip_items={"reports"})
    saved = json.loads(session_file.read_text())
    if budget == 1:
        assert state.events == ["api"]
        assert result["assessment_status"] == "inconclusive"
        assert result["success"] is False
        assert not {"js_analysis", "param_discovery"}.intersection(saved["completed_steps"])
        assert hunt._api_pending_consumers("example.invalid") == {"scan", "js_analysis", "param_discovery"}
        assert any(row["tool"] == "api_discovery" for row in hunt._DEGRADED_CAPABILITIES)
    else:
        assert state.events == ["api", "js", "GET", "scan"]
        assert result["assessment_status"] == "complete" and result["success"] is True
        assert {"api_fuzz", "scan", "js_analysis", "param_discovery"}.issubset(saved["completed_steps"])
        assert not hunt._api_pending_consumers("example.invalid")
    assert saved["last_result"]["assessment_status"] == result["assessment_status"]


@pytest.mark.parametrize("already_complete", [False, True])
def test_actual_planner_consumes_html_only_feedback_without_overriding_retry_completion(
        session, monkeypatch, already_complete):
    state = session
    state.rows = [_response("https://example.invalid/contact.html")]
    hunt.run_api_fuzz("example.invalid")
    monkeypatch.setattr(hunt, "_load_target_state", lambda *a, **k: {})
    signals = hunt._collect_autonomous_signals("example.invalid")
    assert signals["parameterized_urls"] == 0 and signals["js_files"] == 0
    assert signals["api_endpoints"] == 0
    monkeypatch.setattr(hunt, "_collect_autonomous_signals", lambda *a, **k: dict(signals))
    completed = {"scan"}
    if already_complete:
        completed.add("param_discovery")
    _, plan = hunt._build_autonomous_plan(
        "example.invalid", completed_steps=completed, max_steps=4)
    params = [row for row in plan if row["step"] == "param_discovery"]
    if already_complete:
        assert params == [], "pending discovery bypassed the planner's exhausted/completed step gate"
    else:
        assert len(params) == 1
        assert params[0]["priority"] == hunt.AUTONOMOUS_STEP_BASE_PRIORITY["param_discovery"] + 30
        assert "new scoped discovery inputs" in params[0]["reason"]

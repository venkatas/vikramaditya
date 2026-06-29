"""Deterministic, LLM-free tool router + graceful degradation (tool_router.py).

Centralizes capability -> installed-tool resolution with three relationship MODES
(substitute / accumulate / pipeline), tiered fallback, a failure classifier, and a deterministic
scan plan that visibly SKIPS capabilities whose tools are all absent (the recurring 'binary
missing on the operator box' pain). The substitute/accumulate/pipeline split and the
failure->action mapping were refined via adversarial review (codex/grok/agy).

Tool presence is injected via the _which indirection so these tests never depend on what is
actually installed on the box.
"""
import pytest

import tool_router as tr


@pytest.fixture
def fake_tools(monkeypatch):
    """Install a fake `_which` so only the named tools 'exist'; reset the availability cache."""
    def _make(present):
        present = set(present)
        monkeypatch.setattr(tr, "_which", lambda name: ("/usr/bin/" + name) if name in present else None)
        tr.reset_cache()
        return present
    return _make


# ── resolve / chains (substitute) ─────────────────────────────────────────────
def test_resolve_returns_most_preferred_installed(fake_tools):
    fake_tools({"feroxbuster", "ffuf", "gobuster"})
    assert tr.resolve("web_content_discovery") == "feroxbuster"


def test_resolve_skips_to_next_when_top_absent(fake_tools):
    fake_tools({"ffuf", "gobuster"})  # feroxbuster missing
    assert tr.resolve("web_content_discovery") == "ffuf"


def test_resolve_none_when_none_installed(fake_tools):
    fake_tools(set())
    assert tr.resolve("web_content_discovery") is None


def test_resolve_unknown_capability_is_none(fake_tools):
    fake_tools({"nmap"})
    assert tr.resolve("does_not_exist") is None


def test_available_chain_is_installed_subset_in_order(fake_tools):
    fake_tools({"gobuster", "feroxbuster"})  # ffuf absent, dirb absent
    assert tr.available_chain("web_content_discovery") == ["feroxbuster", "gobuster"]


# ── modes: substitute / accumulate / pipeline ─────────────────────────────────
def test_mode_classification():
    assert tr.mode("http_probe") == "substitute"
    assert tr.mode("vuln_templates") == "substitute"
    assert tr.mode("subdomain_enum") == "accumulate"
    assert tr.mode("url_crawl_passive") == "accumulate"
    assert tr.mode("port_scan") == "pipeline"


def test_accumulate_tools_returns_all_installed_in_order(fake_tools):
    fake_tools({"subfinder", "amass"})  # assetfinder absent
    assert tr.accumulate_tools("subdomain_enum") == ["subfinder", "amass"]


def test_pipeline_plan_discover_then_enrich(fake_tools):
    fake_tools({"naabu", "nmap"})
    pp = tr.pipeline_plan("port_scan")
    assert pp == {"discover": "naabu", "enrich": "nmap"}


def test_pipeline_plan_discover_only_when_no_enricher(fake_tools):
    fake_tools({"rustscan"})  # no nmap
    pp = tr.pipeline_plan("port_scan")
    assert pp["discover"] == "rustscan" and pp["enrich"] is None


def test_pipeline_plan_nmap_serves_both_roles(fake_tools):
    fake_tools({"nmap"})
    pp = tr.pipeline_plan("port_scan")
    assert pp == {"discover": "nmap", "enrich": "nmap"}


# ── tools_for: concrete run set per mode ──────────────────────────────────────
def test_tools_for_substitute_single_winner(fake_tools):
    fake_tools({"httpx", "curl"})
    assert tr.tools_for("http_probe") == ["httpx"]


def test_tools_for_accumulate_all_installed(fake_tools):
    fake_tools({"subfinder", "assetfinder", "amass"})
    assert tr.tools_for("subdomain_enum") == ["subfinder", "assetfinder", "amass"]


def test_tools_for_pipeline_two_stages(fake_tools):
    fake_tools({"naabu", "nmap"})
    assert tr.tools_for("port_scan") == ["naabu", "nmap"]


def test_tools_for_pipeline_dedupes_when_one_tool_does_both(fake_tools):
    fake_tools({"nmap"})
    assert tr.tools_for("port_scan") == ["nmap"]


def test_tools_for_empty_when_none_installed(fake_tools):
    fake_tools(set())
    assert tr.tools_for("web_content_discovery") == []


# ── failure-driven swap (substitute) ──────────────────────────────────────────
def test_next_after_returns_next_installed(fake_tools):
    fake_tools({"feroxbuster", "ffuf", "gobuster"})
    assert tr.next_after("web_content_discovery", "feroxbuster") == "ffuf"


def test_next_after_skips_uninstalled(fake_tools):
    fake_tools({"feroxbuster", "gobuster"})  # ffuf missing
    assert tr.next_after("web_content_discovery", "feroxbuster") == "gobuster"


def test_next_after_none_at_end_of_chain(fake_tools):
    fake_tools({"feroxbuster", "gobuster"})
    assert tr.next_after("web_content_discovery", "gobuster") is None


# ── failure classification + recommended action ───────────────────────────────
@pytest.mark.parametrize("rc,err,expected", [
    (127, "", "missing"),
    (124, "", "timeout"),
    (137, "", "timeout"),                          # 128+9 SIGKILL (timeout --signal)
    (1, "timed out waiting for response", "timeout"),
    (1, "bash: nuclei: command not found", "missing"),
    (1, "Permission denied", "permission"),
    (1, "HTTP 429 Too Many Requests", "rate_limit"),
    (1, "rate limit exceeded", "rate_limit"),
    (1, "Could not resolve host: example.invalid", "network"),
    (1, "connection refused", "network"),
    (1, "404 Not Found", "not_found"),
    (2, "some unexpected parser error", "other"),
])
def test_classify_failure(rc, err, expected):
    assert tr.classify_failure(rc, stderr=err) == expected


def test_classify_failure_success_is_ok():
    assert tr.classify_failure(0, stderr="") == "ok"


def test_missing_input_file_is_not_missing_binary(fake_tools):
    # review fix: a missing wordlist/target FILE must not be classified as a missing BINARY
    # (which would wrongly swap to an alternative that hits the same missing input).
    assert tr.classify_failure(1, stderr="open /wordlists/big.txt: no such file or directory") == "other"


@pytest.mark.parametrize("category,action", [
    ("ok", "continue"),
    ("not_found", "continue"),     # empty result must not kill the phase (review consensus)
    ("missing", "swap"),
    ("permission", "swap"),        # an unprivileged alternative may exist
    ("other", "swap"),
    ("timeout", "retry"),          # retry slower before swapping
    ("rate_limit", "backoff"),
    ("network", "backoff"),        # transient archive/DNS stalls, not a hard abort
])
def test_recommend_action(category, action):
    assert tr.recommend_action(category) == action


# ── deterministic plan + degradation visibility ───────────────────────────────
def test_plan_maps_capabilities_to_mode_and_tools(fake_tools):
    fake_tools({"httpx", "nuclei", "ffuf"})
    by_cap = {c: (m, tools) for c, m, tools in tr.plan("quick")}
    assert by_cap["http_probe"] == ("substitute", ["httpx"])
    assert by_cap["vuln_templates"] == ("substitute", ["nuclei"])
    assert by_cap["web_content_discovery"] == ("substitute", ["ffuf"])


def test_plan_marks_unavailable_capabilities_empty(fake_tools):
    fake_tools({"httpx"})  # no nuclei, no fuzzers
    by_cap = {c: tools for c, _m, tools in tr.plan("quick")}
    assert by_cap["http_probe"] == ["httpx"]
    assert by_cap["vuln_templates"] == []
    assert by_cap["web_content_discovery"] == []


def test_missing_capabilities_lists_fully_degraded(fake_tools):
    fake_tools({"httpx"})
    missing = tr.missing_capabilities("quick")
    assert "vuln_templates" in missing
    assert "web_content_discovery" in missing
    assert "http_probe" not in missing


def test_select_capabilities_ip_target_drops_subdomain(fake_tools):
    fake_tools({"nmap", "nuclei"})
    caps = tr.select_capabilities("comprehensive", target_type="ip")
    assert "subdomain_enum" not in caps
    assert "subdomain_takeover" not in caps
    assert "port_scan" in caps


def test_select_capabilities_url_keeps_subdomain(fake_tools):
    fake_tools({"subfinder"})
    caps = tr.select_capabilities("comprehensive", target_type="url")
    assert "subdomain_enum" in caps


def test_unknown_objective_is_empty(fake_tools):
    fake_tools({"nmap"})
    assert tr.select_capabilities("bogus_objective") == []


def test_scope_lock_drops_subdomain_even_for_url(fake_tools):
    # review fix: exact-host engagement (--scope-lock) must skip subdomain enum/takeover
    # regardless of target_type, so callers don't have to remember to filter.
    fake_tools({"subfinder", "nuclei"})
    caps = tr.select_capabilities("comprehensive", target_type="url", scope_lock=True)
    assert "subdomain_enum" not in caps
    assert "subdomain_takeover" not in caps
    assert "vuln_templates" in caps


def test_scope_lock_threads_through_plan(fake_tools):
    fake_tools({"nuclei"})
    caps = [c for c, _m, _t in tr.plan("comprehensive", target_type="url", scope_lock=True)]
    assert "subdomain_enum" not in caps


# ── bounded recovery (loop-safety, review concern) ────────────────────────────
def test_recover_retries_then_escalates_to_swap(fake_tools):
    fake_tools({"feroxbuster", "ffuf"})
    # within retry budget -> retry same tool
    assert tr.recover("web_content_discovery", "feroxbuster", "timeout", attempt=0) == ("retry", "feroxbuster")
    # budget exhausted -> escalate to swap to the next installed tool
    assert tr.recover("web_content_discovery", "feroxbuster", "timeout", attempt=tr.MAX_RETRIES) == ("swap", "ffuf")


def test_recover_swap_skips_already_tried(fake_tools):
    fake_tools({"feroxbuster", "ffuf", "gobuster"})
    assert tr.recover("web_content_discovery", "feroxbuster", "missing", tried=("ffuf",)) == ("swap", "gobuster")


def test_recover_gives_up_at_end_of_chain(fake_tools):
    fake_tools({"feroxbuster", "gobuster"})
    assert tr.recover("web_content_discovery", "gobuster", "missing") == ("give_up", None)


def test_recover_continue_on_empty_result(fake_tools):
    fake_tools({"feroxbuster"})
    assert tr.recover("web_content_discovery", "feroxbuster", "not_found") == ("continue", None)


def test_recover_cannot_infinite_loop(fake_tools):
    # Drive the full recovery loop to a terminal state; must converge, never spin.
    fake_tools({"feroxbuster", "ffuf", "gobuster"})
    tool, tried, attempt, steps = "feroxbuster", set(), 0, 0
    while True:
        steps += 1
        assert steps < 50, "recovery did not terminate"
        action, nxt = tr.recover("web_content_discovery", tool, "missing", attempt=attempt, tried=tried)
        if action in ("give_up", "continue"):
            break
        tried.add(tool)
        tool = nxt
    assert action == "give_up"


# ── caching ───────────────────────────────────────────────────────────────────
def test_availability_is_cached_until_reset(monkeypatch):
    calls = {"n": 0}
    def counting_which(name):
        calls["n"] += 1
        return "/usr/bin/" + name
    monkeypatch.setattr(tr, "_which", counting_which)
    tr.reset_cache()
    tr.available("nmap"); tr.available("nmap"); tr.available("nmap")
    assert calls["n"] == 1
    tr.reset_cache()
    tr.available("nmap")
    assert calls["n"] == 2

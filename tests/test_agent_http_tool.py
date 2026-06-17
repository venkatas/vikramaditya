"""agent.py wiring for the http_request tool: it must be registered, dispatch to
agent_http.probe, return an LLM-digestible observation, and stay scope-gated
(loopback/operator-listener blocked by the existing scopeguard pass)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import agent  # noqa: E402
import agent_http  # noqa: E402


def _dispatcher(tmp_path):
    mem = agent.HuntMemory(str(tmp_path / "sess.json"))
    return agent.ToolDispatcher("victim.example", mem, scope_lock=True, max_urls=10)


def test_http_request_is_registered():
    assert "http_request" in agent.TOOL_NAMES


def test_http_request_dispatch_calls_probe(tmp_path, monkeypatch):
    captured = {}

    def fake_probe(method, url, **kw):
        captured["method"] = method
        captured["url"] = url
        return {"status": 200, "headers": {"Content-Type": "text/html"}, "body": "<h1>hi</h1>",
                "bytes": 10, "truncated": False, "is_binary": False, "content_type": "text/html",
                "elapsed_ms": 5, "url": url, "final_url": url, "method": method, "error": ""}

    monkeypatch.setattr(agent_http, "probe", fake_probe)
    d = _dispatcher(tmp_path)
    obs = d.dispatch("http_request", {"url": "http://victim.example/api/user/1", "method": "GET"})
    assert captured["url"] == "http://victim.example/api/user/1"
    assert captured["method"] == "GET"
    assert "200" in obs                      # status surfaced to the LLM
    assert "hi" in obs                        # body excerpt surfaced


def test_http_request_blocks_loopback(tmp_path):
    d = _dispatcher(tmp_path)
    obs = d.dispatch("http_request", {"url": "http://127.0.0.1:8080/", "method": "GET"})
    assert "BLOCKED" in obs                   # scopeguard refuses the operator's own listener


# ── Codex fix: scope-lock must keep http_request on the engagement target ───────

def test_http_request_scope_lock_blocks_offsite(tmp_path, monkeypatch):
    import agent_http
    monkeypatch.setattr(agent_http, "probe", lambda *a, **k: (_ for _ in ()).throw(AssertionError("probe should NOT run")))
    d = _dispatcher(tmp_path)   # scope_lock=True, domain=victim.example
    obs = d.dispatch("http_request", {"url": "https://google.com/", "method": "GET"})
    assert "scope" in obs.lower() or "BLOCKED" in obs   # refused, probe never called


def test_http_request_scope_lock_allows_subdomain(tmp_path, monkeypatch):
    import agent_http
    seen = {}
    monkeypatch.setattr(agent_http, "probe", lambda method, url, **k: seen.update(url=url) or {
        "status": 200, "headers": {}, "body": "ok", "bytes": 2, "truncated": False,
        "is_binary": False, "content_type": "", "elapsed_ms": 1, "url": url,
        "final_url": url, "method": method, "error": ""})
    d = _dispatcher(tmp_path)
    obs = d.dispatch("http_request", {"url": "https://api.victim.example/v1", "method": "GET"})
    assert seen.get("url") == "https://api.victim.example/v1"   # subdomain allowed
    assert "200" in obs

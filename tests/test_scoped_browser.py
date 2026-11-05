"""Exact browser scope must contain redirects, resources, and JS network APIs."""
import asyncio
import contextlib
import http.server
import json
from pathlib import Path
import threading

import pytest

import browser_agent
import scoped_browser


class _Context:
    def __init__(self):
        self.events = []

    async def route(self, pattern, handler):
        self.events.append(("http", pattern, handler))

    async def route_web_socket(self, pattern, handler):
        self.events.append(("websocket", pattern, handler))

    async def add_init_script(self, source):
        self.events.append(("init", source))


class _Response:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}
        self.disposed = False

    async def dispose(self):
        self.disposed = True


class _Route:
    def __init__(self, response=None):
        self.response = response or _Response()
        self.events = []

    async def abort(self, reason):
        self.events.append(("abort", reason))

    async def fetch(self, **kwargs):
        self.events.append(("fetch", kwargs))
        return self.response

    async def fulfill(self, **kwargs):
        self.events.append(("fulfill", kwargs))


def _policy():
    context = _Context()
    blocked = []
    asyncio.run(scoped_browser.install_scope_routes(context, {"example.invalid"}, blocked))
    return context.events[0][2], blocked


@pytest.mark.parametrize("destination", [
    "https://www.example.invalid/", "https://outside.invalid/", "https://example.invalid:8443/",
    "https://example.invalid@outside.invalid/", "file:///tmp/no", "https://user@example.invalid/",
])
def test_initial_resource_is_checked_before_fetch(destination):
    handler, blocked = _policy()
    route = _Route()
    request = type("Request", (), {"url": destination, "method": "GET"})()
    asyncio.run(handler(route, request))
    assert [e[0] for e in route.events] == ["abort"]
    assert blocked[0]["url"] == destination


def test_redirect_is_checked_without_automatic_fetch_following():
    handler, blocked = _policy()
    response = _Response(302, {"location": "https://outside.invalid/"})
    route = _Route(response)
    request = type("Request", (), {"url": "https://example.invalid/start", "method": "GET"})()
    asyncio.run(handler(route, request))
    assert [e[0] for e in route.events] == ["fetch", "abort"]
    assert route.events[0][1]["max_redirects"] == 0
    assert response.disposed
    assert blocked[0]["reason"] == "off-scope redirect"


def test_allowed_relative_redirect_is_passed_to_browser():
    handler, blocked = _policy()
    route = _Route(_Response(302, {"location": "/same-host"}))
    request = type("Request", (), {"url": "https://example.invalid/start", "method": "GET"})()
    asyncio.run(handler(route, request))
    assert [e[0] for e in route.events] == ["fetch", "fulfill"]
    assert blocked == []


def test_unsafe_method_is_blocked_before_fetch():
    handler, blocked = _policy()
    route = _Route()
    request = type("Request", (), {"url": "https://example.invalid/write", "method": "POST"})()
    asyncio.run(handler(route, request))
    assert [e[0] for e in route.events] == ["abort"]
    assert blocked[0]["reason"] == "unsafe method disabled"


def test_missing_websocket_interception_fails_before_any_route():
    class OldContext:
        async def route(self, *args):
            raise AssertionError("old backend must fail before installing partial policy")

    with pytest.raises(RuntimeError, match="WebSockets"):
        asyncio.run(scoped_browser.install_scope_routes(OldContext(), {"example.invalid"}, []))


def test_empty_allowlist_or_bad_initial_url_does_not_import_browser(tmp_path, monkeypatch):
    for urls, allowed in [(["https://example.invalid"], set()),
                           (["https://outside.invalid"], {"example.invalid"})]:
        with pytest.raises(ValueError):
            asyncio.run(scoped_browser.render_pages(urls, allowed, tmp_path))


def test_browser_agent_exact_branch_bypasses_uncontained_agent_backend(tmp_path, monkeypatch):
    agent = browser_agent.BrowserAgent("https://example.invalid", tmp_path,
                                       scope_lock=True, exact_hosts={"example.invalid"})
    monkeypatch.setattr(agent, "_init_llm", lambda: (_ for _ in ()).throw(AssertionError("LLM called")))
    async def render(*args, **kwargs):
        assert args[1] == {"example.invalid"}
        return {"completed": 1, "failed": 0, "pages": [{"final_url": "https://example.invalid/",
            "forms": [{"action": "https://example.invalid/submit", "scope_allowed": True},
                      {"action": "https://outside.invalid/submit", "scope_allowed": False}]}]}
    monkeypatch.setattr(scoped_browser, "render_pages", render)
    assert agent.run() == {"GuardedRendering": 0}
    assert agent.partial
    assert agent._tasks_completed == 1
    assert "LLM-driven vulnerability validation unavailable" in (tmp_path / "manual_review" / "coverage_gaps.txt").read_text()
    assert "outside.invalid" not in (tmp_path / "browser" / "form_discovery.txt").read_text()


def test_browser_agent_infers_authoritative_persisted_scope(tmp_path):
    recon = tmp_path / "recon" / "example.invalid" / "sessions" / "s1" / "scope"
    recon.mkdir(parents=True)
    (recon / "allow.txt").write_text("example.invalid\n")
    findings = tmp_path / "findings" / "example.invalid" / "sessions" / "s1"
    agent = browser_agent.BrowserAgent("https://example.invalid", findings)
    assert agent.scope_lock and agent.exact_hosts == {"example.invalid"}


def test_cli_records_failure_without_overwriting_existing_coverage(tmp_path):
    urls = tmp_path / "urls.txt"
    urls.write_text("https://example.invalid/\n")
    coverage = tmp_path / "coverage_degraded.json"
    coverage.write_text(json.dumps([{"tool": "sqlmap", "reason": "earlier timeout"}]))
    rc = scoped_browser.main(["--allow-file", str(tmp_path / "missing"),
        "--urls-file", str(urls), "--output-dir", str(tmp_path / "screens"),
        "--coverage-file", str(coverage)])
    assert rc == 2
    rows = json.loads(coverage.read_text())
    assert rows[0]["tool"] == "sqlmap"
    assert rows[1]["tool"] == "browser" and "allowlist" in rows[1]["reason"]


def test_cli_records_screenshot_cap_as_degraded(tmp_path, monkeypatch):
    urls = tmp_path / "urls.txt"
    urls.write_text("https://example.invalid/a\nhttps://example.invalid/b\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("example.invalid\n")
    coverage = tmp_path / "coverage_degraded.json"
    async def render(supplied, *args, **kwargs):
        assert supplied == ["https://example.invalid/a"]
        return {"completed": 1, "failed": 0, "blocked": [], "pages": [{}]}
    monkeypatch.setattr(scoped_browser, "render_pages", render)
    rc = scoped_browser.main(["--allow-file", str(allow), "--urls-file", str(urls),
        "--out-dir", str(tmp_path / "screens"), "--max-urls", "1",
        "--coverage-file", str(coverage)])
    assert rc == 0
    assert "1 of 2" in json.loads(coverage.read_text())[0]["reason"]


def test_open_redirect_prompt_never_authorizes_external_navigation():
    task = browser_agent.OpenRedirectTask("https://example.invalid", "/tmp/findings")
    assert "Never leave the target origin" in task.prompt
    assert "follow the redirect" not in task.prompt
    assert "ends up at evil" not in task.prompt


@contextlib.contextmanager
def _server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.seen.append(("GET", self.path))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", self.server.destination)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self.server.html.encode())

        def do_POST(self):
            self.server.seen.append(("POST", self.path))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.seen = []
    server.destination = "/final"
    server.html = "<html><title>Allowed</title><form action='/submit'><input name='name'></form></html>"
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_real_browser_contains_redirect_resources_popups_fetch_and_websocket(tmp_path):
    pytest.importorskip("playwright.async_api")
    with _server() as (origin, url), _server() as (outside, outside_url):
        origin.html = f"""<html><title>Guard test</title>
        <img src='{outside_url}/image'><iframe src='{outside_url}/frame'></iframe>
        <script>
        fetch('{outside_url}/fetch').catch(()=>{{}});
        fetch('/unsafe', {{method:'POST'}}).catch(()=>{{}});
        window.open('{outside_url}/popup');
        try {{new WebSocket('{outside_url.replace('http:', 'ws:')}/socket')}} catch (_) {{}}
        try {{new Worker('{outside_url}/worker')}} catch (_) {{}}
        try {{new RTCPeerConnection({{iceServers:[{{urls:'stun:outside.invalid'}}]}})}} catch (_) {{}}
        navigator.serviceWorker.register('/sw.js').catch(()=>{{}});
        </script><form action='/submit'><input name='real'></form></html>"""
        result = asyncio.run(scoped_browser.render_pages([url], {url.split('://')[1]}, tmp_path,
                                                         timeout=5, settle_ms=800))
        assert result['completed'] == 1
        assert outside.seen == []
        assert ('POST', '/unsafe') not in origin.seen
        assert ('GET', '/sw.js') not in origin.seen
        assert result['pages'][0]['forms'][0]['scope_allowed'] is True
        assert list(tmp_path.glob('*.png'))
        assert any('off-scope' in item['reason'] for item in result['blocked'])
        assert any(item['reason'] == 'websocket disabled' for item in result['blocked'])
        outside.seen.clear()
        origin.destination = outside_url + '/off-scope-redirect'
        result = asyncio.run(scoped_browser.render_pages([url + '/redirect'], {url.split('://')[1]},
                                                         tmp_path / 'redirect', timeout=5))
        assert result['failed'] == 1
        assert outside.seen == []


def test_real_browser_keeps_permitted_redirect_working(tmp_path):
    pytest.importorskip("playwright.async_api")
    with _server() as (origin, url):
        result = asyncio.run(scoped_browser.render_pages([url + '/redirect'], {url.split('://')[1]},
                                                         tmp_path, timeout=5, settle_ms=0))
        assert result['completed'] == 1
        assert result['pages'][0]['final_url'] == url + '/final'
        assert ('GET', '/final') in origin.seen

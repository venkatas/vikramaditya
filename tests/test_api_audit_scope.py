"""Exercise the OpenAPI active boundary using only local, instrumented servers."""
import json
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import api_audit


@pytest.fixture
def servers(monkeypatch):
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    monkeypatch.delenv("SCOPE_LOCK", raising=False)
    running = []

    def start(routes):
        hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                status, headers, body = routes.get(self.path, (404, {}, "missing"))
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        running.append((server, thread))
        return f"http://127.0.0.1:{server.server_port}", hits

    yield start
    for server, thread in running:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def allow_host(url):
    return {url.split("://", 1)[1]}


def write_recon(tmp_path, host, *, scope=True):
    (tmp_path / "live").mkdir()
    (tmp_path / "live" / "urls.txt").write_text(host + "\n")
    if scope:
        (tmp_path / "scope").mkdir()
        (tmp_path / "scope" / "allow.txt").write_text(next(iter(allow_host(host))) + "\n")


def test_initial_destination_and_redirect_hops_are_blocked(servers):
    sink, sink_hits = servers({"/stolen": (200, {}, "secret")})
    routes = {}
    origin, origin_hits = servers(routes)
    routes.update({
        "/first": (302, {"Location": "/second"}, ""),
        "/second": (307, {"Location": sink + "/stolen"}, ""),
    })
    blocked = api_audit.fetch(sink + "/stolen", exact_hosts=allow_host(origin))
    redirected = api_audit.fetch(origin + "/first", exact_hosts=allow_host(origin))
    assert blocked["status"] == redirected["status"] == 0
    assert blocked["scope_blocked"] == redirected["scope_blocked"] == sink + "/stolen"
    assert sink_hits == []
    assert origin_hits == ["/first", "/second"]


@pytest.mark.parametrize("destination", ["file:///etc/passwd", "http://example.test/", "http://user@127.0.0.1/"])
def test_malicious_redirect_forms_fail_closed(servers, destination):
    origin, hits = servers({"/redirect": (302, {"Location": destination}, "")})
    response = api_audit.fetch(origin + "/redirect", exact_hosts=allow_host(origin))
    assert response["status"] == 0 and response["scope_blocked"] == destination
    assert hits == ["/redirect"]


def test_allowed_redirects_and_unlocked_behavior_remain(servers):
    sink, sink_hits = servers({"/ok": (200, {"Content-Type": "application/json"}, '{"ok":true}')})
    routes = {"/ok": (200, {"Content-Type": "application/json"}, '{"ok":true}')}
    origin, hits = servers(routes)
    routes["/allowed"] = (303, {"Location": "/ok"}, "")
    routes["/unlocked"] = (302, {"Location": sink + "/ok"}, "")
    assert api_audit.fetch(origin + "/allowed", exact_hosts=allow_host(origin))["status"] == 200
    assert api_audit.fetch(origin + "/unlocked")["status"] == 200
    assert hits == ["/allowed", "/ok", "/unlocked"] and sink_hits == ["/ok"]


def test_target_spec_servers_and_html_links_never_escape(servers, tmp_path, monkeypatch):
    sink, sink_hits = servers({"/users": (200, {}, '{"secret":true}')})
    routes = {}
    origin, hits = servers(routes)
    routes["/swagger.json"] = (200, {"Content-Type": "application/json"}, json.dumps({
        "openapi": "3.0.0", "servers": [{"url": sink}],
        "paths": {"/users": {"get": {"summary": "external users"}}},
    }))
    routes["/docs"] = (200, {"Content-Type": "text/html"},
                       '<div>swagger-ui url:"' + sink + '/openapi.json"</div>')
    write_recon(tmp_path, origin)
    monkeypatch.setattr(api_audit, "SPEC_PATHS", ["/swagger.json", "/docs"])
    monkeypatch.setattr(sys, "argv", ["api_audit.py", "--recon-dir", str(tmp_path)])
    assert api_audit.main() == 0
    out = tmp_path / "api_specs"
    assert json.loads((out / "operations.json").read_text()) == []
    assert json.loads((out / "unauth_findings.json").read_text()) == []
    assert sink_hits == [] and hits == ["/swagger.json", "/docs"]
    coverage = json.loads((out / "api_coverage.json").read_text())
    assert coverage["degraded"] and coverage["scope_blocked"] == 2
    assert (out / "SCOPE_BLOCKED.marker").exists()
    assert not (out / "COVERAGE_CAPPED.marker").exists()
    assert "scope blocked" in json.loads((out / "coverage.json").read_text())[0]["reason"]


def test_allowed_spec_and_operation_still_audited(servers, tmp_path, monkeypatch):
    routes = {
        "/swagger.json": (200, {"Content-Type": "application/json"}, json.dumps({
            "openapi": "3.0.0", "paths": {"/users": {"get": {}}},
        })),
        "/users": (200, {"Content-Type": "application/json"}, '{"users":[]}'),
    }
    origin, hits = servers(routes)
    write_recon(tmp_path, origin)
    monkeypatch.setattr(api_audit, "SPEC_PATHS", ["/swagger.json"])
    monkeypatch.setattr(sys, "argv", ["api_audit.py", "--recon-dir", str(tmp_path)])
    assert api_audit.main() == 0
    assert hits == ["/swagger.json", "/users"]
    out = tmp_path / "api_specs"
    assert len(json.loads((out / "unauth_findings.json").read_text())) == 1
    assert not json.loads((out / "api_coverage.json").read_text())["degraded"]


@pytest.mark.parametrize("policy", ["missing-env", "empty-env", "missing-lock", "empty", "unreadable"])
def test_explicit_unavailable_scope_does_not_send_requests(servers, tmp_path, monkeypatch, policy):
    origin, hits = servers({})
    write_recon(tmp_path, origin, scope=False)
    path = tmp_path / "scope" / "allow.txt"
    if policy == "missing-env":
        monkeypatch.setenv("SCOPE_ALLOW_FILE", str(path))
    elif policy == "empty-env":
        monkeypatch.setenv("SCOPE_ALLOW_FILE", "")
    elif policy == "missing-lock":
        monkeypatch.setenv("SCOPE_LOCK", "1")
    elif policy == "empty":
        path.parent.mkdir()
        path.write_text("# no authorized hosts\n")
    else:
        path.mkdir(parents=True)  # cannot be read as an allowlist
    monkeypatch.setattr(sys, "argv", ["api_audit.py", "--recon-dir", str(tmp_path)])
    assert api_audit.main() == 0 and hits == []
    out = tmp_path / "api_specs"
    assert json.loads((out / "api_coverage.json").read_text())["degraded"]
    assert json.loads((out / "unauth_findings.json").read_text()) == []


def test_explicit_scope_environment_overrides_persisted_file(servers, tmp_path, monkeypatch):
    origin, hits = servers({})
    write_recon(tmp_path, origin)
    override = tmp_path / "override.txt"
    override.write_text("different.test\n")
    monkeypatch.setenv("SCOPE_ALLOW_FILE", str(override))
    assert api_audit.discover_specs(tmp_path, max_hosts=1)[2] == []
    assert hits == []


def test_locked_fetch_preserves_verified_tls_context(servers, monkeypatch):
    origin, _ = servers({"/ok": (200, {}, "ok")})
    real_builder = api_audit.build_opener
    observed = []

    def capture(*handlers):
        context = next(handler._context for handler in handlers
                       if isinstance(handler, api_audit.HTTPSHandler))
        observed.append((context.verify_mode, context.check_hostname))
        return real_builder(*handlers)

    monkeypatch.setattr(api_audit, "VERIFY_TLS", True)
    monkeypatch.setattr(api_audit, "build_opener", capture)
    assert api_audit.fetch(origin + "/ok", exact_hosts=allow_host(origin))["status"] == 200
    assert observed == [(ssl.CERT_REQUIRED, True)]

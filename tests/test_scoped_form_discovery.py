"""Exact-scope form reads must not launch an uncontained renderer."""
from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shlex
import threading
from types import SimpleNamespace

import pytest

import hunt
import scoped_http


def _forbidden(*args, **kwargs):
    raise AssertionError("uncontained renderer/HTTP fallback must not be used")


@pytest.fixture
def discovery(tmp_path, monkeypatch):
    recon = tmp_path / "recon"
    (recon / "live").mkdir(parents=True)
    (recon / "live" / "urls.txt").write_text("https://app.example.invalid/login.html\n")
    monkeypatch.delenv("SCOPE_ALLOW_FILE", raising=False)
    monkeypatch.delenv("SCOPE_LOCK", raising=False)
    monkeypatch.setattr(hunt, "_brain", None)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda *a, **k: str(recon))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "log", lambda *a, **k: None)
    monkeypatch.setattr(hunt, "_which", lambda *a, **k: False)
    gaps = []
    monkeypatch.setattr(hunt, "_mark_degraded", lambda tool, reason: gaps.append((tool, reason)))
    return recon, gaps


def _lock(recon: Path, content="app.example.invalid\n"):
    (recon / "scope").mkdir()
    allow_file = recon / "scope" / "allow.txt"
    allow_file.write_text(content)
    return allow_file


def test_scoped_helper_uses_final_response_url_and_preserves_auth(monkeypatch):
    calls = []
    closed = []
    response = SimpleNamespace(
        url="https://app.example.invalid/forms/login.html",
        text='<form action="submit" method="post"><input name="user"></form>',
        close=lambda: closed.append(True),
    )
    monkeypatch.setattr(hunt, "_lightpanda_bin", _forbidden)
    monkeypatch.setattr(hunt, "run_capture", _forbidden)
    monkeypatch.setattr(scoped_http, "get", lambda *a, **k: calls.append((a, k)) or response)

    forms = hunt._lightpanda_fetch_forms(
        "https://app.example.invalid/start.html", cookies="sid=secret",
        headers={"X-Test": "allowed"}, exact_hosts={"app.example.invalid"}, timeout=4,
    )

    assert forms == [{"action": "https://app.example.invalid/forms/submit", "method": "POST", "inputs": ["user"]}]
    assert calls[0][1]["headers"]["Cookie"] == "sid=secret"
    assert calls[0][1]["headers"]["X-Test"] == "allowed"
    assert calls[0][1]["timeout"] == 4
    assert closed == [True]


def test_unlocked_helper_preserves_lightpanda(monkeypatch):
    calls = []
    monkeypatch.setattr(hunt, "_lightpanda_bin", lambda: "/fake/lightpanda")
    monkeypatch.setattr(hunt, "run_capture", lambda *a, **k: calls.append(a[0]) or {
        "stdout": '<form action="relative" method="post"><input name="x"></form>',
        "stderr": "", "returncode": 0, "timed_out": False,
    })
    monkeypatch.setattr(scoped_http, "get", _forbidden)
    assert hunt._lightpanda_fetch_forms("https://app.example.invalid/")[0]["action"] == "relative"
    assert calls[0] == ["/fake/lightpanda", "fetch", "--log_level", "warn", "https://app.example.invalid/"]


def test_persisted_lock_never_probes_or_installs_lightpanda(discovery, monkeypatch):
    recon, gaps = discovery
    _lock(recon)
    monkeypatch.setattr(hunt, "_lightpanda_bin", _forbidden)
    monkeypatch.setattr(hunt, "_install_lightpanda", _forbidden)
    calls = []
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", lambda *a, **k: calls.append(k) or [
        {"action": "/submit", "method": "POST", "inputs": ["name"]},
        {"action": "https://app.example.invalid:8443/collect", "method": "POST", "inputs": ["secret"]},
    ])

    assert hunt.run_post_param_discovery("example.invalid") is True
    assert calls[0]["exact_hosts"] == {"app.example.invalid"}
    params = json.loads((recon / "params" / "post_params.json").read_text())
    assert set(params) == {"https://app.example.invalid/submit"}
    forms = json.loads((recon / "params" / "lightpanda_forms.json").read_text())
    assert forms[1]["scope_allowed"] is False
    assert any("static HTTP forms only" in reason for _, reason in gaps)


def test_bare_live_origin_is_an_html_seed(discovery, monkeypatch):
    recon, _ = discovery
    _lock(recon)
    (recon / "live/urls.txt").write_text("https://app.example.invalid\n")
    calls = []
    monkeypatch.setattr(hunt, "_lightpanda_bin", _forbidden)
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", lambda url, **kw: calls.append(url) or [
        {"action": "/submit", "method": "POST", "inputs": ["name"]},
    ])
    assert hunt.run_post_param_discovery("app.example.invalid") is True
    assert calls == ["https://app.example.invalid"]
    params = json.loads((recon / "params/post_params.json").read_text())
    assert set(params) == {"https://app.example.invalid/submit"}


@pytest.mark.parametrize("locked", [False, True])
def test_post_tools_disable_redirects_only_under_exact_lock(discovery, monkeypatch, locked):
    recon, _ = discovery
    if locked:
        _lock(recon)
        monkeypatch.setattr(hunt, "_lightpanda_bin", _forbidden)
    else:
        monkeypatch.setattr(hunt, "_lightpanda_bin", lambda: "/fake/lightpanda")
    monkeypatch.setattr(hunt, "_which", lambda name: name in {"arjun", "sqlmap"})
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", lambda *a, **k: [
        {"action": "/submit", "method": "POST", "inputs": ["name"]},
    ])
    commands = []
    monkeypatch.setattr(hunt, "run_cmd", lambda cmd, **k: commands.append(shlex.split(cmd)) or (True, ""))

    assert hunt.run_post_param_discovery("example.invalid") is True
    arjun = next(argv for argv in commands if argv[0] == "arjun")
    sqlmap = next(argv for argv in commands if argv[0] == "sqlmap")
    assert ("--disable-redirects" in arjun) is locked
    assert ("--ignore-redirects" in sqlmap) is locked


@pytest.mark.parametrize("missing", [False, True])
def test_empty_or_missing_explicit_scope_fails_closed(discovery, monkeypatch, missing):
    recon, gaps = discovery
    allow_file = recon / "missing.txt" if missing else _lock(recon, "")
    monkeypatch.setattr(hunt, "_lightpanda_bin", _forbidden)
    monkeypatch.setattr(hunt, "_install_lightpanda", _forbidden)
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", _forbidden)
    assert hunt.run_post_param_discovery("example.invalid", allow_file=str(allow_file)) is False
    assert any("missing or empty" in reason for _, reason in gaps)


def test_exact_seed_and_action_port_boundaries(discovery, monkeypatch):
    recon, _ = discovery
    _lock(recon, "app.example.invalid:8443\n")
    (recon / "live" / "urls.txt").write_text(
        "https://app.example.invalid:8443/login.html\n"
        "https://app.example.invalid:9443/login.html\n"
    )
    monkeypatch.setattr(hunt, "_lightpanda_bin", _forbidden)
    calls = []
    monkeypatch.setattr(hunt, "_lightpanda_fetch_forms", lambda url, **k: calls.append(url) or [
        {"action": "/submit", "method": "POST", "inputs": ["name"]},
        {"action": "https://app.example.invalid/collect", "method": "POST", "inputs": ["secret"]},
    ])
    assert hunt.run_post_param_discovery("example.invalid") is True
    assert calls == ["https://app.example.invalid:8443/login.html"]
    assert set(json.loads((recon / "params" / "post_params.json").read_text())) == {
        "https://app.example.invalid:8443/submit",
    }


def test_scoped_failed_fetch_is_not_clean_zero_completion(discovery, monkeypatch):
    recon, gaps = discovery
    _lock(recon)
    monkeypatch.setattr(hunt, "_lightpanda_bin", _forbidden)
    def fail(url, *a, **k):
        raise scoped_http.ScopeError(url, "https://evil.invalid/collect")
    monkeypatch.setattr(scoped_http, "get", fail)
    assert hunt.run_post_param_discovery("example.invalid") is False
    assert not (recon / "params" / "post_params_done.marker").exists()
    errors = json.loads((recon / "params" / "form_fetch_errors.json").read_text())
    assert errors[0]["destination"] == "https://evil.invalid/collect"
    assert any("scoped form fetch failed" in reason for _, reason in gaps)


@contextmanager
def _http_server(responder):
    hits = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            status, headers, body = responder(self.path)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body.encode())
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_scoped_form_reads_gate_redirects_and_never_render_subresources(monkeypatch):
    monkeypatch.setattr(hunt, "_lightpanda_bin", _forbidden)
    monkeypatch.setattr(hunt, "run_capture", _forbidden)
    monkeypatch.setattr(hunt, "_mark_degraded", lambda *a, **k: None)
    with _http_server(lambda path: (200, {}, "outside")) as (outside, outside_hits):
        def respond(path):
            if path == "/escape.html":
                return 302, {"Location": outside + "/escaped"}, ""
            if path == "/start.html":
                return 302, {"Location": "/forms/page.html"}, ""
            return 200, {"Content-Type": "text/html"}, (
                '<form action="submit" method="post"><input name="name"></form>'
                f'<img src="{outside}/image"><script>fetch("{outside}/fetch")</script>'
            )
        with _http_server(respond) as (inside, inside_hits):
            exact_hosts = {inside.removeprefix("http://")}
            errors = []
            assert hunt._lightpanda_fetch_forms(inside + "/escape.html", exact_hosts=exact_hosts, errors=errors) == []
            assert errors[0]["destination"] == outside + "/escaped"
            forms = hunt._lightpanda_fetch_forms(inside + "/start.html", exact_hosts=exact_hosts)
            assert forms[0]["action"] == inside + "/forms/submit"
            assert inside_hits == ["/escape.html", "/start.html", "/forms/page.html"]
            assert outside_hits == []

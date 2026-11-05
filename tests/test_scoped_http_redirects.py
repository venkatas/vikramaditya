"""Scope-lock checks must happen before every HTTP request, including redirects.

Mock transports exercise adversarial locations. Loopback-only fixtures exercise
the real requests client and the scanner's actual CSP shell helper.
"""
from __future__ import annotations

import contextlib
import http.server
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import threading

import pytest
import requests

import scoped_http


REPO = Path(__file__).resolve().parent.parent


class _Response:
    def __init__(self, status=200, body=b"ok", headers=None):
        self.status_code = status
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})
        self._body = body
        self.closed = False
        self.url = ""
        self.history = []

    def iter_content(self, chunk_size):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def close(self):
        self.closed = True

    @property
    def text(self):
        return self._content.decode()


class _Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        assert kwargs["allow_redirects"] is False
        response = self.responses.pop(0)
        response.url = url
        return response


def _transport(monkeypatch, *responses):
    session = _Session(responses)
    monkeypatch.setattr(scoped_http.requests, "Session", lambda: session)
    return session


@pytest.mark.parametrize("destination", [
    "https://www.example.invalid/",
    "https://api.example.invalid/",
    "https://example.invalid.attacker.invalid/",
    "https://example.invalid@outside.invalid/",
    "https://user:password@example.invalid/",
    "https://example.invalid:8443/",
    "//outside.invalid/path",
    "file:///etc/passwd",
    "ftp://example.invalid/file",
    "https://example.invalid\\@outside.invalid/",
])
def test_disallowed_redirect_is_never_requested(monkeypatch, destination):
    redirect = _Response(302, headers={"Location": destination})
    session = _transport(monkeypatch, redirect)
    with pytest.raises(scoped_http.ScopeError):
        scoped_http.get("https://example.invalid/", {"example.invalid"})
    assert [url for url, _ in session.calls] == ["https://example.invalid/"]
    assert redirect.closed and session.closed


@pytest.mark.parametrize("url", [
    "", "file:///etc/passwd", "https://outside.invalid/",
    "https://user@example.invalid/", "https://example.invalid:8443/",
    "https://example.invalid/with\nnewline", "https://example.invalid\\evil/",
])
def test_bad_initial_url_never_creates_transport(monkeypatch, url):
    def forbidden():
        raise AssertionError("transport created before validating initial URL")
    monkeypatch.setattr(scoped_http.requests, "Session", forbidden)
    with pytest.raises(scoped_http.ScopeError):
        scoped_http.get(url, {"example.invalid"})


def test_relative_and_same_host_scheme_redirects_work(monkeypatch):
    first = _Response(301, headers={"Location": "https://example.invalid/start"})
    second = _Response(302, headers={"Location": "/final?q=ok"})
    last = _Response(200, b"legitimate final content", {"Content-Security-Policy": "default-src 'self'"})
    session = _transport(monkeypatch, first, second, last)
    response = scoped_http.get("http://example.invalid/", {"example.invalid"})
    assert response.text == "legitimate final content"
    assert response.headers["Content-Security-Policy"] == "default-src 'self'"
    assert [url for url, _ in session.calls] == [
        "http://example.invalid/", "https://example.invalid/start", "https://example.invalid/final?q=ok",
    ]
    assert response.history == [first, second]
    assert all(r.closed for r in (first, second, last)) and session.closed


def test_late_chain_escape_is_rejected(monkeypatch):
    first = _Response(302, headers={"Location": "/second"})
    second = _Response(307, headers={"Location": "https://outside.invalid/"})
    session = _transport(monkeypatch, first, second)
    with pytest.raises(scoped_http.ScopeError) as exc:
        scoped_http.get("https://example.invalid/", {"example.invalid"})
    assert len(session.calls) == 2
    assert exc.value.source == "https://example.invalid/second"
    assert exc.value.destination == "https://outside.invalid/"
    assert first.closed and second.closed


def test_redirect_limit_closes_last_response(monkeypatch):
    first = _Response(302, headers={"Location": "/again"})
    last = _Response(302, headers={"Location": "/again"})
    session = _transport(monkeypatch, first, last)
    with pytest.raises(requests.TooManyRedirects):
        scoped_http.get("https://example.invalid/", {"example.invalid"}, max_redirects=1)
    assert len(session.calls) == 2 and first.closed and last.closed


def test_final_body_is_capped_and_socket_closed(monkeypatch):
    response = _Response(200, b"a" * 30_000)
    session = _transport(monkeypatch, response)
    result = scoped_http.get("https://example.invalid/", {"example.invalid"}, max_body=17)
    assert result.text == "a" * 17
    assert response.closed and session.closed


def test_explicitly_allowed_other_host_drops_credentials(monkeypatch):
    first = _Response(302, headers={"Location": "https://second.invalid/"})
    last = _Response()
    session = _transport(monkeypatch, first, last)
    scoped_http.get("https://example.invalid/", {"example.invalid", "second.invalid"},
                    headers={"Cookie": "sid=secret", "Authorization": "Bearer secret", "X-Test": "keep"})
    assert session.calls[1][1]["headers"] == {"X-Test": "keep"}


def test_missing_allow_file_cli_fails_without_request(monkeypatch, tmp_path, capsys):
    def forbidden():
        raise AssertionError("missing allowlist started a network request")
    monkeypatch.setattr(scoped_http.requests, "Session", forbidden)
    result = scoped_http.main(["--allow-file", str(tmp_path / "missing"), "https://example.invalid/"])
    assert result != 0
    assert "scope blocked" in capsys.readouterr().err


def test_cli_records_blocked_hop_as_passive_lead(monkeypatch, tmp_path, capsys):
    allow = tmp_path / "allow.txt"
    allow.write_text("example.invalid\n")
    lead = tmp_path / "manual_review" / "off_scope_redirects.jsonl"
    session = _transport(monkeypatch, _Response(302, headers={"Location": "https://outside.invalid/"}))
    result = scoped_http.main(["--allow-file", str(allow), "--blocked-log", str(lead),
                               "--headers-only", "https://example.invalid/"])
    assert result != 0 and len(session.calls) == 1
    assert json.loads(lead.read_text()) == {
        "source": "https://example.invalid/", "location": "https://outside.invalid/",
    }
    assert capsys.readouterr().out == ""


def test_cli_keeps_allowed_redirect_evidence_for_cms_but_only_final_csp_headers(monkeypatch, tmp_path, capsys):
    allow = tmp_path / "allow.txt"
    allow.write_text("example.invalid\n")
    for flag in ("--include-headers", "--headers-only"):
        _transport(monkeypatch,
                   _Response(301, headers={"Location": "/author/alice", "Content-Security-Policy": "initial-policy"}),
                   _Response(200, b"profile"))
        assert scoped_http.main(["--allow-file", str(allow), flag,
                                 "https://example.invalid/?author=1"]) == 0
        output = capsys.readouterr().out
        assert ("/author/alice" in output) == (flag == "--include-headers")
        assert ("initial-policy" in output) == (flag == "--include-headers")


@contextlib.contextmanager
def _server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.seen.append(self.path)
            if self.path.startswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", self.server.destination)
            else:
                self.send_response(200)
                self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            self.wfile.write(b"fixture body")

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.seen = []
    server.destination = "/final"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_transport_follows_only_allowed_loopback_hops(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    with _server() as (origin, origin_url), _server() as (sink, sink_url):
        origin.destination = sink_url + "/allowed-final"
        allowed = {origin_url.split("://")[1], sink_url.split("://")[1]}
        response = scoped_http.get(origin_url + "/redirect", allowed)
        assert response.status_code == 200 and response.text == "fixture body"
        assert sink.seen == ["/allowed-final"]
        sink.seen.clear()
        origin.destination = sink_url + "/disallowed-final"
        with pytest.raises(scoped_http.ScopeError):
            scoped_http.get(origin_url + "/redirect", {origin_url.split("://")[1]})
        assert sink.seen == []


def test_actual_scanner_csp_helper_rejects_off_scope_redirect(tmp_path):
    source = (REPO / "scanner.sh").read_text()
    start = source.index("_csp_headers() {")
    end = source.index("\n}", start) + 2
    helper = source[start:end]
    allow = tmp_path / "allow.txt"
    with _server() as (origin, origin_url), _server() as (sink, sink_url):
        allow.write_text(origin_url.split("://")[1] + "\n")
        env = dict(os.environ, SCRIPT_DIR=str(REPO), _SCOPE_ALLOW=str(allow),
                   FINDINGS_DIR=str(tmp_path / "findings"), NO_PROXY="localhost,127.0.0.1")
        # scanner invokes python3; prepend the test interpreter's directory.
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env["PATH"]
        origin.destination = sink_url + "/must-not-be-fetched"
        result = subprocess.run(["bash", "-c", helper + "\n_csp_headers " + shlex.quote(origin_url + "/redirect")],
                                env=env, capture_output=True, text=True, timeout=15)
        assert result.returncode != 0
        assert sink.seen == []
        origin.destination = "/final"
        result = subprocess.run(["bash", "-c", helper + "\n_csp_headers " + shlex.quote(origin_url + "/redirect")],
                                env=env, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0
        assert "Content-Security-Policy: default-src 'self'" in result.stdout

"""Structured HTTP probe tool (ported from xalgorix http_request).

Gives the agent/brain a native HTTP request capability — status/headers/body
(capped, binary-aware), redirect-chain inspection, multi-value headers, method
whitelist — so it can fuzz IDOR/numeric-IDs, test auth-bypass, and inspect
open-redirects mid-loop WITHOUT shelling out to curl. Output is LLM-digestible.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import agent_http  # noqa: E402


class _FakeResp:
    def __init__(self, status=200, headers=None, content=b"", url="http://t/"):
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/html"}
        self.content = content
        self.url = url

    @property
    def text(self):
        return self.content.decode("utf-8", "ignore")


def _patch(monkeypatch, resp=None, capture=None, exc=None):
    def fake_request(method, url, **kwargs):
        if capture is not None:
            capture["method"] = method
            capture["url"] = url
            capture.update(kwargs)
        if exc is not None:
            raise exc
        return resp

    monkeypatch.setattr(agent_http.requests, "request", fake_request)


# ── core structured response ──────────────────────────────────────────────────

def test_probe_returns_structured_fields(monkeypatch):
    _patch(monkeypatch, _FakeResp(200, {"Content-Type": "application/json"}, b'{"ok":true}'))
    r = agent_http.probe("GET", "http://victim.example/api/user/1")
    assert r["status"] == 200
    assert r["error"] == ""
    assert r["is_binary"] is False
    assert "ok" in r["body"]
    assert r["content_type"].startswith("application/json")
    assert isinstance(r["headers"], dict)
    assert r["method"] == "GET"


# ── binary safety: don't dump megabytes of image bytes into LLM context ─────────

def test_probe_binary_content_not_decoded(monkeypatch):
    _patch(monkeypatch, _FakeResp(200, {"Content-Type": "image/png"}, b"\x89PNG\r\n\x1a\n" + b"\x00" * 5000))
    r = agent_http.probe("GET", "http://victim.example/logo.png")
    assert r["is_binary"] is True
    assert "PNG" not in r["body"]            # raw bytes never leak into body
    assert "binary" in r["body"].lower()
    assert r["bytes"] >= 5000


# ── truncation cap so a huge HTML page can't blow the context window ────────────

def test_probe_truncates_large_body(monkeypatch):
    big = b"A" * 200_000
    _patch(monkeypatch, _FakeResp(200, {"Content-Type": "text/html"}, big))
    r = agent_http.probe("GET", "http://victim.example/big", max_body=50_000)
    assert r["truncated"] is True
    assert len(r["body"]) <= 50_050        # cap + small marker slack


# ── method whitelist (reject TRACE/CONNECT/garbage) ─────────────────────────────

def test_probe_rejects_unknown_method(monkeypatch):
    _patch(monkeypatch, _FakeResp())
    r = agent_http.probe("TRACE", "http://victim.example/")
    assert r["status"] == 0
    assert "method" in r["error"].lower()


def test_probe_accepts_standard_methods(monkeypatch):
    for m in ("get", "POST", "Put", "delete", "patch", "head", "options"):
        _patch(monkeypatch, _FakeResp())
        r = agent_http.probe(m, "http://victim.example/")
        assert r["error"] == "", f"{m} should be allowed"
        assert r["method"] == m.upper()


# ── redirect-chain inspection for open-redirect / SSRF probing ──────────────────

def test_probe_no_follow_exposes_location(monkeypatch):
    cap = {}
    _patch(monkeypatch, _FakeResp(302, {"Location": "https://evil.example/", "Content-Type": "text/html"}, b""), capture=cap)
    r = agent_http.probe("GET", "http://victim.example/redir?url=evil", follow_redirects=False)
    assert r["status"] == 302
    assert r["headers"].get("Location") == "https://evil.example/"
    assert cap["allow_redirects"] is False


# ── multi-value headers (Accept-Encoding chains, cookie lists) ──────────────────

def test_probe_joins_list_header_values(monkeypatch):
    cap = {}
    _patch(monkeypatch, _FakeResp(), capture=cap)
    agent_http.probe("GET", "http://victim.example/", headers={"Accept-Encoding": ["gzip", "br", "deflate"]})
    assert cap["headers"]["Accept-Encoding"] == "gzip, br, deflate"


# ── timeout is capped so the agent can't hang the loop on one request ───────────

def test_probe_caps_timeout(monkeypatch):
    cap = {}
    _patch(monkeypatch, _FakeResp(), capture=cap)
    agent_http.probe("GET", "http://victim.example/", timeout=9999)
    assert cap["timeout"] <= 60


# ── network failure is graceful, never raises into the agent loop ───────────────

def test_probe_network_error_is_graceful(monkeypatch):
    _patch(monkeypatch, exc=OSError("connection refused"))
    r = agent_http.probe("GET", "http://victim.example/")
    assert r["status"] == 0
    assert "connection refused" in r["error"]
    assert r["body"] == ""


# ── Codex review fixes ──────────────────────────────────────────────────────

def _patch_seq(monkeypatch, responses, capture=None):
    """Return responses[i] on the i-th request call (for redirect chains)."""
    seq = list(responses)

    def fake_request(method, url, **kwargs):
        if capture is not None:
            capture.setdefault("urls", []).append(url)
        return seq.pop(0) if seq else _FakeResp(200, {"Content-Type": "text/html"}, b"end")

    monkeypatch.setattr(agent_http.requests, "request", fake_request)


def test_probe_follows_allowed_redirect(monkeypatch):
    cap = {}
    _patch_seq(monkeypatch, [
        _FakeResp(302, {"Location": "http://victim.example/next", "Content-Type": "text/html"}, b""),
        _FakeResp(200, {"Content-Type": "text/html"}, b"<h1>landed</h1>"),
    ], capture=cap)
    r = agent_http.probe("GET", "http://victim.example/start", allow_url=lambda u: True)
    assert r["status"] == 200
    assert "landed" in r["body"]
    assert cap["urls"][1] == "http://victim.example/next"   # second hop actually fetched


def test_probe_does_not_follow_redirect_to_disallowed_host(monkeypatch):
    cap = {}
    _patch_seq(monkeypatch, [
        _FakeResp(302, {"Location": "http://127.0.0.1:8080/", "Content-Type": "text/html"}, b""),
        _FakeResp(200, {"Content-Type": "text/html"}, b"SHOULD NOT REACH"),
    ], capture=cap)
    # allow_url refuses the loopback hop → the open-redirect is surfaced, not followed
    r = agent_http.probe("GET", "http://victim.example/redir", allow_url=lambda u: "127.0.0.1" not in u)
    assert r["status"] == 302
    assert r["headers"].get("Location") == "http://127.0.0.1:8080/"
    assert r.get("redirect_blocked") == "http://127.0.0.1:8080/"
    assert len(cap["urls"]) == 1                              # second hop never fetched


def test_probe_caps_redirect_chain(monkeypatch):
    # an infinite redirect loop must terminate at max_redirects, never hang
    cap = {}
    loop = [_FakeResp(302, {"Location": "http://victim.example/loop", "Content-Type": "text/html"}, b"")
            for _ in range(50)]
    _patch_seq(monkeypatch, loop, capture=cap)
    r = agent_http.probe("GET", "http://victim.example/loop", max_redirects=3, allow_url=lambda u: True)
    assert len(cap["urls"]) <= 4                              # initial + at most max_redirects hops


def test_probe_byte_sniffs_mislabeled_binary(monkeypatch):
    # server lies: Content-Type text/html but body is NUL-laden binary
    _patch(monkeypatch, _FakeResp(200, {"Content-Type": "text/html"}, b"\x00\x01\x02BINARY\x00\x00ware"))
    r = agent_http.probe("GET", "http://victim.example/x")
    assert r["is_binary"] is True
    assert "BINARY" not in r["body"]


# ── stream=True connection-leak regression (every exit path must close resp) ──

class _ClosableResp(_FakeResp):
    """A response that records close() calls and exposes iter_content so the
    stream=True read path in agent_http exercises the same code as production."""

    def __init__(self, status=200, headers=None, content=b"", url="http://t/"):
        super().__init__(status, headers, content, url)
        self.closed = 0

    def iter_content(self, chunk_size):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        self.closed += 1


def test_probe_closes_response_on_terminal_path(monkeypatch):
    # the ordinary 200 terminal response must be closed exactly once
    resp = _ClosableResp(200, {"Content-Type": "text/html"}, b"<h1>ok</h1>")
    _patch(monkeypatch, resp)
    r = agent_http.probe("GET", "http://victim.example/x")
    assert r["status"] == 200
    assert "ok" in r["body"]
    assert resp.closed == 1, "stream=True response leaked: close() never called"


def test_probe_closes_response_on_redirect_blocked_path(monkeypatch):
    # the redirect-blocked branch must also close the response it read
    blocked = _ClosableResp(302, {"Location": "http://127.0.0.1:8080/", "Content-Type": "text/html"}, b"")
    _patch(monkeypatch, blocked)
    r = agent_http.probe("GET", "http://victim.example/redir", allow_url=lambda u: "127.0.0.1" not in u)
    assert r.get("redirect_blocked") == "http://127.0.0.1:8080/"
    assert blocked.closed == 1, "redirect_blocked response leaked: close() never called"


def test_probe_closes_every_hop_in_redirect_chain(monkeypatch):
    # each followed hop AND the terminal response must be closed (no leaks)
    hop = _ClosableResp(302, {"Location": "http://victim.example/next", "Content-Type": "text/html"}, b"")
    final = _ClosableResp(200, {"Content-Type": "text/html"}, b"<h1>landed</h1>")
    seq = [hop, final]

    def fake_request(method, url, **kwargs):
        return seq.pop(0) if seq else final

    monkeypatch.setattr(agent_http.requests, "request", fake_request)
    r = agent_http.probe("GET", "http://victim.example/start", allow_url=lambda u: True)
    assert r["status"] == 200
    assert hop.closed == 1, "intermediate redirect hop leaked"
    assert final.closed == 1, "terminal response leaked"

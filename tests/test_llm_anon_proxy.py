"""Proxy tests — no network, no real Anthropic, no real Claude Code.

Two strategies:

1. *Unit-level*: exercise the pure-function helpers (``_anonymise_body``,
   ``_deanonymise_body``, ``_deanonymise_sse_line``) that do the byte-level
   work. These are what the critical-path invariants rest on, so they
   deserve tight tests.

2. *Integration*: stand up a FastAPI app pointed at a second FastAPI app
   acting as the upstream, using httpx's ASGITransport. That lets us drive
   a full request/response cycle — including SSE — entirely in-process.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse

from llm_anon import Anonymizer, Vault
from llm_anon.proxy import (
    _anonymise_body, _deanonymise_body, _deanonymise_sse_line,
    _walk_strings, create_app,
)


# ---------------------------------------------------------------------------
# Helpers: anonymizer bound to an in-memory vault
# ---------------------------------------------------------------------------


@pytest.fixture
def anon(tmp_path) -> Anonymizer:
    vault = Vault(tmp_path / "proxy.db", engagement_id="proxy-test")
    return Anonymizer(vault)


# ---------------------------------------------------------------------------
# Unit — body transforms
# ---------------------------------------------------------------------------


class TestBodyTransforms:
    def test_anonymise_json_walks_strings(self, anon: Anonymizer) -> None:
        body = json.dumps({
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": "scan 10.20.0.10"}],
            "metadata": {"target_ip": "10.20.0.10"},
        }).encode()
        out = _anonymise_body(body, "application/json", anon)
        assert b"10.20.0.10" not in out
        parsed = json.loads(out)
        assert parsed["model"] == "claude-sonnet-4"  # non-PII preserved

    def test_anonymise_plaintext_body(self, anon: Anonymizer) -> None:
        out = _anonymise_body(b"target host DC01 at 10.20.0.10", "text/plain", anon)
        assert b"10.20.0.10" not in out

    def test_deanonymise_roundtrip_json(self, anon: Anonymizer) -> None:
        body = json.dumps({"x": "see 10.20.0.10 and admin@contoso.local"}).encode()
        anonymised = _anonymise_body(body, "application/json", anon)
        restored = _deanonymise_body(anonymised, "application/json", anon)
        assert json.loads(restored) == json.loads(body)

    def test_binary_body_passes_through(self, anon: Anonymizer) -> None:
        binary = b"\x89PNG\r\n\x1a\n" + b"\xff" * 32
        out = _anonymise_body(binary, "image/png", anon)
        assert out == binary

    def test_empty_body(self, anon: Anonymizer) -> None:
        assert _anonymise_body(b"", "application/json", anon) == b""

    def test_walk_strings_preserves_non_str(self) -> None:
        obj = {"n": 1, "b": True, "list": [2, None, "keep"]}
        out = _walk_strings(obj, lambda s: s.upper())
        assert out == {"n": 1, "b": True, "list": [2, None, "KEEP"]}


# ---------------------------------------------------------------------------
# Unit — SSE line handling
# ---------------------------------------------------------------------------


class TestSSE:
    def test_passthrough_comment(self, anon: Anonymizer) -> None:
        assert _deanonymise_sse_line(": heartbeat", anon) == ": heartbeat"

    def test_passthrough_event_line(self, anon: Anonymizer) -> None:
        assert _deanonymise_sse_line("event: message_start", anon) == "event: message_start"

    def test_passthrough_done(self, anon: Anonymizer) -> None:
        assert _deanonymise_sse_line("data: [DONE]", anon) == "data: [DONE]"

    def test_malformed_data_passthrough(self, anon: Anonymizer) -> None:
        assert _deanonymise_sse_line("data: not-json", anon) == "data: not-json"

    def test_deanonymises_text_delta(self, anon: Anonymizer) -> None:
        # Pre-seed a mapping so we have something to restore.
        anon.anonymize("recon on 10.20.0.10")
        surrogate = anon._vault.get_surrogate("ipv4", "10.20.0.10")
        assert surrogate is not None

        line = ("data: " + json.dumps({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": f"scanned {surrogate}"}
        }))
        out = _deanonymise_sse_line(line, anon)
        parsed = json.loads(out[len("data: "):])
        assert parsed["delta"]["text"] == "scanned 10.20.0.10"


# ---------------------------------------------------------------------------
# Integration — full proxy round-trip against a fake upstream
# ---------------------------------------------------------------------------


def _build_fake_upstream(capture: list[bytes]) -> FastAPI:
    """Fake Anthropic-ish upstream that records what it was sent."""
    up = FastAPI()

    @up.post("/v1/messages")
    async def messages(req: Request):
        body = await req.body()
        capture.append(body)
        # Echo-ish JSON response that references one of the incoming strings
        # so we can verify deanonymisation.
        parsed = json.loads(body)
        content_str = parsed["messages"][0]["content"]
        return JSONResponse({
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": f"observed: {content_str}"}],
        })

    @up.post("/v1/messages/stream")
    async def stream(req: Request):
        body = await req.body()
        capture.append(body)
        parsed = json.loads(body)
        echoed = parsed["messages"][0]["content"]

        async def gen():
            yield "event: message_start\n".encode()
            yield ("data: " + json.dumps({
                "type": "content_block_delta",
                "delta": {"type": "text_delta", "text": f"saw {echoed}"}
            }) + "\n").encode()
            yield "data: [DONE]\n".encode()

        return StreamingResponse(gen(), media_type="text/event-stream")

    return up


@pytest.fixture
def wired(tmp_path):
    """Proxy app + stub upstream wired together via httpx ASGI transport.

    The proxy is built with a ``http_client_factory`` that yields clients
    pointed at the in-process upstream app. No network, no real Anthropic.
    """
    vault = Vault(tmp_path / "wired.db", engagement_id="wired-test")
    anon = Anonymizer(vault)
    capture: list[bytes] = []
    upstream_app = _build_fake_upstream(capture)

    def factory():
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=upstream_app),
            base_url="http://upstream",
        )

    app = create_app(anonymizer=anon, upstream="http://upstream",
                    http_client_factory=factory)
    yield app, capture, anon


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")


class TestProxyIntegration:
    @pytest.mark.asyncio
    async def test_health_reports_engagement(self, wired) -> None:
        app, _, _ = wired
        async with _client(app) as c:
            r = await c.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["engagement"] == "wired-test"
        assert "stats" in body

    @pytest.mark.asyncio
    async def test_post_anonymises_outbound_and_restores_inbound(self, wired) -> None:
        app, capture, _ = wired
        payload = {
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": "scan 10.20.0.10 now"}],
        }
        async with _client(app) as c:
            r = await c.post("/v1/messages", json=payload)
        assert r.status_code == 200

        # Upstream must have seen the surrogate, not the original.
        assert len(capture) == 1
        sent = json.loads(capture[0])
        sent_text = sent["messages"][0]["content"]
        assert "10.20.0.10" not in sent_text
        assert "203.0.113" in sent_text or "192.0.2" in sent_text or "198.51.100" in sent_text

        # Response must have the original restored for Claude Code.
        resp_body = r.json()
        echoed = resp_body["content"][0]["text"]
        assert "10.20.0.10" in echoed

    @pytest.mark.asyncio
    async def test_streaming_sse_deanonymised(self, wired) -> None:
        app, capture, _ = wired
        payload = {
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": "ping dc01.contoso.local"}],
        }
        async with _client(app) as c:
            async with c.stream("POST", "/v1/messages/stream", json=payload) as r:
                chunks = [line async for line in r.aiter_lines()]

        # Upstream saw the surrogate.
        sent_text = json.loads(capture[0])["messages"][0]["content"]
        assert "contoso.local" not in sent_text

        # The SSE text_delta reaching the "client" must contain the original.
        data_lines = [c for c in chunks if c.startswith("data:") and c != "data: [DONE]"]
        assert any("contoso.local" in l for l in data_lines), chunks



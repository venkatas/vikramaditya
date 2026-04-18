"""FastAPI reverse proxy — transparent anonymization for Claude Code.

Point Claude Code at this proxy with ``ANTHROPIC_BASE_URL=http://localhost:8080``.
Every outbound message body is anonymised; every response (including SSE
streams) is deanonymised before it reaches Claude Code.

Threat model
------------
This proxy prevents content-based correlation — Claude never sees a real
IP / hostname / hash / credential / AWS key. It does *not* prevent
correlation via query patterns, tool call sequences, or timing. Use over
an HTTPS-terminated local loopback only; do not expose it to other hosts.

Streaming protocol
------------------
Anthropic's `/v1/messages` endpoint returns Server-Sent Events (SSE). Each
``data: {...}`` line is a JSON payload carrying incremental text in
``delta.text``. We parse each line, deanonymise any ``text`` field in the
payload, and re-emit the line — the stream passes through without buffering
more than the current line. SSE comments (``:`` prefix) and event lines
pass through unchanged.

Dependencies
------------
Install with ``pip install fastapi uvicorn httpx`` — or use the provided
``scripts/run_anon_proxy.sh`` which sets up a venv.

CLI
---
    ANTHROPIC_API_KEY=sk-ant-... \
    ENGAGEMENT_ID=acme-2026 \
    python -m llm_anon.proxy
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import AsyncIterator

try:
    import httpx
    from fastapi import FastAPI, Request, Response
    from fastapi.responses import JSONResponse, StreamingResponse
except ImportError as e:  # pragma: no cover - import guard
    raise SystemExit(
        "llm_anon.proxy requires fastapi, uvicorn, and httpx.\n"
        "Install via: pip install fastapi uvicorn httpx\n"
        f"(missing: {e.name})"
    ) from e

from .anonymizer import Anonymizer
from .vault import Vault


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ANTHROPIC_UPSTREAM = os.environ.get("ANTHROPIC_UPSTREAM", "https://api.anthropic.com")
ENGAGEMENT_ID = os.environ.get("ENGAGEMENT_ID", "default")
VAULT_PATH = os.environ.get(
    "ANON_VAULT_PATH",
    str(Path.home() / ".vikramaditya" / "anon_vault.db"),
)
PROXY_PORT = int(os.environ.get("ANON_PROXY_PORT", "8080"))

# Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1).
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
})


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def _walk_strings(obj, fn):
    """Recursively transform every ``str`` leaf in a JSON-like object."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_walk_strings(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: _walk_strings(v, fn) for k, v in obj.items()}
    return obj


def create_app(
    anonymizer: Anonymizer | None = None,
    upstream: str | None = None,
    http_client_factory=None,
) -> FastAPI:
    """Build a FastAPI app bound to the given anonymizer + upstream.

    Factored out so tests can inject a stub anonymizer and a fake upstream
    without spinning up Ollama or hitting Anthropic.

    ``http_client_factory`` is a callable returning a fresh
    ``httpx.AsyncClient`` per request. The default factory builds a normal
    client talking to ``upstream``. Tests override it to route through an
    ``httpx.ASGITransport`` pointed at an in-process upstream app.
    """
    if anonymizer is None:
        vault = Vault(VAULT_PATH, engagement_id=ENGAGEMENT_ID)
        anonymizer = Anonymizer(vault)
    base_url = (upstream or ANTHROPIC_UPSTREAM).rstrip("/")
    if http_client_factory is None:
        def http_client_factory():
            return httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=None, write=60.0, pool=10.0)
            )

    app = FastAPI(title="Vikramaditya VAPT anonymization proxy")

    @app.get("/health")
    async def health() -> dict:
        # Pull engagement + vault path from the bound anonymizer so tests
        # with a non-default fixture report the right values.
        vault_obj = anonymizer._vault
        return {
            "status": "ok",
            "engagement": vault_obj.engagement_id,
            "vault_path": vault_obj.db_path,
            "upstream": base_url,
            "stats": anonymizer.stats(),
        }

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    async def proxy(request: Request, path: str):
        # --------------------------------------------------- request prep
        body_bytes = await request.body()
        anonymised_body = _anonymise_body(body_bytes, request.headers.get("content-type", ""), anonymizer)

        fwd_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP
        }

        url = f"{base_url}/{path}"
        if request.url.query:
            url = f"{url}?{request.url.query}"

        # --------------------------------------------------- send upstream
        client = http_client_factory()
        try:
            upstream_req = client.build_request(
                method=request.method,
                url=url,
                headers=fwd_headers,
                content=anonymised_body,
            )
            upstream_resp = await client.send(upstream_req, stream=True)
        except httpx.HTTPError as e:
            await client.aclose()
            return JSONResponse(
                {"error": "upstream_error", "detail": str(e)},
                status_code=502,
            )

        # --------------------------------------------------- stream back
        response_ct = upstream_resp.headers.get("content-type", "")
        # Drop hop-by-hop + any encoding headers that we'd be re-doing.
        resp_headers = {
            k: v for k, v in upstream_resp.headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "content-encoding"
        }

        if "text/event-stream" in response_ct:
            async def iter_sse() -> AsyncIterator[bytes]:
                try:
                    async for raw in upstream_resp.aiter_lines():
                        yield (_deanonymise_sse_line(raw, anonymizer) + "\n").encode("utf-8")
                finally:
                    await upstream_resp.aclose()
                    await client.aclose()
            return StreamingResponse(iter_sse(), status_code=upstream_resp.status_code,
                                     headers=resp_headers, media_type="text/event-stream")

        # Non-stream: read full body, deanonymise JSON / text, return.
        try:
            full = await upstream_resp.aread()
        finally:
            await upstream_resp.aclose()
            await client.aclose()
        out = _deanonymise_body(full, response_ct, anonymizer)
        return Response(content=out, status_code=upstream_resp.status_code,
                        headers=resp_headers, media_type=response_ct or None)

    return app


# ---------------------------------------------------------------------------
# Body transforms
# ---------------------------------------------------------------------------

def _anonymise_body(body: bytes, content_type: str, anonymizer: Anonymizer) -> bytes:
    if not body:
        return body
    if "application/json" in content_type:
        try:
            payload = json.loads(body)
        except ValueError:
            return anonymizer.anonymize(body.decode("utf-8", errors="replace")).encode("utf-8")
        transformed = _walk_strings(payload, anonymizer.anonymize)
        return json.dumps(transformed, separators=(",", ":")).encode("utf-8")
    # Plain-text fallback.
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body  # Opaque binary — pass through.
    return anonymizer.anonymize(text).encode("utf-8")


def _deanonymise_body(body: bytes, content_type: str, anonymizer: Anonymizer) -> bytes:
    if not body:
        return body
    if "application/json" in content_type:
        try:
            payload = json.loads(body)
        except ValueError:
            return anonymizer.deanonymize(body.decode("utf-8", errors="replace")).encode("utf-8")
        transformed = _walk_strings(payload, anonymizer.deanonymize)
        return json.dumps(transformed, separators=(",", ":")).encode("utf-8")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    return anonymizer.deanonymize(text).encode("utf-8")


def _deanonymise_sse_line(line: str, anonymizer: Anonymizer) -> str:
    """Deanonymise a single SSE line.

    Anthropic event streams look like::

        event: content_block_delta
        data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"..."}}

    Only ``data:`` lines carrying JSON need structural handling; everything
    else passes through unchanged.
    """
    if not line:
        return line
    if line.startswith(":") or not line.startswith("data:"):
        return line
    payload_str = line[len("data:"):].lstrip()
    if not payload_str or payload_str == "[DONE]":
        return line
    try:
        payload = json.loads(payload_str)
    except ValueError:
        return line  # Malformed — upstream's problem, don't corrupt further.
    transformed = _walk_strings(payload, anonymizer.deanonymize)
    return "data: " + json.dumps(transformed, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:  # pragma: no cover - CLI wrapper
    import uvicorn
    uvicorn.run(create_app(), host="127.0.0.1", port=PROXY_PORT, log_level="info")


if __name__ == "__main__":  # pragma: no cover
    main()

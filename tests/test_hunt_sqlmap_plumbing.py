"""Regression tests for v7.1.4 hunt.py SQLi plumbing fixes.

Covers the four bugs that surfaced on the testfire.net dogfood run:

- **Bug 3** — ``_collect_openapi_post_endpoints`` must harvest POST/PUT/PATCH
  ops from ``api_specs/*.json`` so Swagger-documented endpoints like
  ``/api/login`` reach sqlmap. Without the fix, the testfire SQLi was
  invisible to the tool.
- **Bug 4** — ``_looks_like_payload_url`` + ``_collect_urls_from_file(
  filter_payloads=True)`` must drop URLs whose query already carries a
  payload (dalfox PoCs crawled back through gau/wayback and wasted
  sqlmap cycles).

Bug 5 (threading ``--cookie`` into the sqlmap call) is a string-builder
change in ``run_sqlmap_targeted`` that's hard to unit test without
subprocessing — it's covered by the v7.1.2 approach: verify at integration
time on the next live engagement.

Bug 6 (brain triage retry) is exercised separately in
``tests/test_intel_engine.py`` patterns; brain.py's _stream_fast is not
a pure function and isn't unit-testable without Ollama.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hunt import (
    _collect_openapi_post_endpoints,
    _collect_urls_from_file,
    _looks_like_payload_url,
)


# ---------------------------------------------------------------------------
# Bug 4 — payload filtering on URL ingestion
# ---------------------------------------------------------------------------


class TestPayloadFilter:
    def test_clean_url_passes(self) -> None:
        assert _looks_like_payload_url("https://target/search?q=hello") is False

    def test_inline_script_tag_rejected(self) -> None:
        assert _looks_like_payload_url(
            "https://target/search?q=<script>alert(1)</script>"
        ) is True

    def test_url_encoded_payload_rejected(self) -> None:
        assert _looks_like_payload_url(
            "https://target/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        ) is True

    def test_srcdoc_iframe_rejected(self) -> None:
        assert _looks_like_payload_url(
            'https://target/index.jsp?content=inside_about.htm\'">'
            '<iframe srcdoc="<input onauxclick=alert(1)>">'
        ) is True

    def test_javascript_protocol_rejected(self) -> None:
        assert _looks_like_payload_url(
            "https://target/go?url=javascript:alert(1)"
        ) is True

    def test_testfire_dalfox_poc_rejected(self) -> None:
        """The exact kind of URL that contaminated Vikramaditya's SQLi candidates."""
        testfire_poc = (
            "http://altoro.testfire.net/search.jsp?"
            "query=%3Cbody+bgcolor%3D%22red%22+%2F%3E%3Ch3+style%3D%22"
            "background-color%3Apowderblue%3B%22%3EThis+website+is+...+"
            "%3Ca+href%3D%22evil.com%22%3Esecurewebsite%3C%2Fa%3E%3C%2Fh3%3E"
        )
        assert _looks_like_payload_url(testfire_poc) is True

    def test_filter_drops_payload_urls_during_collection(self, tmp_path) -> None:
        p = tmp_path / "with_params.txt"
        p.write_text(
            "https://target/api/user?id=1\n"
            "https://target/search?q=<script>alert(1)</script>\n"
            "https://target/bank/showAccount?listAccounts=800002\n"
            "https://target/go?url=javascript:alert(1)\n"
        )
        urls = _collect_urls_from_file(
            str(p), require_query=True, filter_payloads=True
        )
        assert len(urls) == 2
        assert all("<script" not in u.lower() for u in urls)
        assert all("javascript:" not in u.lower() for u in urls)

    def test_filter_off_keeps_payload_urls(self, tmp_path) -> None:
        """Opt-in flag: when False (default), behaviour is unchanged."""
        p = tmp_path / "with_params.txt"
        p.write_text(
            "https://target/search?q=<script>alert(1)</script>\n"
            "https://target/api/user?id=1\n"
        )
        urls = _collect_urls_from_file(str(p), require_query=True)
        assert len(urls) == 2


# ---------------------------------------------------------------------------
# Bug 3 — OpenAPI POST endpoint harvesting
# ---------------------------------------------------------------------------


def _write_swagger_2_0(recon_dir, body_required=True):
    """Write a Swagger-2.0 spec mirroring testfire's /swagger/properties.json."""
    os.makedirs(os.path.join(recon_dir, "api_specs"), exist_ok=True)
    spec = {
        "swagger": "2.0",
        "host": "testfire.net",
        "basePath": "/api",
        "schemes": ["https"],
        "paths": {
            "/login": {
                "post": {
                    "tags": ["1. Login"],
                    "parameters": [{
                        "in": "body",
                        "name": "body",
                        "required": body_required,
                        "schema": {"$ref": "#/definitions/login"},
                    }],
                },
                "get": {"tags": ["1. Login"]},
            },
            "/feedback/submit": {
                "post": {
                    "parameters": [{
                        "in": "body",
                        "name": "body",
                        "schema": {"$ref": "#/definitions/feedback"},
                    }],
                },
            },
            "/account": {"get": {"tags": ["2. Account"]}},
        },
        "definitions": {
            "login": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                },
            },
            "feedback": {
                "type": "object",
                "properties": {
                    "email": {"type": "string"},
                    "message": {"type": "string"},
                },
            },
        },
    }
    path = os.path.join(recon_dir, "api_specs", "spec_swagger2.json")
    with open(path, "w") as f:
        json.dump(spec, f)
    return path


def _write_openapi_3_0(recon_dir):
    os.makedirs(os.path.join(recon_dir, "api_specs"), exist_ok=True)
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.dev/v1"}],
        "paths": {
            "/widgets": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Widget"},
                            },
                        },
                    },
                },
                "patch": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"enabled": {"type": "boolean"}},
                                },
                            },
                        },
                    },
                },
            },
            "/health": {"get": {}},
        },
        "components": {
            "schemas": {
                "Widget": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "size": {"type": "integer"},
                    },
                },
            },
        },
    }
    path = os.path.join(recon_dir, "api_specs", "spec_oas3.json")
    with open(path, "w") as f:
        json.dump(spec, f)
    return path


class TestOpenAPIPostHarvest:
    def test_no_specs_dir_returns_empty(self, tmp_path) -> None:
        assert _collect_openapi_post_endpoints(str(tmp_path)) == []

    def test_swagger_2_0_login_endpoint_captured(self, tmp_path) -> None:
        _write_swagger_2_0(str(tmp_path))
        eps = _collect_openapi_post_endpoints(str(tmp_path))

        by_url = {e["url"]: e for e in eps}
        assert "https://testfire.net/api/login" in by_url
        login = by_url["https://testfire.net/api/login"]
        assert login["method"] == "POST"
        assert login["json_body"] == {"username": "test", "password": "test"}

    def test_swagger_get_only_endpoints_skipped(self, tmp_path) -> None:
        """GET /account should NOT appear — sqlmap-GET is handled elsewhere."""
        _write_swagger_2_0(str(tmp_path))
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        urls = {e["url"] for e in eps}
        assert "https://testfire.net/api/account" not in urls

    def test_openapi_3_0_post_and_patch_captured(self, tmp_path) -> None:
        _write_openapi_3_0(str(tmp_path))
        eps = _collect_openapi_post_endpoints(str(tmp_path))

        methods = {(e["url"], e["method"]) for e in eps}
        assert ("https://api.example.dev/v1/widgets", "POST") in methods
        assert ("https://api.example.dev/v1/widgets", "PATCH") in methods
        # PATCH body uses an inline schema without $ref — still generates keys.
        patch = next(e for e in eps if e["method"] == "PATCH")
        assert "enabled" in patch["json_body"]

    def test_both_specs_merge_without_duplicates(self, tmp_path) -> None:
        _write_swagger_2_0(str(tmp_path))
        _write_openapi_3_0(str(tmp_path))
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        # 2 from swagger2 (login POST, feedback POST) + 2 from oas3 (widgets POST+PATCH)
        assert len(eps) == 4

    def test_limit_respected(self, tmp_path) -> None:
        _write_swagger_2_0(str(tmp_path))
        _write_openapi_3_0(str(tmp_path))
        eps = _collect_openapi_post_endpoints(str(tmp_path), limit=2)
        assert len(eps) == 2

    def test_malformed_spec_does_not_crash_collector(self, tmp_path) -> None:
        os.makedirs(os.path.join(str(tmp_path), "api_specs"), exist_ok=True)
        bad = os.path.join(str(tmp_path), "api_specs", "bad.json")
        open(bad, "w").write("{ not valid json at all")
        _write_swagger_2_0(str(tmp_path))  # one good spec alongside
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        # The valid spec still yields endpoints; the bad one is silently skipped.
        assert len(eps) >= 2
        assert any("/login" in e["url"] for e in eps)

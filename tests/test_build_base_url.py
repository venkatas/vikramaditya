"""Regression tests for v7.1.8 — ``api_audit.build_base_url`` preserves basePath.

testfire.net serves its Swagger 2.0 spec without a ``host`` field; the
spec declares ``basePath: "/api"``. Pre-v7.1.8 ``build_base_url`` dropped
the basePath entirely in that branch and returned just ``scheme://netloc``,
producing ``sample_url`` values like ``https://testfire.net/login`` instead
of ``https://testfire.net/api/login``. sqlmap then POST'd to the wrong
endpoint and missed the boolean-blind SQLi.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api_audit import build_base_url, extract_operations


class TestBuildBaseURL:
    def test_swagger2_no_host_with_basepath_preserves_basepath(self) -> None:
        """The exact testfire.net shape — no host, basePath=/api."""
        spec = {"swagger": "2.0", "basePath": "/api"}
        out = build_base_url(spec, "https://testfire.net/swagger/properties.json")
        assert out == "https://testfire.net/api"

    def test_swagger2_no_host_no_basepath_returns_origin(self) -> None:
        spec = {"swagger": "2.0"}
        out = build_base_url(spec, "https://example.com/docs/swagger.json")
        assert out == "https://example.com"

    def test_swagger2_with_host_includes_basepath(self) -> None:
        spec = {
            "swagger": "2.0",
            "host": "api.example.com",
            "basePath": "/v2",
            "schemes": ["https"],
        }
        out = build_base_url(spec, "https://anything/x")
        assert out == "https://api.example.com/v2"

    def test_swagger2_with_host_no_basepath(self) -> None:
        spec = {"swagger": "2.0", "host": "api.example.com", "schemes": ["https"]}
        out = build_base_url(spec, "https://anything/x")
        assert out == "https://api.example.com"

    def test_openapi3_servers_url_honoured(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.dev/v1"}],
        }
        out = build_base_url(spec, "https://anything/x")
        assert out == "https://api.example.dev/v1"

    def test_basepath_without_leading_slash_still_works(self) -> None:
        """Defensive: some generators emit ``basePath: "api"`` without a slash."""
        spec = {"swagger": "2.0", "basePath": "api"}
        out = build_base_url(spec, "https://example.com/swagger.json")
        assert out == "https://example.com/api"

    def test_basepath_with_trailing_slash_is_stripped(self) -> None:
        spec = {"swagger": "2.0", "basePath": "/api/"}
        out = build_base_url(spec, "https://example.com/swagger.json")
        assert out == "https://example.com/api"


class TestExtractOperationsSampleURL:
    def test_testfire_shape_produces_api_login_url(self) -> None:
        """End-to-end: the exact testfire spec shape → /api/login in sample_url."""
        spec = {
            "swagger": "2.0",
            "basePath": "/api",
            "paths": {
                "/login": {
                    "post": {
                        "tags": ["1. Login"],
                        "parameters": [{
                            "in": "body",
                            "name": "body",
                            "schema": {"$ref": "#/definitions/login"},
                        }],
                    },
                },
            },
            "definitions": {
                "login": {"type": "object",
                           "properties": {"username": {"type": "string"}}},
            },
        }
        _meta, ops = extract_operations(spec, "https://testfire.net/swagger/properties.json")
        login_ops = [o for o in ops if o["path"] == "/login" and o["method"] == "POST"]
        assert len(login_ops) == 1
        assert login_ops[0]["sample_url"] == "https://testfire.net/api/login"

    def test_testfire_account_id_sample_url(self) -> None:
        spec = {
            "swagger": "2.0",
            "basePath": "/api",
            "paths": {
                "/account/{accountNo}/transactions": {
                    "get": {"tags": ["2. Account"]},
                    "post": {"tags": ["2. Account"]},
                },
            },
        }
        _meta, ops = extract_operations(spec, "https://testfire.net/swagger/properties.json")
        get_op = next(o for o in ops if o["method"] == "GET")
        post_op = next(o for o in ops if o["method"] == "POST")
        # Path param {accountNo} is replaced with "1" via sample_path().
        assert get_op["sample_url"] == "https://testfire.net/api/account/1/transactions"
        assert post_op["sample_url"] == "https://testfire.net/api/account/1/transactions"

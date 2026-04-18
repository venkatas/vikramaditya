"""Regression tests for v7.1.9 — body-schema expansion in OpenAPI collector.

Pre-v7.1.9 ``_collect_openapi_post_endpoints`` only saw
``parameters[in=body, name=body]`` in ``operations.json`` (the body schema
was stripped during ``extract_operations``). Result: sqlmap was handed
``{"test":"1"}`` instead of ``{"username":"test","password":"test"}``
and could never find the injectable field, even on the right URL.

v7.1.9:
1. ``api_audit.py::discover_specs`` now also returns the raw parsed specs.
2. ``api_audit.py::write_outputs`` persists each parsed spec as
   ``<saved_as>.json`` alongside ``operations.json``.
3. ``hunt.py::_collect_openapi_post_endpoints`` indexes raw specs by
   ``(path, method)`` up front and resolves body schemas through the
   ``$ref`` chain (Swagger 2.0 ``definitions`` + OpenAPI 3
   ``components.schemas``).

These tests pin the per-endpoint body shapes against the exact testfire
spec — if a future refactor re-strips the schema, the test named for
each failing endpoint will flag it.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hunt import _collect_openapi_post_endpoints


def _testfire_spec_bytes() -> dict:
    """Minimal reproduction of the real testfire Swagger 2.0 spec."""
    return {
        "swagger": "2.0",
        "basePath": "/api",
        "paths": {
            "/login": {
                "post": {
                    "parameters": [{
                        "in": "body",
                        "name": "body",
                        "schema": {"$ref": "#/definitions/login"},
                    }],
                },
            },
            "/transfer": {
                "post": {
                    "parameters": [{
                        "in": "body",
                        "name": "body",
                        "schema": {"$ref": "#/definitions/transfer"},
                    }],
                },
            },
            "/admin/addUser": {
                "post": {
                    "parameters": [{
                        "in": "body",
                        "name": "body",
                        "schema": {"$ref": "#/definitions/newUser"},
                    }],
                },
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
        },
        "definitions": {
            "login": {"type": "object",
                      "properties": {"username": {"type": "string"},
                                     "password": {"type": "string"}}},
            "transfer": {"type": "object",
                         "properties": {"toAccount": {"type": "string"},
                                         "fromAccount": {"type": "string"},
                                         "transferAmount": {"type": "number"}}},
            "newUser": {"type": "object",
                        "properties": {"username": {"type": "string"},
                                        "password1": {"type": "string"},
                                        "password2": {"type": "string"}}},
            "feedback": {"type": "object",
                         "properties": {"name": {"type": "string"},
                                         "email": {"type": "string"},
                                         "message": {"type": "string"}}},
        },
    }


@pytest.fixture
def testfire_recon(tmp_path):
    specs = tmp_path / "api_specs"
    specs.mkdir()
    # operations.json (pre-parsed by api_audit.py) — what Phase 6.5 writes
    ops = [
        {"method": "POST", "path": "/login",
         "sample_url": "https://testfire.net/api/login"},
        {"method": "POST", "path": "/transfer",
         "sample_url": "https://testfire.net/api/transfer"},
        {"method": "POST", "path": "/admin/addUser",
         "sample_url": "https://testfire.net/api/admin/addUser"},
        {"method": "POST", "path": "/feedback/submit",
         "sample_url": "https://testfire.net/api/feedback/submit"},
        # Non-target controls
        {"method": "GET", "path": "/account",
         "sample_url": "https://testfire.net/api/account"},
    ]
    (specs / "operations.json").write_text(json.dumps(ops))
    (specs / "discovered_specs.json").write_text(
        json.dumps([{"saved_as": "testfire_abc"}]))
    (specs / "unauth_findings.json").write_text("[]")
    # v7.1.9 — raw spec file saved alongside
    (specs / "testfire_abc.json").write_text(json.dumps(_testfire_spec_bytes()))
    return str(tmp_path)


class TestBodyExpansion:
    def test_login_body_has_username_and_password(self, testfire_recon) -> None:
        """Regression pin: the exact field names sqlmap needs."""
        eps = _collect_openapi_post_endpoints(testfire_recon)
        login = next(e for e in eps if e["url"].endswith("/api/login"))
        assert set(login["json_body"].keys()) == {"username", "password"}

    def test_transfer_body_extracted(self, testfire_recon) -> None:
        eps = _collect_openapi_post_endpoints(testfire_recon)
        transfer = next(e for e in eps if e["url"].endswith("/api/transfer"))
        assert set(transfer["json_body"].keys()) == {
            "toAccount", "fromAccount", "transferAmount",
        }

    def test_nested_path_addUser(self, testfire_recon) -> None:
        """Nested paths (/admin/addUser) must resolve correctly."""
        eps = _collect_openapi_post_endpoints(testfire_recon)
        add_user = next(e for e in eps if e["url"].endswith("/api/admin/addUser"))
        assert set(add_user["json_body"].keys()) == {
            "username", "password1", "password2",
        }

    def test_get_operation_still_filtered(self, testfire_recon) -> None:
        """GET /account must not appear in POST-candidate list."""
        eps = _collect_openapi_post_endpoints(testfire_recon)
        urls = [e["url"] for e in eps]
        assert "https://testfire.net/api/account" not in urls

    def test_missing_raw_spec_falls_back_to_stub(self, tmp_path) -> None:
        """If raw spec file absent, stub body is used (pre-v7.1.9 behaviour)."""
        specs = tmp_path / "api_specs"
        specs.mkdir()
        (specs / "operations.json").write_text(json.dumps([
            {"method": "POST", "path": "/login",
             "sample_url": "https://x/api/login"},
        ]))
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert eps[0]["json_body"] == {"test": "1"}

    def test_openapi3_requestBody_resolved(self, tmp_path) -> None:
        specs = tmp_path / "api_specs"
        specs.mkdir()
        (specs / "operations.json").write_text(json.dumps([
            {"method": "POST", "path": "/widgets",
             "sample_url": "https://api.example.dev/v1/widgets"},
        ]))
        (specs / "spec_abc.json").write_text(json.dumps({
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
                },
            },
            "components": {
                "schemas": {
                    "Widget": {"type": "object",
                                "properties": {"name": {"type": "string"},
                                                "size": {"type": "integer"}}},
                },
            },
        }))
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert eps[0]["json_body"] == {"name": "test", "size": "test"}

    def test_formData_params_also_resolved(self, tmp_path) -> None:
        specs = tmp_path / "api_specs"
        specs.mkdir()
        (specs / "operations.json").write_text(json.dumps([
            {"method": "POST", "path": "/upload",
             "sample_url": "https://x/upload"},
        ]))
        (specs / "spec.json").write_text(json.dumps({
            "swagger": "2.0",
            "paths": {
                "/upload": {
                    "post": {
                        "parameters": [
                            {"in": "formData", "name": "file"},
                            {"in": "formData", "name": "signature"},
                        ],
                    },
                },
            },
        }))
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert set(eps[0]["json_body"].keys()) == {"file", "signature"}


class TestConfirmNonTTYFix:
    """v7.1.9 bug 9 — confirm() returns default instead of EOFError on non-TTY."""

    def test_confirm_returns_default_yes_on_eof(self, monkeypatch) -> None:
        import builtins
        import vikramaditya
        def raise_eof(*_a, **_kw):
            raise EOFError
        monkeypatch.setattr(builtins, "input", raise_eof)
        assert vikramaditya.confirm("proceed?", default_yes=True) is True
        assert vikramaditya.confirm("proceed?", default_yes=False) is False

    def test_prompt_returns_default_on_eof(self, monkeypatch) -> None:
        import builtins
        import vikramaditya
        def raise_eof(*_a, **_kw):
            raise EOFError
        monkeypatch.setattr(builtins, "input", raise_eof)
        assert vikramaditya.prompt("name?", default="default-name") == "default-name"
        assert vikramaditya.prompt("name?") == ""

"""Regression tests for v7.1.7 — ``_collect_openapi_post_endpoints`` hardening.

The v7.1.6 implementation called ``spec.get("host")`` on every ``*.json`` in
``api_specs/``. api_audit.py writes three non-spec JSON files there
(``discovered_specs.json``, ``operations.json``, ``unauth_findings.json``),
all of which are ``list`` objects — so the call crashed with
``AttributeError: 'list' object has no attribute 'get'`` and aborted the
whole SQLMAP phase on every live run. v7.1.7:

1. **Primary parse path** uses ``operations.json`` (list of pre-parsed op
   dicts produced by api_audit.py).
2. **Fallback path** walks raw spec files but skips the non-spec JSON
   artefacts and anything that isn't an OpenAPI-shaped dict.
3. All ``.get()`` calls are guarded against non-dict payloads.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hunt import _collect_openapi_post_endpoints


def _write(recon_dir, name, payload):
    specs = os.path.join(str(recon_dir), "api_specs")
    os.makedirs(specs, exist_ok=True)
    with open(os.path.join(specs, name), "w") as f:
        json.dump(payload, f)


class TestCrashRegressions:
    def test_discovered_specs_list_does_not_crash(self, tmp_path) -> None:
        """The exact shape that triggered the v7.1.6 AttributeError."""
        _write(tmp_path, "discovered_specs.json", [
            {"url": "https://x/swagger.json", "format": "openapi"},
        ])
        # No operations.json → falls to path-2. Must not raise.
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert eps == []

    def test_unauth_findings_list_is_skipped(self, tmp_path) -> None:
        _write(tmp_path, "unauth_findings.json", [{"url": "x"}])
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert eps == []

    def test_malformed_json_skipped_not_raised(self, tmp_path) -> None:
        bad = os.path.join(str(tmp_path), "api_specs", "bad.json")
        os.makedirs(os.path.dirname(bad), exist_ok=True)
        open(bad, "w").write("{ this is not valid json")
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert eps == []

    def test_non_dict_payload_at_top_level_skipped(self, tmp_path) -> None:
        """A JSON file that decodes to ``[1, 2, 3]`` or ``"string"`` etc."""
        _write(tmp_path, "weird.json", [1, 2, 3])
        _write(tmp_path, "also_weird.json", "hello")
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert eps == []


class TestOperationsJsonPath:
    def test_reads_operations_json_first(self, tmp_path) -> None:
        """Primary parse path — matches exactly what api_audit.py writes."""
        _write(tmp_path, "operations.json", [
            {
                "method": "POST",
                "path": "/login",
                "sample_url": "https://testfire.net/login",
                "requires_auth": False,
                "parameters": [
                    {"in": "body", "name": "username"},
                    {"in": "body", "name": "password"},
                ],
            },
            {
                "method": "GET",
                "path": "/account",
                "sample_url": "https://testfire.net/account",
                "requires_auth": True,
            },
        ])
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert len(eps) == 1
        assert eps[0]["method"] == "POST"
        assert eps[0]["url"] == "https://testfire.net/login"
        # Body keys come from parameters[in=body]
        assert set(eps[0]["json_body"].keys()) == {"username", "password"}

    def test_post_with_no_body_params_gets_stub(self, tmp_path) -> None:
        _write(tmp_path, "operations.json", [
            {
                "method": "POST",
                "path": "/ping",
                "sample_url": "https://x/ping",
                "parameters": [],
            },
        ])
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert eps[0]["json_body"] == {"test": "1"}

    def test_duplicate_operation_deduped(self, tmp_path) -> None:
        _write(tmp_path, "operations.json", [
            {"method": "POST", "path": "/x", "sample_url": "https://x/a"},
            {"method": "POST", "path": "/x", "sample_url": "https://x/a"},
        ])
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert len(eps) == 1

    def test_limit_respected_in_ops_json(self, tmp_path) -> None:
        _write(tmp_path, "operations.json", [
            {"method": "POST", "path": f"/op{i}", "sample_url": f"https://x/op{i}"}
            for i in range(10)
        ])
        eps = _collect_openapi_post_endpoints(str(tmp_path), limit=3)
        assert len(eps) == 3

    def test_post_form_data_also_captured(self, tmp_path) -> None:
        """formData parameters (Swagger 2.0 multipart/urlencoded) count too."""
        _write(tmp_path, "operations.json", [
            {
                "method": "POST",
                "path": "/upload",
                "sample_url": "https://x/upload",
                "parameters": [
                    {"in": "formData", "name": "file"},
                    {"in": "formData", "name": "token"},
                ],
            },
        ])
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert set(eps[0]["json_body"].keys()) == {"file", "token"}

    def test_invalid_url_in_op_is_skipped(self, tmp_path) -> None:
        _write(tmp_path, "operations.json", [
            {"method": "POST", "path": "/x", "sample_url": "//no-scheme"},
            {"method": "POST", "path": "/y", "sample_url": "https://x/y"},
        ])
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert len(eps) == 1
        assert eps[0]["url"] == "https://x/y"


class TestRawSpecFallback:
    def test_falls_back_to_raw_spec_when_ops_missing(self, tmp_path) -> None:
        """If no operations.json, walk raw spec files in the dir."""
        _write(tmp_path, "host_abc12345.json", {
            "swagger": "2.0",
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/users": {
                    "post": {
                        "parameters": [{"in": "body", "name": "body",
                                        "schema": {"$ref": "#/definitions/User"}}],
                    },
                },
            },
            "definitions": {
                "User": {"type": "object",
                          "properties": {"email": {"type": "string"}}},
            },
        })
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert len(eps) == 1
        assert eps[0]["url"] == "https://api.example.com/v1/users"
        assert eps[0]["json_body"] == {"email": "test"}

    def test_non_spec_json_siblings_do_not_crash_fallback(self, tmp_path) -> None:
        _write(tmp_path, "discovered_specs.json", [{"url": "x"}])
        _write(tmp_path, "host_deadbeef.json", {
            "swagger": "2.0",
            "host": "y.com",
            "paths": {"/z": {"post": {}}},
        })
        eps = _collect_openapi_post_endpoints(str(tmp_path))
        assert any(e["url"].startswith("https://y.com") for e in eps)

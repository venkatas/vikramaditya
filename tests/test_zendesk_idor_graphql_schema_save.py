#!/usr/bin/env python3
"""
Regression test for zendesk_idor.test_graphql() schema-save path.

Bug: open("recon/zendesk/graphql_schema.json","w") lived inside the JSON-parse
try/except. When recon/zendesk/ did not exist, FileNotFoundError was swallowed
and mislabeled as 'Status 200 but not JSON', silently discarding a CONFIRMED
open-introspection finding.

Fix: makedirs() the parent first and move the file write out of the JSON guard.

All data here is SYNTHETIC.
"""
import os
import sys
import json
import importlib

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


@pytest.fixture
def zendesk_mod(monkeypatch):
    # Synthetic env so the module-level guard does not sys.exit on import.
    monkeypatch.setenv("ZENDESK_SUBDOMAIN", "acme")
    monkeypatch.setenv("ZENDESK_EMAIL", "agent@example.invalid")
    monkeypatch.setenv("ZENDESK_API_TOKEN", "placeholder-token")
    mod = importlib.import_module("zendesk_idor")
    return importlib.reload(mod)


class _FakeResp:
    status_code = 200
    text = ""

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def test_introspection_schema_saved_when_recon_dir_absent(tmp_path, monkeypatch, zendesk_mod):
    """An open-introspection result must persist the schema even if recon/zendesk/ is missing."""
    introspection_payload = {
        "data": {"__schema": {"types": [{"name": "Query", "description": "root"}]}}
    }

    def fake_post(url, *args, **kwargs):
        # Only the first probed path returns a schema; others 404.
        if url.endswith("/graphql"):
            return _FakeResp(introspection_payload)
        r = _FakeResp({})
        r.status_code = 404
        return r

    monkeypatch.setattr(zendesk_mod.requests, "post", fake_post)

    # Run from a clean temp cwd with NO recon/zendesk/ pre-created.
    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / "recon" / "zendesk").exists()

    zendesk_mod.test_graphql()

    saved = tmp_path / "recon" / "zendesk" / "graphql_schema.json"
    assert saved.exists(), "schema file must be created when introspection is enabled"
    on_disk = json.loads(saved.read_text())
    assert on_disk == introspection_payload

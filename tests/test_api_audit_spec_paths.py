"""Regression test for v7.1.6 — api_audit.py spec-path probe list.

testfire.net publishes its Swagger spec at ``/swagger/properties.json``.
Before v7.1.6, ``SPEC_PATHS`` had ``/swagger-ui/index.html`` (hyphenated)
but no ``/swagger/index.html`` (slash) and no ``/swagger/properties.json``
at all — so api_audit.py reported ``OpenAPI specs: 0`` for a target that
literally exposes its spec via a public, known path.

This test pins the three paths that must exist in the probe list.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api_audit import SPEC_PATHS


class TestSpecPaths:
    def test_swagger_properties_json_in_list(self) -> None:
        """The exact path testfire.net serves the spec at."""
        assert "/swagger/properties.json" in SPEC_PATHS

    def test_swagger_slash_index_html_in_list(self) -> None:
        """Slash-separated Swagger UI bootstrap (vs. hyphenated)."""
        assert "/swagger/index.html" in SPEC_PATHS

    def test_hyphenated_swagger_ui_still_present(self) -> None:
        """Backward-compat: the older hyphenated variant must stay."""
        assert "/swagger-ui/index.html" in SPEC_PATHS
        assert "/swagger-ui.html" in SPEC_PATHS

    def test_fastapi_docs_path_in_list(self) -> None:
        """FastAPI defaults to /docs for Swagger UI bootstrap."""
        assert "/docs" in SPEC_PATHS

    def test_legacy_paths_preserved(self) -> None:
        """All of v7.1.5's existing paths must survive the expansion."""
        for expected in (
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/swagger/v1/swagger.json",
            "/swagger/v2/swagger.json",
            "/redoc",
        ):
            assert expected in SPEC_PATHS, f"legacy path dropped: {expected}"

    def test_list_has_no_duplicates(self) -> None:
        assert len(SPEC_PATHS) == len(set(SPEC_PATHS))

    def test_all_paths_are_absolute(self) -> None:
        """Every entry must start with ``/`` — relative paths would break urljoin."""
        assert all(p.startswith("/") for p in SPEC_PATHS)

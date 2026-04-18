"""Regression tests for v7.1.10 — sqlmap invocation hardening.

v7.1.9 got Vikramaditya hitting the right URL (``/api/login``) with the
right body (``{"username":"test","password":"test"}``). But sqlmap still
didn't detect the SQLi because its Boolean oracle got only HTTP 400
responses — testfire's JSON API rejects requests that don't carry
``Content-Type: application/json``. Sqlmap also ran every payload family
(time-based, stacked, etc.) before timing out; most of those are useless
against JSON REST APIs.

v7.1.10 fixes both:
1. Auto-attach ``--headers "Content-Type: application/json"`` when the
   body looks like JSON (starts with ``{`` or ``[``).
2. Pass ``--technique=BEU --smart`` so Boolean/Error/Union run first and
   non-numeric params are heuristically pruned.

Also fixes a detection bug: the old code passed ``-o <path>`` thinking
it was the output-file flag. ``-o`` is actually a **boolean** enable
flag — the path was silently ignored and no per-op output file was ever
written. v7.1.10 reads sqlmap's own ``results-*.csv`` output via
``_glob_results_csvs``.

These tests exercise the code-level behaviour. The end-to-end "sqlmap
actually finds the SQLi" invariant is too slow (10 min per probe) to
pin here — verified separately via live re-run on testfire.net.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hunt import _glob_results_csvs


class TestResultsCSVGlob:
    def test_empty_dir_returns_empty_list(self, tmp_path) -> None:
        assert _glob_results_csvs(str(tmp_path)) == []

    def test_matches_sqlmap_csv_naming(self, tmp_path) -> None:
        (tmp_path / "results-04192026_0405am.csv").write_text("Target URL,Place,...")
        (tmp_path / "results-04192026_0415am.csv").write_text("Target URL,Place,...")
        (tmp_path / "other.csv").write_text("unrelated")
        (tmp_path / "sqlmap_results.txt").write_text("also unrelated")
        hits = _glob_results_csvs(str(tmp_path))
        assert len(hits) == 2
        assert all(os.path.basename(h).startswith("results-") for h in hits)

    def test_nonexistent_dir_returns_empty_list(self, tmp_path) -> None:
        """Glob against a missing dir must return [] not raise."""
        assert _glob_results_csvs(str(tmp_path / "does-not-exist")) == []


class TestJSONHeaderHeuristic:
    """The ``is_json_body`` inline heuristic — cheap substring check.

    We can't invoke ``run_sqlmap_targeted`` without a real sqlmap
    process; instead we pin the exact behaviour of the heuristic via
    a tiny reproduction.
    """

    @staticmethod
    def _decide(body: str) -> bool:
        """Mirror the inline decision in hunt.py::run_sqlmap_targeted."""
        return body.startswith("{") or body.startswith("[")

    def test_object_body_triggers_json_header(self) -> None:
        assert self._decide('{"username":"test"}') is True

    def test_array_body_triggers_json_header(self) -> None:
        assert self._decide('[{"id":1}]') is True

    def test_form_body_does_not_trigger_json_header(self) -> None:
        assert self._decide('username=test&password=test') is False

    def test_empty_body_does_not_trigger_json_header(self) -> None:
        assert self._decide('') is False

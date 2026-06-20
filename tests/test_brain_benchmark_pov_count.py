#!/usr/bin/env python3
"""Regression tests for brain_benchmark._run_buttercup PoV counting.

Covers the operator-precedence bug where
    len(data.get("povs", []) or data if isinstance(data, list) else [])
always parsed Buttercup's findings.json as 0 PoVs for both the documented
dict shape ({"povs": [...]}) and the bare-list shape ([...]).

All data here is SYNTHETIC.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import brain_benchmark  # noqa: E402


def _make_buttercup_dir(tmp_path: Path, findings_obj) -> Path:
    """Lay out run_dir/buttercup/findings.json with the given JSON object."""
    run_dir = tmp_path / "run"
    (run_dir / "buttercup").mkdir(parents=True)
    (run_dir / "buttercup" / "findings.json").write_text(json.dumps(findings_obj))
    return run_dir


def _stub_which(monkeypatch):
    monkeypatch.setattr(brain_benchmark, "_which", lambda name: "/usr/bin/true")


def _stub_run_returncode_0(monkeypatch):
    class _R:
        returncode = 0

    monkeypatch.setattr(brain_benchmark.subprocess, "run", lambda *a, **k: _R())


def test_dict_shape_counts_povs(tmp_path, monkeypatch):
    """Documented {"povs": [...]} schema must count all entries, not 0."""
    _stub_which(monkeypatch)
    _stub_run_returncode_0(monkeypatch)
    run_dir = _make_buttercup_dir(tmp_path, {"povs": [1, 2, 3]})

    result = brain_benchmark._run_buttercup("https://example.invalid", None, run_dir)

    assert result["pov_count"] == 3
    assert "_parse_error" not in result


def test_bare_list_shape_counts_povs(tmp_path, monkeypatch):
    """Bare-list [...] schema must count all entries without AttributeError."""
    _stub_which(monkeypatch)
    _stub_run_returncode_0(monkeypatch)
    run_dir = _make_buttercup_dir(tmp_path, [{"id": "a"}, {"id": "b"}])

    result = brain_benchmark._run_buttercup("https://example.invalid", None, run_dir)

    assert result["pov_count"] == 2
    assert "_parse_error" not in result


def test_empty_dict_povs(tmp_path, monkeypatch):
    """Empty PoV list reports 0 cleanly (no error)."""
    _stub_which(monkeypatch)
    _stub_run_returncode_0(monkeypatch)
    run_dir = _make_buttercup_dir(tmp_path, {"povs": []})

    result = brain_benchmark._run_buttercup("https://example.invalid", None, run_dir)

    assert result["pov_count"] == 0
    assert "_parse_error" not in result


def test_malformed_json_surfaces_error(tmp_path, monkeypatch):
    """A malformed findings.json must be visible, not masquerade as 0 PoVs."""
    _stub_which(monkeypatch)
    _stub_run_returncode_0(monkeypatch)
    run_dir = tmp_path / "run"
    (run_dir / "buttercup").mkdir(parents=True)
    (run_dir / "buttercup" / "findings.json").write_text("{not valid json")

    result = brain_benchmark._run_buttercup("https://example.invalid", None, run_dir)

    assert result["pov_count"] == 0
    assert "_parse_error" in result


def test_unexpected_type_surfaces_error(tmp_path, monkeypatch):
    """A non-list/non-dict top-level value records a parse error."""
    _stub_which(monkeypatch)
    _stub_run_returncode_0(monkeypatch)
    run_dir = _make_buttercup_dir(tmp_path, "just a string")

    result = brain_benchmark._run_buttercup("https://example.invalid", None, run_dir)

    assert result["pov_count"] == 0
    assert "_parse_error" in result


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

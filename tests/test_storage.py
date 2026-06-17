#!/usr/bin/env python3
"""
tests/test_storage.py — TDD coverage for storage.py atomic write primitives.

Proves the temp+fsync+rename contract holds under failure:
  1. content round-trips for json / text / bytes
  2. an interrupted overwrite leaves the ORIGINAL file intact and leaves
     no stray "<dst>.tmp.*" sibling on disk (no partial/corrupt write)
  3. the destination file ends up mode 0o600
  4. a missing parent directory is created automatically

All paths are synthetic (tmp_path) and all sample data uses example.com.
"""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

# Vikramaditya flat layout — modules live at repo root, not tools/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import storage


# --------------------------------------------------------------------------- #
# 1. content round-trips
# --------------------------------------------------------------------------- #
def test_atomic_write_json_round_trips(tmp_path):
    dst = tmp_path / "state.json"
    data = {"target": "example.com", "findings": [1, 2, 3], "nested": {"a": True}}

    storage.atomic_write_json(str(dst), data)

    with open(dst) as fh:
        assert json.load(fh) == data


def test_atomic_write_json_is_pretty_printed(tmp_path):
    dst = tmp_path / "pretty.json"
    storage.atomic_write_json(str(dst), {"k": "v"})

    text = dst.read_text()
    # indent=2 produces a newline + two-space indent before the key.
    assert '\n  "k": "v"' in text


def test_atomic_write_text_round_trips(tmp_path):
    dst = tmp_path / "note.txt"
    payload = "scan of example.com\nline two\n"

    storage.atomic_write_text(str(dst), payload)

    assert dst.read_text() == payload


def test_atomic_write_bytes_round_trips(tmp_path):
    dst = tmp_path / "blob.bin"
    payload = b"\x00\x01\x02example.com\xff"

    storage.atomic_write_bytes(str(dst), payload)

    assert dst.read_bytes() == payload


# --------------------------------------------------------------------------- #
# 2. interrupted overwrite — original intact, no temp litter
# --------------------------------------------------------------------------- #
def _temp_siblings(dst):
    """Return any leftover '<dst>.tmp.*' files next to dst."""
    parent = dst.parent
    base = dst.name
    return [
        p.name
        for p in parent.iterdir()
        if p.name != base and p.name.startswith(base + ".tmp.")
    ]


def test_failed_json_write_preserves_original(tmp_path, monkeypatch):
    dst = tmp_path / "state.json"
    original = {"target": "example.com", "v": 1}
    storage.atomic_write_json(str(dst), original)

    # Blow up mid-serialise (before anything reaches disk).
    def boom(*_a, **_k):
        raise RuntimeError("simulated json serialise failure")

    monkeypatch.setattr(storage.json, "dumps", boom)

    with pytest.raises(RuntimeError):
        storage.atomic_write_json(str(dst), {"target": "example.com", "v": 2})

    # Original content is untouched.
    with open(dst) as fh:
        assert json.load(fh) == original
    # No stray temp file left behind.
    assert _temp_siblings(dst) == []


def test_failed_rename_preserves_original_and_cleans_temp(tmp_path, monkeypatch):
    dst = tmp_path / "state.json"
    original = {"target": "example.com", "v": 1}
    storage.atomic_write_json(str(dst), original)

    def boom(*_a, **_k):
        raise OSError("simulated os.replace failure")

    monkeypatch.setattr(storage.os, "replace", boom)

    with pytest.raises(OSError):
        storage.atomic_write_json(str(dst), {"target": "example.com", "v": 2})

    with open(dst) as fh:
        assert json.load(fh) == original
    assert _temp_siblings(dst) == []


def test_failed_text_write_leaves_no_temp_litter(tmp_path, monkeypatch):
    dst = tmp_path / "note.txt"
    storage.atomic_write_text(str(dst), "original example.com content")

    real_replace = storage.os.replace

    def boom(*_a, **_k):
        raise OSError("simulated os.replace failure")

    monkeypatch.setattr(storage.os, "replace", boom)

    with pytest.raises(OSError):
        storage.atomic_write_text(str(dst), "new content that must not land")

    monkeypatch.setattr(storage.os, "replace", real_replace)
    assert dst.read_text() == "original example.com content"
    assert _temp_siblings(dst) == []


# --------------------------------------------------------------------------- #
# 3. file mode is 0o600
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "writer, payload",
    [
        (storage.atomic_write_json, {"target": "example.com"}),
        (storage.atomic_write_text, "example.com"),
        (storage.atomic_write_bytes, b"example.com"),
    ],
)
def test_default_mode_is_0o600(tmp_path, writer, payload):
    dst = tmp_path / "secret.dat"
    writer(str(dst), payload)

    perm = stat.S_IMODE(os.stat(dst).st_mode)
    assert perm == 0o600


def test_custom_mode_is_honoured(tmp_path):
    dst = tmp_path / "world_readable.json"
    storage.atomic_write_json(str(dst), {"target": "example.com"}, mode=0o644)

    perm = stat.S_IMODE(os.stat(dst).st_mode)
    assert perm == 0o644


# --------------------------------------------------------------------------- #
# 4. parent directory is created if missing
# --------------------------------------------------------------------------- #
def test_parent_dir_created_for_json(tmp_path):
    dst = tmp_path / "a" / "b" / "c" / "state.json"
    assert not dst.parent.exists()

    storage.atomic_write_json(str(dst), {"target": "example.com"})

    assert dst.exists()
    with open(dst) as fh:
        assert json.load(fh) == {"target": "example.com"}


def test_parent_dir_created_for_text_and_bytes(tmp_path):
    tdst = tmp_path / "deep" / "note.txt"
    bdst = tmp_path / "deeper" / "still" / "blob.bin"

    storage.atomic_write_text(str(tdst), "example.com")
    storage.atomic_write_bytes(str(bdst), b"example.com")

    assert tdst.read_text() == "example.com"
    assert bdst.read_bytes() == b"example.com"


# --------------------------------------------------------------------------- #
# bonus: overwrite leaves only the final content (durability of the swap)
# --------------------------------------------------------------------------- #
def test_overwrite_replaces_content_atomically(tmp_path):
    dst = tmp_path / "state.json"
    storage.atomic_write_json(str(dst), {"target": "example.com", "v": 1})
    storage.atomic_write_json(str(dst), {"target": "example.com", "v": 2})

    with open(dst) as fh:
        assert json.load(fh) == {"target": "example.com", "v": 2}
    assert _temp_siblings(dst) == []

#!/usr/bin/env python3
"""
tests/test_agent_state_atomic.py — regression coverage for HuntMemory's
crash-safe session persistence (agent.py).

Background: HuntMemory.save() used a naive non-atomic write_text(), so a
crash / ^C / full disk / revoked macOS TCC lock partway through could truncate
agent_session.json and leave a corrupt half-written file. _load() then swallowed
the JSONDecodeError silently and reset all resume state to defaults.

These tests prove:
  1. save() round-trips through an atomic write (state survives reload)
  2. save() routes through storage.atomic_write_json (no partial file possible)
  3. a pre-existing corrupt session file is NOT silently reset to defaults —
     it is preserved as a *.corrupt.* sibling and a warning is emitted.

All data is synthetic (tmp_path, example.invalid).
"""

from __future__ import annotations

import glob
import json
import os
import sys
from unittest import mock

import pytest

# Vikramaditya flat layout — modules live at repo root, not tools/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import agent
import storage


def test_save_roundtrips_state(tmp_path):
    sf = tmp_path / "sub" / "agent_session.json"
    mem = agent.HuntMemory(str(sf))
    mem.working_memory = "notes for example.invalid"
    mem.add_finding("scanner", "high", "synthetic finding")
    mem.completed_steps = ["recon", "scan"]
    mem.step_count = 7
    mem.save()

    # File exists and is valid JSON.
    assert sf.is_file()
    data = json.loads(sf.read_text())
    assert data["working_memory"] == "notes for example.invalid"
    assert data["step_count"] == 7

    # A fresh HuntMemory pointed at the same file recovers everything.
    mem2 = agent.HuntMemory(str(sf))
    assert mem2.working_memory == "notes for example.invalid"
    assert mem2.step_count == 7
    assert mem2.completed_steps == ["recon", "scan"]
    assert len(mem2.findings_log) == 1


def test_save_uses_atomic_primitive(tmp_path):
    sf = tmp_path / "agent_session.json"
    mem = agent.HuntMemory(str(sf))
    mem.step_count = 3
    with mock.patch.object(storage, "atomic_write_json",
                           wraps=storage.atomic_write_json) as spy:
        mem.save()
    spy.assert_called_once()
    # First positional arg is the destination path.
    assert spy.call_args[0][0] == str(sf)


def test_corrupt_session_is_preserved_not_silently_reset(tmp_path, capsys):
    sf = tmp_path / "agent_session.json"
    # Simulate a half-written / truncated file from an interrupted save.
    sf.write_text('{"working_memory": "partial wri')

    mem = agent.HuntMemory(str(sf))

    # State falls back to defaults (can't parse), but NOT silently:
    assert mem.step_count == 0
    assert mem.working_memory == ""

    # The corrupt file is preserved for forensics, not just clobbered.
    corrupt = glob.glob(str(sf) + ".corrupt.*")
    assert corrupt, "corrupt session file should be preserved as *.corrupt.*"

    # And a warning was surfaced (to stderr), not swallowed.
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "session file" in err


def test_no_partial_file_when_encoding_fails(tmp_path):
    """If serialisation fails, the previous good file must stay intact and no
    temp sibling must be left behind (delegated to storage.atomic_write_json)."""
    sf = tmp_path / "agent_session.json"
    mem = agent.HuntMemory(str(sf))
    mem.step_count = 1
    mem.save()
    good = sf.read_text()

    # Inject an unserialisable object into the in-memory state.
    mem.working_memory = object()  # type: ignore[assignment]
    mem.step_count = 99
    with pytest.raises(TypeError):
        mem.save()

    # Original file untouched; no stray temp siblings.
    assert sf.read_text() == good
    assert not glob.glob(str(sf) + ".tmp.*")

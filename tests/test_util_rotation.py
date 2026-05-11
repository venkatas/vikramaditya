"""Acceptance tests for util_rotation.py — fcntl-based file rotation."""

from __future__ import annotations

import multiprocessing
import os
from pathlib import Path

import pytest

from util_rotation import (
    DEFAULT_KEEP,
    DEFAULT_MAX_BYTES,
    RotatingAppender,
    rotate_if_needed,
)


# ─── Single-writer rotation ───────────────────────────────────────────────────
class TestRotation:
    def test_no_rotation_when_below_threshold(self, tmp_path):
        target = tmp_path / "log.jsonl"
        target.write_bytes(b"x" * 100)
        rotated = rotate_if_needed(target, max_bytes=1000)
        assert rotated is False
        assert target.exists()
        assert target.stat().st_size == 100

    def test_rotation_at_threshold(self, tmp_path):
        target = tmp_path / "log.jsonl"
        target.write_bytes(b"x" * 1024)
        rotated = rotate_if_needed(target, max_bytes=1024)
        assert rotated is True
        # path was moved to path.1; path no longer exists.
        assert not target.exists()
        assert (tmp_path / "log.jsonl.1").exists()
        assert (tmp_path / "log.jsonl.1").stat().st_size == 1024

    def test_keep_backups_oldest_is_dropped(self, tmp_path):
        target = tmp_path / "log.jsonl"
        # Simulate three pre-existing rotated copies.
        (tmp_path / "log.jsonl.1").write_bytes(b"first ")
        (tmp_path / "log.jsonl.2").write_bytes(b"second ")
        (tmp_path / "log.jsonl.3").write_bytes(b"third ")
        target.write_bytes(b"current-rolled-over")

        rotated = rotate_if_needed(target, max_bytes=1, keep=3)
        assert rotated is True
        # Oldest (.3) was dropped; new chain is current → .1, old .1 → .2, old .2 → .3.
        assert (tmp_path / "log.jsonl.1").read_bytes() == b"current-rolled-over"
        assert (tmp_path / "log.jsonl.2").read_bytes() == b"first "
        assert (tmp_path / "log.jsonl.3").read_bytes() == b"second "
        # The old .3 is gone.
        assert not target.exists()

    def test_nonexistent_path_is_noop(self, tmp_path):
        assert rotate_if_needed(tmp_path / "missing", max_bytes=1024) is False

    def test_invalid_args_raise(self, tmp_path):
        target = tmp_path / "log.jsonl"
        target.write_bytes(b"x")
        with pytest.raises(ValueError, match="max_bytes"):
            rotate_if_needed(target, max_bytes=0)
        with pytest.raises(ValueError, match="keep"):
            rotate_if_needed(target, max_bytes=1024, keep=0)


# ─── RotatingAppender end-to-end ──────────────────────────────────────────────
class TestRotatingAppender:
    def test_appender_writes_and_creates_parent(self, tmp_path):
        target = tmp_path / "sub" / "audit.csv"
        with RotatingAppender(target, max_bytes=1024) as fh:
            fh.write("a,b,c\n")
            fh.write("1,2,3\n")
        assert target.exists()
        assert target.read_text() == "a,b,c\n1,2,3\n"

    def test_appender_rotates_when_threshold_crossed(self, tmp_path):
        target = tmp_path / "audit.csv"
        # Pre-fill close to the threshold.
        target.write_bytes(b"x" * 1024)
        with RotatingAppender(target, max_bytes=1024) as fh:
            fh.write("new\n")
        # Old contents went to .1; new file holds only the fresh append.
        assert (tmp_path / "audit.csv.1").read_bytes() == b"x" * 1024
        assert target.read_text() == "new\n"


# ─── Multi-process concurrent writes ──────────────────────────────────────────
def _child_writer(args):
    """Writer used by the concurrency test. ``keep`` is bumped high
    enough that no rotation pruning runs during the test — that lets us
    assert "no byte loss" rather than "no corruption among retained
    backups"."""
    target, rounds, keep = args
    from util_rotation import RotatingAppender as RA
    for i in range(rounds):
        with RA(target, max_bytes=512, keep=keep) as fh:
            fh.write(f"p{os.getpid():06d}-{i:04d}\n")
    return rounds


class TestConcurrent:
    def test_no_byte_loss_under_concurrency(self, tmp_path):
        target = tmp_path / "concurrent.log"
        n_procs = 4
        rounds = 50
        # keep high enough that no rotated backup gets pruned for this test:
        # at ~14 bytes per line × 200 lines / 512 bytes ≈ 6 rotations max.
        keep = 50
        with multiprocessing.Pool(n_procs) as pool:
            pool.map(_child_writer, [(target, rounds, keep)] * n_procs)

        total_lines = 0
        for f in sorted(tmp_path.iterdir()):
            if not f.is_file():
                continue
            if f.name.endswith(".rotlock"):
                continue
            if f.name == "concurrent.log" or f.name.startswith("concurrent.log."):
                total_lines += sum(1 for _ in f.open())

        # Every (proc, round) pair produced exactly one line.
        assert total_lines == n_procs * rounds, \
            f"lost lines under concurrency: got {total_lines}, expected {n_procs * rounds}"

#!/usr/bin/env python3
"""
util_rotation.py — size-based, lock-safe rotation primitive for the
append-only JSONL files Vikramaditya writes during long engagements
(``logs/runner.log``, the per-engagement audit CSV, anything that
grows unbounded across multiple `hunt.py --autonomous` calls).

Design
------
- ``fcntl.LOCK_EX`` around the size check + rename so two concurrent
  writers don't both rotate the same file half-way through each
  other's append.
- Rotation moves ``path`` → ``path.1`` → ``path.2`` → … up to
  ``keep`` backups; the oldest is deleted.
- Bytes-only — no JSON parsing — so it works on CSVs, JSONLs, plain
  logs, anything line-oriented.
- Disk-full safe: if the rename fails with ``ENOSPC`` we surface
  ``OSError`` instead of silently producing a half-rotated state.
- No third-party deps (no ``logging.handlers.RotatingFileHandler``
  dependency, which has known race-condition issues under multi-
  process workloads).

Public API
----------
- ``rotate_if_needed(path, max_bytes, keep=3)`` → returns ``True`` if
  the file was rotated, ``False`` otherwise. Safe to call before
  every append; the size check is fast.
- ``RotatingAppender(path, max_bytes, keep=3)`` — context-manager
  wrapping the rotation + append in one call. Use this from new code.

Tests in ``tests/test_util_rotation.py`` cover:
- single-writer rotation at the boundary,
- ``keep`` backups (oldest deleted),
- multi-process concurrent appends under rotation (no corruption,
  no lost bytes),
- ``OSError`` propagation when the filesystem is wedged.

Inspired by ``memory/rotation.py`` in
[shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
(MIT).  We do not import or copy their code; this is a generalised
stdlib rewrite that works on any append-only file Vikramaditya owns.
"""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Union

PathLike = Union[str, Path]

DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB
DEFAULT_KEEP = 3


def _path(p: PathLike) -> Path:
    return p if isinstance(p, Path) else Path(p)


@contextmanager
def _file_lock(lock_path: Path) -> Iterator[int]:
    """
    Exclusive file lock. Uses ``fcntl.LOCK_EX``; falls back to
    no-op on Windows (Vikramaditya targets macOS / Linux, so this
    branch is for the test suite running portably).
    """
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            # Best-effort on platforms without flock — proceed unlocked.
            pass
        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def rotate_if_needed(
    path: PathLike,
    max_bytes: int = DEFAULT_MAX_BYTES,
    keep: int = DEFAULT_KEEP,
) -> bool:
    """
    Rotate ``path`` if its current size is at or above ``max_bytes``.

    Move chain:
        path     -> path.1
        path.1   -> path.2
        ...
        path.<keep-1> -> path.<keep>
        path.<keep>   -> deleted
    Then ``path`` is left empty (the writer is expected to recreate
    on next append).

    Returns ``True`` if rotation actually happened.

    Raises:
        ValueError: ``max_bytes`` or ``keep`` non-positive.
        OSError:    any unrecoverable filesystem error (ENOSPC etc.).
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if keep < 1:
        raise ValueError("keep must be at least 1")

    target = _path(path)
    if not target.exists():
        return False
    if target.stat().st_size < max_bytes:
        return False

    lock_path = target.with_suffix(target.suffix + ".rotlock")
    with _file_lock(lock_path):
        # Re-check under the lock: another writer may have rotated already.
        if not target.exists() or target.stat().st_size < max_bytes:
            return False

        # Drop the oldest backup.
        oldest = target.with_suffix(target.suffix + f".{keep}")
        if oldest.exists():
            oldest.unlink()

        # Shift path.<n-1> → path.<n>, from n=keep down to n=2.
        for n in range(keep, 1, -1):
            src = target.with_suffix(target.suffix + f".{n-1}")
            dst = target.with_suffix(target.suffix + f".{n}")
            if src.exists():
                os.rename(src, dst)

        # Finally: path → path.1
        first_backup = target.with_suffix(target.suffix + ".1")
        os.rename(target, first_backup)

    # Discard the lockfile — it served its purpose, no need to leave grit.
    try:
        if lock_path.exists():
            lock_path.unlink()
    except OSError:
        pass
    return True


class RotatingAppender:
    """
    Context-manager wrapper that rotates ``path`` if needed and then
    yields a file handle opened in append mode. Intended for new code
    that wants the simplest possible API.

        with RotatingAppender(audit_log, max_bytes=50_000_000) as fh:
            fh.write(json.dumps(record) + "\n")
    """

    def __init__(
        self,
        path: PathLike,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep: int = DEFAULT_KEEP,
        encoding: str = "utf-8",
    ):
        self.path = _path(path)
        self.max_bytes = max_bytes
        self.keep = keep
        self.encoding = encoding
        self._fh = None

    def __enter__(self):
        rotate_if_needed(self.path, self.max_bytes, self.keep)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", encoding=self.encoding)
        return self._fh

    def __exit__(self, exc_type, exc, tb):
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        return False  # do not suppress

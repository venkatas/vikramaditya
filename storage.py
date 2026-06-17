#!/usr/bin/env python3
"""
storage.py — atomic on-disk write primitives for Vikramaditya.

Adapted from xalgorix (MIT) — internal/storage/atomic.go (WriteAtomic).

Every long-running scan persists state (target_state.json, agent_session.json,
findings, reports). A crash, ^C, full disk, or revoked macOS TCC lock partway
through a naive `open(path, "w"); json.dump(...)` truncates the destination and
leaves a corrupt half-written file — which then poisons the next resume.

These helpers implement the temp+fsync+rename contract exactly once so the
destination is only ever swapped in via an atomic `os.replace`:

    write -> "<dst>.tmp.<rand>" in the SAME directory
    flush + os.fsync                        (data hits the platter)
    chmod 0o600                             (normalise umask effects)
    os.replace(tmp, dst)                    (atomic rename over dst)

On any failure before the rename the temp file is removed, so a caller never
observes a stray "<dst>.tmp.*" sibling and the previous good file stays intact.
The temp lives in the same directory as the destination because os.replace is
only atomic within a single filesystem.

Pure stdlib — runs on bare system python.
"""

from __future__ import annotations

import json
import os
import secrets

__all__ = [
    "atomic_write_bytes",
    "atomic_write_text",
    "atomic_write_json",
]


def atomic_write_bytes(path: str, data: bytes, mode: int = 0o600) -> None:
    """Atomically write ``data`` bytes to ``path`` with permission ``mode``.

    Writes to a temp file in the same directory, fsyncs it, chmods it, then
    renames over ``path``. The parent directory is created (0o700) if missing.
    On any error before the rename the temp file is cleaned up and the original
    ``path`` (if any) is left untouched.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)

    # Random suffix so concurrent writers in the same dir cannot collide,
    # and O_EXCL guarantees we never reuse an abandoned temp file.
    tmp = "{}.tmp.{}".format(path, secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        # Chmod after close so any umask effects on O_CREAT are normalised.
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def atomic_write_text(path: str, text: str, mode: int = 0o600) -> None:
    """Atomically write ``text`` (UTF-8) to ``path`` with permission ``mode``.

    See :func:`atomic_write_bytes` for the durability contract.
    """
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def atomic_write_json(path: str, data, mode: int = 0o600) -> None:
    """Atomically write ``data`` as pretty-printed JSON (indent=2) to ``path``.

    Serialisation happens fully in memory first, so a failure inside
    ``json.dump`` never reaches the filesystem and the original ``path`` is
    preserved. See :func:`atomic_write_bytes` for the durability contract.
    """
    # Serialise before touching disk: if encoding fails, nothing is written.
    payload = json.dumps(data, indent=2, ensure_ascii=False)
    atomic_write_text(path, payload, mode=mode)

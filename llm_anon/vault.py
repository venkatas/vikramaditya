"""PII Vault — SQLite-backed per-engagement surrogate store.

The vault exists so every mention of ``10.20.0.10`` within an engagement
resolves to the same surrogate across sessions, and so two different
engagements for the same underlying organisation can't correlate by
surrogate overlap — each engagement has its own mapping namespace.

Schema
------
``mappings(engagement, entity, original PRIMARY KEY (engagement, original))``
plus a reverse-index column (``surrogate``) so ``deanonymize`` can look up
surrogates in O(log n). SQLite is fine: we're talking low thousands of
entries per engagement, not millions.

Thread safety
-------------
Connections are per-call (short-lived). SQLite's default isolation level
handles our write load — this is single-user tooling, not a service.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path


class Vault:
    """Persistent mapping store for anonymisation surrogates.

    Args:
        db_path: Filesystem path to the SQLite database. The parent dir is
            created if missing. Use ``":memory:"`` for tests.
        engagement_id: Logical engagement / client boundary. Mappings in
            different engagements never collide.
    """

    def __init__(self, db_path: str | os.PathLike[str], engagement_id: str) -> None:
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_path = str(db_path)
        self._engagement = engagement_id
        self._ensure_schema()

    # ------------------------------------------------------------------ DDL

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mappings (
                    engagement TEXT NOT NULL,
                    entity     TEXT NOT NULL,
                    original   TEXT NOT NULL,
                    surrogate  TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (engagement, original)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_mappings_surrogate
                ON mappings(engagement, surrogate)
                """
            )

    # ------------------------------------------------------------ read/write

    def get_surrogate(self, entity: str, original: str) -> str | None:
        """Return the surrogate for ``original`` in the current engagement."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT surrogate FROM mappings "
                "WHERE engagement = ? AND original = ?",
                (self._engagement, original),
            ).fetchone()
        return row[0] if row else None

    def get_original(self, surrogate: str) -> str | None:
        """Reverse lookup — used by the deanonymiser."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT original FROM mappings "
                "WHERE engagement = ? AND surrogate = ?",
                (self._engagement, surrogate),
            ).fetchone()
        return row[0] if row else None

    def put(self, entity: str, original: str, surrogate: str) -> None:
        """Persist a mapping. No-op if (engagement, original) already exists."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO mappings "
                "(engagement, entity, original, surrogate) VALUES (?, ?, ?, ?)",
                (self._engagement, entity, original, surrogate),
            )

    def stats(self) -> dict[str, int]:
        """Entity-type histogram for the current engagement."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT entity, COUNT(*) FROM mappings "
                "WHERE engagement = ? GROUP BY entity",
                (self._engagement,),
            ).fetchall()
        return {entity: n for entity, n in rows}

    def all_mappings(self) -> list[tuple[str, str, str]]:
        """Return ``(entity, original, surrogate)`` rows for this engagement.

        Used by :class:`Anonymizer.deanonymize` to build the reverse substitution
        set — sorted longest-first to avoid partial replacement.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT entity, original, surrogate FROM mappings "
                "WHERE engagement = ?",
                (self._engagement,),
            ).fetchall()
        return [(e, o, s) for e, o, s in rows]

    def clear(self) -> int:
        """Drop all mappings for the current engagement. Returns rows deleted."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM mappings WHERE engagement = ?",
                (self._engagement,),
            )
            return cur.rowcount

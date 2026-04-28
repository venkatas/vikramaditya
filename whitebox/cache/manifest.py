from __future__ import annotations
import json
import time
from pathlib import Path


class PhaseCache:
    """24h TTL phase cache. Stored as JSON manifest in <session>/cloud/<account>/manifest.json."""

    def __init__(self, account_dir: Path, ttl_seconds: int = 86400):
        self.account_dir = Path(account_dir)
        self.account_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.account_dir / "manifest.json"
        self.ttl = ttl_seconds
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2, default=str))

    def mark_complete(self, phase: str, artifacts: dict | None = None) -> None:
        self._data[phase] = {
            "status": "complete",
            "completed_at": time.time(),
            "artifacts": artifacts or {},
        }
        self._save()

    def mark_failed(self, phase: str, error: str) -> None:
        self._data[phase] = {
            "status": "failed",
            "completed_at": time.time(),
            "error": error,
        }
        self._save()

    def is_fresh(self, phase: str) -> bool:
        meta = self._data.get(phase)
        if not meta or meta.get("status") != "complete":
            return False
        return (time.time() - meta["completed_at"]) < self.ttl

    def get(self, phase: str) -> dict | None:
        return self._data.get(phase)

    def refresh(self) -> None:
        self._data = {}
        self._save()

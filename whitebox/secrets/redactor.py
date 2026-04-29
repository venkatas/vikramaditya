from __future__ import annotations
import json
import os
from pathlib import Path


def write_evidence(secrets_dir: Path, finding_id: str, hits: list[dict]) -> Path:
    """Write full secret values to mode-0600 JSON. Raises ValueError on path traversal in finding_id.
    Caller must use only inside cloud/secrets/. Parent dir is locked to 0700."""
    secrets_dir = Path(secrets_dir)
    # Reject path-traversal / absolute-path finding IDs
    if "/" in finding_id or "\\" in finding_id or ".." in finding_id or finding_id.startswith("."):
        raise ValueError(f"finding_id contains illegal path characters: {finding_id!r}")
    secrets_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(secrets_dir, 0o700)
    path = secrets_dir / f"{finding_id}.json"
    # Defensive resolve check — must stay inside secrets_dir
    if not path.resolve().is_relative_to(secrets_dir.resolve()):
        raise ValueError(f"finding_id resolves outside secrets_dir: {finding_id!r}")
    # Atomic open with mode 0600 — no race window
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(hits, indent=2))
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return path


def redact_for_html(hits: list[dict]) -> list[dict]:
    """Strip raw value before passing to report renderer."""
    return [{k: v for k, v in h.items() if k != "value"} for h in hits]

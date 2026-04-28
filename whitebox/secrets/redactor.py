from __future__ import annotations
import json
import os
from pathlib import Path


def write_evidence(secrets_dir: Path, finding_id: str, hits: list[dict]) -> Path:
    """Write full secret values to mode-0600 JSON. Caller must use only inside cloud/secrets/."""
    secrets_dir = Path(secrets_dir)
    secrets_dir.mkdir(parents=True, exist_ok=True)
    path = secrets_dir / f"{finding_id}.json"
    path.write_text(json.dumps(hits, indent=2))
    os.chmod(path, 0o600)
    return path


def redact_for_html(hits: list[dict]) -> list[dict]:
    """Strip raw value before passing to report renderer."""
    return [{k: v for k, v in h.items() if k != "value"} for h in hits]

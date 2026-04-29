from __future__ import annotations
import json
from pathlib import Path
from whitebox.models import Finding


def dump_findings(findings: list[Finding], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
    return path

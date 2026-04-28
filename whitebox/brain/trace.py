from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path


class BrainTrace:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, decision_point: str, input_summary: dict, decision: dict,
            model: str = "ollama", rule_traced: str | None = None) -> None:
        payload = json.dumps(input_summary, sort_keys=True, default=str)
        h = hashlib.sha256(payload.encode()).hexdigest()[:12]
        entry = {
            "ts": time.time(),
            "decision_point": decision_point,
            "input_hash": h,
            "input_summary": input_summary,
            "decision": decision,
            "model": model,
            "rule_traced": rule_traced,
        }
        with self.path.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

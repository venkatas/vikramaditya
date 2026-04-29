import json
from whitebox.brain.trace import BrainTrace


def test_trace_writes_jsonl_line_per_decision(tmp_path):
    t = BrainTrace(tmp_path / "brain_trace.jsonl")
    t.log("plan_phases", input_summary={"services": 5}, decision={"order": ["inventory"]})
    t.log("select_secret_targets", input_summary={"buckets": 10}, decision={"selected": ["b1"]})
    lines = (tmp_path / "brain_trace.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["decision"]["order"] == ["inventory"]
    assert "input_hash" in first

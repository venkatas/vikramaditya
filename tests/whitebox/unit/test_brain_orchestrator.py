from unittest.mock import MagicMock
from whitebox.brain.orchestrator import BrainOrchestrator


def test_falls_back_to_defaults_when_brain_unreachable(tmp_path):
    fake_brain = MagicMock()
    fake_brain.ask.side_effect = RuntimeError("ollama down")
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    plan = o.plan_phases({"profile": "p", "services": ["ec2"]})
    # Default plan: all phases in fixed order
    assert plan == ["inventory", "prowler", "iam", "exposure", "secrets", "correlation", "report"]


def test_select_secret_targets_returns_brain_choice(tmp_path):
    fake_brain = MagicMock()
    fake_brain.ask.return_value = '{"buckets": ["a", "b"], "log_groups": ["/x"]}'
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    targets = o.select_secret_targets({"buckets": [{"name": "a"}, {"name": "b"}, {"name": "c"}]})
    assert targets["buckets"] == ["a", "b"]
    assert targets["log_groups"] == ["/x"]


def test_select_secret_targets_falls_back_on_brain_error(tmp_path):
    fake_brain = MagicMock()
    fake_brain.ask.side_effect = RuntimeError("x")
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    targets = o.select_secret_targets({"buckets": [{"name": "a"}, {"name": "b"}]})
    # Default: scan all buckets
    assert set(targets["buckets"]) == {"a", "b"}

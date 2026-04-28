import json
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
    targets = o.select_secret_targets({
        "buckets": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
        "log_groups": [{"name": "/x"}, {"name": "/y"}],
    })
    assert targets["buckets"] == ["a", "b"]
    assert targets["log_groups"] == ["/x"]


def test_select_secret_targets_falls_back_on_brain_error(tmp_path):
    fake_brain = MagicMock()
    fake_brain.ask.side_effect = RuntimeError("x")
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    targets = o.select_secret_targets({"buckets": [{"name": "a"}, {"name": "b"}]})
    # Default: scan all buckets
    assert set(targets["buckets"]) == {"a", "b"}


def test_select_secret_targets_drops_hallucinated_buckets(tmp_path):
    """Brain returning a bucket NOT in inventory must be dropped — defensibility."""
    fake_brain = MagicMock()
    fake_brain.ask.return_value = '{"buckets": ["a", "ghost-bucket"], "log_groups": []}'
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    targets = o.select_secret_targets({"buckets": [{"name": "a"}, {"name": "b"}]})
    assert "ghost-bucket" not in targets["buckets"]
    assert "a" in targets["buckets"]


def test_plan_phases_drops_unknown_and_appends_missing(tmp_path):
    """Brain cannot drop required phases or introduce unknown ones."""
    fake_brain = MagicMock()
    fake_brain.ask.return_value = '{"order": ["report", "unknown_phase", "inventory"]}'
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    plan = o.plan_phases({"profile": "p", "services": []})
    assert "unknown_phase" not in plan
    # All DEFAULT_PHASE_ORDER phases must be present
    from whitebox.brain.orchestrator import DEFAULT_PHASE_ORDER
    assert set(plan) == set(DEFAULT_PHASE_ORDER)


def test_filter_chains_handles_list_response_gracefully(tmp_path):
    """If brain returns a JSON list (matching old prompt) instead of dict, fallback to keep-all."""
    from whitebox.models import Chain, Severity
    fake_brain = MagicMock()
    fake_brain.ask.return_value = '["f1"]'  # list, not dict
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    candidates = [Chain(trigger_finding_id="f1", cloud_asset_arn="arn",
                        iam_path=["a", "b"], promoted_severity=Severity.HIGH,
                        promotion_rule="chain.x", narrative="")]
    kept = o.filter_chains(candidates)
    # malformed response → fallback keeps all
    assert len(kept) == 1


def test_executive_summary_logs_to_trace(tmp_path):
    fake_brain = MagicMock()
    fake_brain.ask.return_value = "Summary text here."
    o = BrainOrchestrator(brain=fake_brain, trace_path=tmp_path / "t.jsonl")
    o.write_executive_summary(findings=[], chains=[])
    lines = (tmp_path / "t.jsonl").read_text().strip().splitlines()
    assert any(json.loads(l)["decision_point"] == "write_executive_summary" for l in lines)

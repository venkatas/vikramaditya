from pathlib import Path
from whitebox.iam.graph import IAMGraph
from whitebox.iam.privesc import detect_paths
from whitebox.models import Severity

FIX = Path(__file__).parents[1] / "integration" / "fixtures" / "pmapper_graph_sample.json"


def test_detect_paths_emits_finding_per_admin_path():
    g = IAMGraph.load(FIX)
    findings = detect_paths(g, account_id="111")
    # alice → web-prod → admin is one privesc path
    assert any("alice" in f.title and "admin" in f.title for f in findings)
    assert all(f.source == "pmapper" for f in findings)
    assert all(f.severity >= Severity.HIGH for f in findings)
    assert all(f.rule_id.startswith("pmapper.") for f in findings)


def test_detect_paths_skips_already_admin_principals():
    g = IAMGraph.load(FIX)
    findings = detect_paths(g, account_id="111")
    # admin role is already admin — no self-finding
    assert not any(f.title.startswith("admin →") for f in findings)

from pathlib import Path
from whitebox.iam.graph import IAMGraph

FIX = Path(__file__).parents[1] / "integration" / "fixtures" / "pmapper_graph_sample.json"


def test_load_graph_counts_nodes_and_edges():
    g = IAMGraph.load(FIX)
    assert len(g.nodes) == 3
    assert len(g.edges) == 2


def test_can_reach_finds_two_hop_path():
    g = IAMGraph.load(FIX)
    path = g.can_reach("arn:aws:iam::111:user/alice", "arn:aws:iam::111:role/admin")
    assert path == [
        "arn:aws:iam::111:user/alice",
        "arn:aws:iam::111:role/web-prod",
        "arn:aws:iam::111:role/admin",
    ]


def test_can_reach_returns_none_when_unreachable():
    g = IAMGraph.load(FIX)
    assert g.can_reach("arn:aws:iam::111:role/admin", "arn:aws:iam::111:user/alice") is None


def test_reachable_admins():
    g = IAMGraph.load(FIX)
    admins = g.reachable_admins("arn:aws:iam::111:user/alice")
    assert "arn:aws:iam::111:role/admin" in admins


def test_blast_radius_counts_assumable_roles():
    g = IAMGraph.load(FIX)
    br = g.blast_radius("arn:aws:iam::111:user/alice")
    assert "arn:aws:iam::111:role/web-prod" in br.assumable_roles
    assert "arn:aws:iam::111:role/admin" in br.assumable_roles

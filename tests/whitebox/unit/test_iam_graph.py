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


def test_load_graph_from_pmapper_storage_dir(tmp_path):
    """IAMGraph.load() must accept a PMapper-style directory: metadata.json + graph/{nodes,edges}.json."""
    (tmp_path / "metadata.json").write_text('{"account_id": "111"}')
    (tmp_path / "graph").mkdir()
    (tmp_path / "graph" / "nodes.json").write_text(
        '[{"arn": "arn:aws:iam::111:role/r", "id_value": "r", "is_admin": false}]'
    )
    (tmp_path / "graph" / "edges.json").write_text("[]")
    g = IAMGraph.load(tmp_path)
    assert "arn:aws:iam::111:role/r" in g.nodes

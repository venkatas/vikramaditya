from __future__ import annotations
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from whitebox.models import BlastRadius


@dataclass
class IAMGraph:
    nodes: dict[str, dict]            # arn → node attrs
    edges: dict[str, list[dict]]      # source_arn → list of {destination, reason}

    @classmethod
    def load(cls, path: Path) -> "IAMGraph":
        """Load from either a single-file JSON (legacy/test fixture) or a PMapper storage directory."""
        path = Path(path)
        if path.is_dir():
            nodes_data = json.loads((path / "graph" / "nodes.json").read_text())
            edges_data = json.loads((path / "graph" / "edges.json").read_text())
            # PMapper node entries: {"arn": ..., "id_value": ..., "is_admin": ...} (compatible)
            # PMapper edge entries: {"source": ..., "destination": ..., "reason": ...} (compatible)
            data = {"nodes": nodes_data if isinstance(nodes_data, list) else nodes_data.get("nodes", []),
                    "edges": edges_data if isinstance(edges_data, list) else edges_data.get("edges", [])}
        else:
            data = json.loads(path.read_text())
        nodes = {n["arn"]: n for n in data.get("nodes", [])}
        edges: dict[str, list[dict]] = defaultdict(list)
        for e in data.get("edges", []):
            edges[e["source"]].append({"destination": e["destination"], "reason": e.get("reason", "")})
        return cls(nodes=nodes, edges=dict(edges))

    def can_reach(self, src: str, dst: str) -> list[str] | None:
        """BFS shortest path. Returns ARN list including endpoints, or None."""
        if src == dst:
            return [src]
        visited = {src}
        queue = deque([(src, [src])])
        while queue:
            node, path = queue.popleft()
            for e in self.edges.get(node, []):
                nxt = e["destination"]
                if nxt in visited:
                    continue
                if nxt == dst:
                    return path + [nxt]
                visited.add(nxt)
                queue.append((nxt, path + [nxt]))
        return None

    def reachable_admins(self, src: str) -> list[str]:
        out = []
        for arn, node in self.nodes.items():
            if node.get("is_admin") and arn != src:
                if self.can_reach(src, arn):
                    out.append(arn)
        return out

    def blast_radius(self, src: str) -> BlastRadius:
        reachable: set[str] = set()
        stack = [src]
        while stack:
            n = stack.pop()
            for e in self.edges.get(n, []):
                if e["destination"] not in reachable and e["destination"] != src:
                    reachable.add(e["destination"])
                    stack.append(e["destination"])
        return BlastRadius(
            principal_arn=src,
            s3_buckets=[],   # populated later by cross-referencing inventory
            kms_keys=[],
            lambdas=[],
            assumable_roles=sorted(reachable),
            regions=[],
        )

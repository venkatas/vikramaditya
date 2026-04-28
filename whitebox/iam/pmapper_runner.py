from __future__ import annotations
import subprocess
from pathlib import Path
from whitebox.profiles import CloudProfile


def build_graph(profile: CloudProfile, out_dir: Path, timeout: int = 1800) -> Path:
    """Invoke pmapper to create the graph; return path to graph JSON."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["pmapper", "--profile", profile.name, "graph", "create"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        (out_dir / "error.log").write_text(proc.stderr)
        raise RuntimeError(f"pmapper exited {proc.returncode}; see {out_dir/'error.log'}")
    # pmapper stores graphs under ~/.principalmapper/<account_id>/graph.json
    src = Path.home() / ".principalmapper" / profile.account_id / "graph.json"
    dst = out_dir / "graph.json"
    dst.write_text(src.read_text())
    return dst

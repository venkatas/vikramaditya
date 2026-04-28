from __future__ import annotations
import subprocess
from pathlib import Path
from whitebox.profiles import CloudProfile


def build_graph(profile: CloudProfile, out_dir: Path, timeout: int = 1800) -> Path:
    """Invoke pmapper to create the graph; return path to the pmapper storage directory.

    Real PMapper (nccgroup/PMapper) writes a directory layout under its storage root:
      <storage_root>/<account_id>/
        metadata.json
        graph/nodes.json
        graph/edges.json

    This function copies that whole tree into out_dir/pmapper-storage/ and returns
    that directory.  The storage root is read from the PMAPPER_STORAGE env var if
    set; otherwise defaults to ~/.principalmapper.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["pmapper", "--profile", profile.name, "graph", "create"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        (out_dir / "error.log").write_text(proc.stderr)
        raise RuntimeError(f"pmapper exited {proc.returncode}; see {out_dir/'error.log'}")
    # Real PMapper storage layout (per nccgroup/PMapper):
    #   <PMAPPER_STORAGE | platform default>/<account_id>/
    #     metadata.json
    #     graph/nodes.json
    #     graph/edges.json
    import os as _os
    storage_root = Path(_os.environ.get("PMAPPER_STORAGE") or (Path.home() / ".principalmapper"))
    src_dir = storage_root / profile.account_id
    if not (src_dir / "metadata.json").exists():
        # Try common alternative locations
        candidates = [
            Path.home() / ".principalmapper" / profile.account_id,
            Path("/var/lib/principalmapper") / profile.account_id,
        ]
        for c in candidates:
            if (c / "metadata.json").exists():
                src_dir = c
                break
        else:
            raise FileNotFoundError(
                f"PMapper graph storage not found under {storage_root!s} or fallback paths "
                f"for account {profile.account_id}. Set PMAPPER_STORAGE env var if non-default."
            )
    dst_dir = out_dir / "pmapper-storage"
    dst_dir.mkdir(parents=True, exist_ok=True)
    (dst_dir / "metadata.json").write_text((src_dir / "metadata.json").read_text())
    (dst_dir / "graph").mkdir(exist_ok=True)
    (dst_dir / "graph" / "nodes.json").write_text((src_dir / "graph" / "nodes.json").read_text())
    (dst_dir / "graph" / "edges.json").write_text((src_dir / "graph" / "edges.json").read_text())
    return dst_dir

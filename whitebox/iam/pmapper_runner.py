from __future__ import annotations
import os
import subprocess
from pathlib import Path
from whitebox.profiles import CloudProfile


def build_graph(profile: CloudProfile, out_dir: Path, timeout: int = 1800) -> Path:
    """Invoke pmapper to create the graph; return path to the storage directory.

    Sets PYTHONNOUSERSITE=1 to avoid distutils-hack noise polluting subprocess
    output. Captures both stdout AND stderr separately so the real error is
    discoverable, and writes a combined log.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["pmapper", "--profile", profile.name, "graph", "create"]

    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"  # skip site-packages distutils-hack
    env["PYTHONWARNINGS"] = "ignore::DeprecationWarning"

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    # Always write both streams so post-mortem is possible regardless of returncode
    (out_dir / "stdout.log").write_text(proc.stdout or "")
    (out_dir / "stderr.log").write_text(proc.stderr or "")

    if proc.returncode != 0:
        # Combined error log — strip the distutils-hack noise lines for readability
        clean_stderr = "\n".join(
            l for l in (proc.stderr or "").splitlines()
            if "_distutils_hack" not in l
            and "distutils-precedence" not in l
            and l.strip()
        )
        (out_dir / "error.log").write_text(
            f"pmapper exited {proc.returncode}\n\n"
            f"stdout:\n{proc.stdout}\n\nstderr (cleaned):\n{clean_stderr}\n"
        )
        raise RuntimeError(f"pmapper exited {proc.returncode}; see {out_dir / 'error.log'}")

    # PMapper storage layout discovery (unchanged from prior fix)
    storage_root = Path(env.get("PMAPPER_STORAGE") or (Path.home() / ".principalmapper"))
    src_dir = storage_root / profile.account_id
    if not (src_dir / "metadata.json").exists():
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

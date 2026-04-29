from __future__ import annotations
import json
import subprocess
import time
from pathlib import Path
from whitebox.profiles import CloudProfile


def _has_prowler() -> bool:
    """Check whether the prowler binary is on PATH."""
    import shutil
    return shutil.which("prowler") is not None


def run(profile: CloudProfile, out_dir: Path,
        check_groups: list[str] | None = None,
        timeout: int = 1800) -> Path:
    """Invoke prowler, return path to OCSF JSON output (must be newer than this run's start).
    Raises FileNotFoundError if prowler binary is not on PATH (caller should fall back gracefully)."""
    if not _has_prowler():
        raise FileNotFoundError(
            "prowler binary not found on PATH. Install with `pip install prowler-cloud==4.5.0` "
            "or skip this phase (it will be marked failed in the manifest and the rest of the "
            "audit will continue)."
        )
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    start_ts = time.time()
    cmd = [
        "prowler", "aws",
        "--profile", profile.name,
        "--output-formats", "json-ocsf",
        "--output-directory", str(out_dir),
    ]
    if check_groups:
        cmd += ["--checks-folder"] + check_groups
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        (out_dir / "error.log").write_text(proc.stderr)
        raise RuntimeError(f"prowler exited {proc.returncode}; see {out_dir / 'error.log'}")
    return _find_output_file(out_dir, min_mtime=start_ts)


def _find_output_file(out_dir: Path, min_mtime: float = 0.0) -> Path:
    candidates = list(out_dir.glob("*.ocsf.json")) + list(out_dir.glob("*ocsf*.json"))
    fresh = [c for c in candidates if c.stat().st_mtime >= min_mtime]
    if not fresh:
        raise FileNotFoundError(f"no fresh OCSF JSON output in {out_dir} (min_mtime={min_mtime})")
    return fresh[0]


def parse(ocsf_path: Path) -> list[dict]:
    return json.loads(Path(ocsf_path).read_text())

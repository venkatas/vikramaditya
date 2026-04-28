from __future__ import annotations
import json
import subprocess
from pathlib import Path
from whitebox.profiles import CloudProfile


def run(profile: CloudProfile, out_dir: Path,
        check_groups: list[str] | None = None,
        timeout: int = 1800) -> Path:
    """Invoke prowler, return path to OCSF JSON output."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
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
        raise RuntimeError(f"prowler exited {proc.returncode}; see {out_dir/'error.log'}")
    return _find_output_file(out_dir)


def _find_output_file(out_dir: Path) -> Path:
    candidates = list(out_dir.glob("*.ocsf.json")) + list(out_dir.glob("*ocsf*.json"))
    if not candidates:
        raise FileNotFoundError(f"no OCSF JSON output in {out_dir}")
    return candidates[0]


def parse(ocsf_path: Path) -> list[dict]:
    return json.loads(Path(ocsf_path).read_text())

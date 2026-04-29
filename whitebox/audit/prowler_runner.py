from __future__ import annotations
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from whitebox.profiles import CloudProfile

# Prowler 4.5.0 hard-pins pydantic==1.10.18, which conflicts with ollama (used by
# brain.py) and most modern Python packages. Install Prowler in an isolated venv
# (default: ~/.venvs/prowler) and discover its binary via these candidate paths
# in priority order. PROWLER_BIN env var overrides everything.
_PROWLER_PATH_CANDIDATES = (
    Path.home() / ".venvs" / "prowler" / "bin" / "prowler",
    Path.home() / ".local" / "share" / "prowler" / "bin" / "prowler",
    Path("/opt/prowler/bin/prowler"),
)


def _resolve_prowler_binary() -> str | None:
    """Find the prowler binary. Returns absolute path string or None if not found.
    Resolution order: PROWLER_BIN env var → isolated venv candidates → PATH."""
    env_override = os.environ.get("PROWLER_BIN")
    if env_override and Path(env_override).is_file():
        return env_override
    for candidate in _PROWLER_PATH_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
    on_path = shutil.which("prowler")
    return on_path


def _has_prowler() -> bool:
    """Check whether a usable prowler binary can be located."""
    return _resolve_prowler_binary() is not None


def run(profile: CloudProfile, out_dir: Path,
        check_groups: list[str] | None = None,
        timeout: int = 1800) -> Path:
    """Invoke prowler, return path to OCSF JSON output (must be newer than this run's start).
    Raises FileNotFoundError if prowler binary cannot be located (caller should fall back gracefully)."""
    binary = _resolve_prowler_binary()
    if binary is None:
        raise FileNotFoundError(
            "prowler binary not found. Install in an isolated venv to avoid pydantic conflicts:\n"
            "  python3 -m venv ~/.venvs/prowler\n"
            "  ~/.venvs/prowler/bin/pip install prowler-cloud==4.5.0\n"
            "Or set PROWLER_BIN to an existing prowler executable. The phase will be marked "
            "failed in the manifest and the rest of the audit will continue."
        )
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    start_ts = time.time()
    cmd = [
        binary, "aws",
        "--profile", profile.name,
        "--output-formats", "json-ocsf",
        "--output-directory", str(out_dir),
    ]
    if check_groups:
        cmd += ["--checks-folder"] + check_groups
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        (out_dir / "error.log").write_text(
            f"prowler exited {proc.returncode}\nbinary: {binary}\n\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}\n"
        )
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

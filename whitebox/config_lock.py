"""Per-session scan-config lock — proves config drift between scans.

Codex review flagged that two consecutive scans of the same target could
produce different findings without any obvious record of why. The fix is
a small, deterministic ``config.lock.json`` written at the start of every
scan that captures: vikramaditya version, external tool versions, hashes
of the wordlists in play, the scope-control env vars, and the resolved
CLI args. Diffing two lock files instantly explains "this run found 3
extra criticals" — usually because nuclei ticked or someone rotated
``WHITEBOX_REGIONS``.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

# Tools that should be probed for ``--version`` / ``-version``. Each entry
# is (binary, args). Missing binaries record ``"not_installed"``.
_TOOL_PROBES = (
    ("nuclei",   ["-version"]),
    ("subfinder", ["-version"]),
    ("httpx",    ["-version"]),
    ("naabu",    ["-version"]),
    ("amass",    ["-version"]),
    ("prowler",  ["--version"]),
    ("pmapper",  ["--version"]),
)

_WORDLIST_PATHS = (
    "wordlists/api-words.txt",
    "wordlists/sqli-payloads.txt",
    "wordlists/xss-payloads.txt",
)

_TRACKED_ENV = (
    "WHITEBOX_REGIONS",
    "PMAPPER_REGIONS",
    "PROWLER_TIMEOUT",
    "PMAPPER_TIMEOUT",
)


def _probe_tool(binary: str, args: list[str]) -> str:
    path = shutil.which(binary)
    if not path:
        return "not_installed"
    try:
        proc = subprocess.run([path, *args], capture_output=True,
                              text=True, timeout=10)
        out = (proc.stdout or proc.stderr or "").strip()
        return out.splitlines()[0] if out else "unknown"
    except Exception as e:
        return f"probe_failed:{type(e).__name__}"


def _hash_file(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return "missing"
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception as e:
        return f"hash_failed:{type(e).__name__}"
    return h.hexdigest()


def _vikramaditya_version(repo_root: Path) -> str:
    version_file = repo_root / "VERSION"
    if version_file.exists():
        try:
            return version_file.read_text().strip() or "unknown"
        except Exception:
            pass
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_root,
                              capture_output=True, text=True, timeout=5)
        sha = (proc.stdout or "").strip()
        if sha:
            return sha
    except Exception:
        pass
    return "unknown"


def _normalise_args(args: Any) -> Any:
    """Best-effort args→dict: argparse.Namespace, dict, or anything mappable."""
    if args is None:
        return {}
    if isinstance(args, dict):
        return {k: _stringify(v) for k, v in args.items()}
    if hasattr(args, "__dict__"):
        return {k: _stringify(v) for k, v in vars(args).items()}
    return {"_repr": repr(args)}


def _stringify(v: Any) -> Any:
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, (list, tuple)):
        return [_stringify(x) for x in v]
    if isinstance(v, dict):
        return {k: _stringify(x) for k, x in v.items()}
    return repr(v)


def write_session_lock(session_dir: str | os.PathLike,
                       args: Any = None,
                       env: dict[str, str] | None = None) -> Path:
    """Write ``<session_dir>/config.lock.json`` and return the path.

    Safe to call multiple times — subsequent calls overwrite. Never raises;
    a failure to capture any single field is recorded inline so the lock
    file always lands.
    """
    sdir = Path(session_dir)
    sdir.mkdir(parents=True, exist_ok=True)
    repo_root = Path(__file__).resolve().parent.parent
    env = env if env is not None else os.environ

    lock = {
        "session_id": sdir.name,
        "vikramaditya_version": _vikramaditya_version(repo_root),
        "tool_versions": {
            binary: _probe_tool(binary, probe_args)
            for binary, probe_args in _TOOL_PROBES
        },
        "wordlist_hashes": {
            rel: _hash_file(repo_root / rel) for rel in _WORDLIST_PATHS
        },
        "env": {k: env.get(k, "") for k in _TRACKED_ENV},
        "args": _normalise_args(args),
        "started_at": _dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    out = sdir / "config.lock.json"
    try:
        out.write_text(json.dumps(lock, indent=2, sort_keys=True))
    except Exception:
        # Final fallback — swallow so the scan never aborts on lockfile IO.
        pass
    return out


__all__ = ["write_session_lock"]

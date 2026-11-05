"""Shared Nuclei redirect guard for exact-scope engagements.

Filtering input hosts cannot constrain a template's ``redirects: true``. The
engine's global disable flag must also be passed by every active entry point.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import tempfile

from phase_manifest import resolve_session_dirs


def scope_locked(*paths, locked: bool = False) -> bool:
    if locked or os.environ.get("SCOPE_LOCK") == "1" or "SCOPE_ALLOW_FILE" in os.environ:
        return True
    for raw in paths:
        if not raw:
            continue
        path = Path(raw).absolute()
        # Inputs may be a session directory, findings subtree, or output file.
        # A present but empty/unreadable policy is still a scope lock.
        for parent in (path, *path.parents):
            for directory in resolve_session_dirs(str(parent)):
                if (Path(directory) / "scope" / "allow.txt").exists():
                    return True
    return False


def nuclei_scope_flags(*paths, locked: bool = False) -> list[str]:
    # Nuclei rejects simultaneous follow/disable booleans before traffic. A
    # conflicting operator configuration therefore fails closed; do not rewrite
    # or discard unknown configuration merely to make the scan run.
    # Same-authority redirects are intentionally suppressed too, so templates
    # requiring a redirect have partial coverage under this exact-scope guard.
    return ["-dr"] if scope_locked(*paths, locked=locked) else []


def _coverage_directory(*paths):
    contexts = [Path(raw).absolute() for raw in paths if raw]
    for path in contexts:
        for parent in (path, *path.parents):
            recon_dir, findings_dir = resolve_session_dirs(str(parent))
            if (Path(recon_dir) / "scope" / "allow.txt").exists():
                return Path(findings_dir)
    for path in contexts:
        match = re.search(r"/(?:recon|findings|reports)/[^/]+/sessions/[^/]+", str(path))
        if match:
            return Path(resolve_session_dirs(str(path)[:match.end()])[1])
    if contexts:
        path = contexts[0]
        if path.is_file() or path.suffix in {".txt", ".json", ".jsonl", ".yaml", ".yml", ".log"}:
            path = path.parent
        return Path(resolve_session_dirs(str(path))[1])
    return None


def record_nuclei_coverage(*paths, exit_code=None, locked: bool = False) -> None:
    """Record intentional redirect limits and fail-closed engine errors, not findings."""
    if not scope_locked(*paths, locked=locked):
        return
    reason = "scope-lock disables all HTTP redirects; redirect-dependent templates have partial coverage"
    if exit_code not in (None, 0):
        reason = (f"scope-locked Nuclei exited rc={exit_code}; coverage is incomplete "
                  "(including incompatible follow-redirect configuration)")
    print(f"[!] Nuclei coverage: {reason}", file=sys.stderr)
    directory = _coverage_directory(*paths)
    if directory is None:
        return
    try:
        directory.mkdir(parents=True, exist_ok=True)
        marker = directory / "coverage_degraded.json"
        # A sidecar lock remains stable across atomic replacement of the JSON
        # inode. Normal and failed concurrent Nuclei calls must not lose gaps.
        with (directory / "coverage_degraded.json.lock").open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                entries = json.loads(marker.read_text())
                if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
                    raise ValueError("existing coverage record is not a list of objects")
            except FileNotFoundError:
                entries = []
            except (OSError, ValueError):
                # Preserve malformed/unreadable evidence byte-for-byte. The
                # reporter already consumes this append-only fallback format.
                gaps = directory / "manual_review" / "coverage_gaps.txt"
                gaps.parent.mkdir(parents=True, exist_ok=True)
                with gaps.open("a") as output:
                    output.write(f"\n[COVERAGE-GAP] nuclei: {reason}\n")
                return
            entry = {"tool": "nuclei", "reason": reason, "phase": "scope_lock"}
            if entry in entries:
                return
            entries.append(entry)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory,
                                                 prefix=".coverage_degraded.", delete=False) as output:
                    temporary = output.name
                    json.dump(entries, output, indent=2)
                    output.write("\n")
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, marker)
            finally:
                if temporary is not None:
                    Path(temporary).unlink(missing_ok=True)
    except OSError as exc:
        print(f"[!] Could not persist Nuclei coverage limitation: {exc}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell-flags", action="store_true")
    parser.add_argument("--locked", action="store_true")
    parser.add_argument("--record-coverage", action="store_true")
    parser.add_argument("--exit-code", type=int)
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    if args.record_coverage:
        record_nuclei_coverage(*args.paths, exit_code=args.exit_code, locked=args.locked)
    else:
        print(" ".join(nuclei_scope_flags(*args.paths, locked=args.locked)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

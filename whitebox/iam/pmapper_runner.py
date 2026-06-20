from __future__ import annotations
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import procutil  # noqa: E402  fork-safe launch (macOS Network.framework atfork SIGSEGV fix)
from whitebox.profiles import CloudProfile  # noqa: E402

# PMapper 1.1.5 has dependency issues in modern venvs; install in an isolated
# venv (default ~/.venvs/pmapper) with a patched case_insensitive_dict.py to
# fix the Python 3.10+ collections.abc import bug. PMAPPER_BIN env var overrides.
_PMAPPER_PATH_CANDIDATES = (
    Path.home() / ".venvs" / "pmapper" / "bin" / "pmapper",
    Path.home() / ".local" / "share" / "pmapper" / "bin" / "pmapper",
    Path("/opt/pmapper/bin/pmapper"),
)


def _resolve_pmapper_binary() -> str | None:
    """Find the pmapper binary. Returns absolute path string or None.
    Resolution order: PMAPPER_BIN env var → isolated venv candidates → PATH."""
    env_override = os.environ.get("PMAPPER_BIN")
    if env_override and Path(env_override).is_file():
        return env_override
    for candidate in _PMAPPER_PATH_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
    return shutil.which("pmapper")


def build_graph(profile: CloudProfile, out_dir: Path, timeout: int | None = None) -> Path:
    """Invoke pmapper to create the graph; return path to the storage directory.
    Sets PYTHONNOUSERSITE=1 to avoid distutils-hack noise polluting subprocess output.
    Raises FileNotFoundError if pmapper binary cannot be located.

    timeout defaults to the PMAPPER_TIMEOUT env var (seconds) if set, otherwise 1800 (30 min).
    On large IAM estates (many users/roles/policies) 1800s is often too tight; raise via
    the env var or by passing an explicit timeout kwarg."""
    if timeout is None:
        timeout = int(os.environ.get("PMAPPER_TIMEOUT", "1800"))
    binary = _resolve_pmapper_binary()
    if binary is None:
        raise FileNotFoundError(
            "pmapper binary not found. Install in an isolated venv:\n"
            "  python3.11 -m venv ~/.venvs/pmapper\n"
            "  ~/.venvs/pmapper/bin/pip install principalmapper\n"
            "  # Patch case_insensitive_dict.py for Python 3.10+:\n"
            "  sed -i 's/from collections import Mapping/from collections.abc import Mapping/' \\\n"
            "    ~/.venvs/pmapper/lib/python*/site-packages/principalmapper/util/case_insensitive_dict.py\n"
            "Or set PMAPPER_BIN to an existing pmapper executable."
        )
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Freshness baseline: PMapper writes its graph into a SHARED per-account
    # storage root (~/.principalmapper/<account_id> or the appdirs location) that
    # is NOT cleared by the orchestrator's --refresh (which only rmtrees the
    # per-run pmapper/ artifact dir). If `graph create` partially fails or is a
    # no-op, an OLD graph from a prior run would otherwise be copied and reported
    # as current privesc paths. Capture the run start so we can reject any graph
    # metadata.json that predates this invocation (mirrors prowler_runner's
    # min_mtime freshness gate).
    start_ts = time.time()
    cmd = [binary, "--profile", profile.name, "graph", "create"]
    # PMAPPER_REGIONS comma-separated env var narrows graph build to specific
    # regions, avoiding ConnectTimeoutError on slow opt-in regions like me-south-1.
    # PMapper's actual flag is `--include-regions r1 r2 ...` (subcommand-level,
    # NOT top-level `--region` which it doesn't accept).
    #
    # v9.2.0 (P0-2) — bake a safe-list default so pmapper doesn't fail on
    # opt-in regions out of the box. Two engagement runs in a row blew up on
    # `me-south-1` ConnectTimeoutError because the region is enabled per
    # AWS-account but boto3 still attempts to reach STS there with no route.
    # Operators can override either with PMAPPER_REGIONS=...,... or
    # PMAPPER_REGIONS_OVERRIDE_NONE=1 to disable narrowing entirely.
    DEFAULT_PMAPPER_REGIONS = "us-east-1,us-east-2,us-west-1,us-west-2,ap-south-1,ap-southeast-1,ap-southeast-2,ap-northeast-1,eu-west-1,eu-west-2,eu-central-1,eu-north-1,ca-central-1,sa-east-1"
    pmapper_regions = os.environ.get("PMAPPER_REGIONS", "").strip()
    if not pmapper_regions and not os.environ.get("PMAPPER_REGIONS_OVERRIDE_NONE"):
        pmapper_regions = DEFAULT_PMAPPER_REGIONS
    if pmapper_regions:
        regions_list = [r.strip() for r in pmapper_regions.split(",") if r.strip()]
        if regions_list:
            cmd += ["--include-regions", *regions_list]

    env = os.environ.copy()
    # Only suppress user-site for known isolated-venv binaries. A pip --user
    # PMapper install lives in user-site itself, so PYTHONNOUSERSITE would
    # break its imports.
    is_isolated = (
        os.environ.get("PMAPPER_BIN") == binary
        or any(str(c) == binary for c in _PMAPPER_PATH_CANDIDATES)
    )
    if is_isolated:
        env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONWARNINGS"] = "ignore::DeprecationWarning"

    # Launch via procutil (os.posix_spawn): cloud_hunt does in-process boto3/HTTPS
    # region discovery before this runner, loading Apple's Network.framework, so a
    # raw subprocess.run fork()+exec SIGSEGVs (rc=-11) the pmapper child on macOS.
    # Pass env= (PYTHONNOUSERSITE/region narrowing) through; keep streams separate so
    # stdout.log / stderr.log and the distutils-noise filter stay byte-identical.
    res = procutil.run_capture(cmd, timeout=timeout, env=env, shell=False, merge_stderr=False)
    if res["timed_out"]:
        (out_dir / "error.log").write_text(
            f"pmapper timed out after {timeout}s\nbinary: {binary}\n"
        )
        raise RuntimeError(f"pmapper timed out after {timeout}s; see {out_dir / 'error.log'}")
    stdout, stderr, rc = res["stdout"], res["stderr"], res["returncode"]
    (out_dir / "stdout.log").write_text(stdout or "")
    (out_dir / "stderr.log").write_text(stderr or "")

    if rc != 0:
        clean_stderr = "\n".join(
            l for l in (stderr or "").splitlines()
            if "_distutils_hack" not in l
            and "distutils-precedence" not in l
            and l.strip()
        )
        (out_dir / "error.log").write_text(
            f"pmapper exited {rc}\nbinary: {binary}\n\n"
            f"stdout:\n{stdout}\n\nstderr (cleaned):\n{clean_stderr}\n"
        )
        raise RuntimeError(f"pmapper exited {rc}; see {out_dir / 'error.log'}")

    storage_root = Path(env.get("PMAPPER_STORAGE") or (Path.home() / ".principalmapper"))
    src_dir = storage_root / profile.account_id
    if not (src_dir / "metadata.json").exists():
        # PMapper 1.1.5 uses platform-specific app-data directories via the appdirs
        # library. macOS resolves to ~/Library/Application Support/com.nccgroup.principalmapper/;
        # Linux is XDG_DATA_HOME (typically ~/.local/share/principalmapper). Linux
        # legacy is ~/.principalmapper. Cover all of them.
        home = Path.home()
        candidates = [
            home / ".principalmapper" / profile.account_id,
            home / "Library" / "Application Support" / "com.nccgroup.principalmapper" / profile.account_id,
            home / ".local" / "share" / "principalmapper" / profile.account_id,
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
    # Staleness gate: the resolved storage graph MUST have been (re)written by
    # THIS run. PMapper reuses ~/.principalmapper/<account_id> across runs and
    # --refresh does not clear it, so a metadata.json older than start_ts means
    # `graph create` produced no fresh graph and we'd be copying last run's
    # privesc paths. Allow a small clock-skew slack (filesystem mtime can lag the
    # measured start by sub-second on some platforms).
    _MTIME_SLACK = 2.0  # seconds
    meta_mtime = (src_dir / "metadata.json").stat().st_mtime
    if meta_mtime < (start_ts - _MTIME_SLACK):
        (out_dir / "error.log").write_text(
            f"pmapper graph storage is stale\nbinary: {binary}\n"
            f"storage: {src_dir}\n"
            f"metadata.json mtime={meta_mtime} < run start={start_ts}\n"
            "PMapper did not write a fresh graph for this account this run; refusing "
            "to copy a prior run's graph. Clear the per-account storage "
            f"({src_dir}) or set PMAPPER_STORAGE to a clean directory and re-run.\n"
        )
        raise RuntimeError(
            f"pmapper graph at {src_dir} predates this run (mtime {meta_mtime} < "
            f"start {start_ts}); refusing to report a stale IAM graph. "
            f"See {out_dir / 'error.log'}"
        )
    dst_dir = out_dir / "pmapper-storage"
    dst_dir.mkdir(parents=True, exist_ok=True)
    (dst_dir / "metadata.json").write_text((src_dir / "metadata.json").read_text())
    (dst_dir / "graph").mkdir(exist_ok=True)
    (dst_dir / "graph" / "nodes.json").write_text((src_dir / "graph" / "nodes.json").read_text())
    (dst_dir / "graph" / "edges.json").write_text((src_dir / "graph" / "edges.json").read_text())
    return dst_dir

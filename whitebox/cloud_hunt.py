from __future__ import annotations
import argparse
import sys
from pathlib import Path
from whitebox.orchestrator import run_for_profile
from whitebox.config_lock import write_session_lock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cloud_hunt",
                                     description="Vikramaditya whitebox AWS audit")
    parser.add_argument("--profile", action="append", required=False,
                        help="AWS profile name (repeatable)")
    parser.add_argument("--session-dir", default="recon/cloud-only/sessions/default",
                        help="Session output directory")
    parser.add_argument("--refresh", action="store_true",
                        help="Bust phase cache and re-run all phases")
    parser.add_argument("--allowlist", action="append", default=None,
                        help="Authorized in-scope domain (repeatable; required unless --no-scope-lock)")
    parser.add_argument("--no-scope-lock", action="store_true",
                        help="Disable Route53 scope-lock (audit ALL public zones in the account)")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if not args.profile:
        parser.print_help(sys.stderr)
        return 2

    # Scope-lock guard: must be explicit either way
    if not args.allowlist and not args.no_scope_lock:
        print(
            "error: --allowlist (repeatable) or --no-scope-lock is REQUIRED.\n"
            "  Pass each authorized in-scope domain via --allowlist (e.g. --allowlist example-prod.invalid),\n"
            "  or explicitly disable scope-locking with --no-scope-lock.",
            file=sys.stderr,
        )
        return 2

    allowlist = ["*"] if args.no_scope_lock else args.allowlist

    # P1-FIX-3 — write a deterministic config.lock.json so two runs are
    # diffable for tool/wordlist/env drift.
    try:
        write_session_lock(args.session_dir, args=args)
    except Exception:
        pass

    rc = 0
    for prof in args.profile:
        rc |= run_for_profile(profile_name=prof,
                              session_dir=Path(args.session_dir),
                              refresh=args.refresh,
                              authorized_allowlist=allowlist)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

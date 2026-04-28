from __future__ import annotations
import argparse
import sys
from pathlib import Path
from whitebox.orchestrator import run_for_profile


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
                        help="Authorized in-scope domain (repeatable). Use '*' to disable scope-lock.")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if not args.profile:
        parser.print_help(sys.stderr)
        return 2

    rc = 0
    for prof in args.profile:
        rc |= run_for_profile(profile_name=prof,
                              session_dir=Path(args.session_dir),
                              refresh=args.refresh,
                              authorized_allowlist=args.allowlist)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
graphql_audit.py — GraphQL DAST bundle (v9.13.0)

Wraps graphw00f (engine fingerprinting), Clairvoyance (introspection-
disabled schema reconstruction via error-message brute-force), and InQL
(auto-query generation + auth/IDOR finder) into a single Vikramaditya-
shaped session.

Output: findings/<host>/graphql/{graphw00f.txt, clairvoyance_schema.json,
inql_queries/, summary.json}

Usage:
    # Full pipeline against an exposed GraphQL endpoint
    python3 graphql_audit.py --url https://api.client.com/graphql

    # Schema reconstruction when introspection is OFF
    python3 graphql_audit.py --url URL --clairvoyance --wordlist words.txt

    # Auth-required endpoint
    python3 graphql_audit.py --url URL --header "Authorization: Bearer ..."

Tool requirements:
    graphw00f     — pip install graphw00f
    clairvoyance  — pip install clairvoyance
    InQL CLI      — pip install inql  (Burp BApp also exists)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list[str], log_path: Path, timeout: int = 600) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] $ {' '.join(cmd)}")
    try:
        with open(log_path, "w") as fh:
            fh.write(f"# {' '.join(cmd)}\n# {datetime.now().isoformat(timespec='seconds')}\n\n")
            fh.flush()
            return subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                  timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return 124
    except FileNotFoundError:
        return 127


def run_graphw00f(url: str, headers: list[str], out_dir: Path) -> None:
    """graphw00f — fingerprint the GraphQL engine (Apollo, Hasura, Yoga, etc.).

    Different engines have different default-on misconfigs (e.g. Hasura's
    JWT claim-injection, Apollo's introspection always-on by default in
    older versions). The fingerprint determines which deeper checks fire.
    """
    if not _which("graphw00f"):
        print("[!] graphw00f not found — pip install graphw00f")
        return
    cmd = ["graphw00f", "-t", url, "-d", "-o", str(out_dir / "graphw00f.txt")]
    for h in headers:
        cmd += ["-H", h]
    _run(cmd, out_dir / "graphw00f.log", timeout=300)


def run_clairvoyance(url: str, headers: list[str], wordlist: str | None,
                     out_dir: Path) -> None:
    """Clairvoyance — reconstruct the schema when introspection is disabled
    by brute-forcing field names against error messages."""
    if not _which("clairvoyance"):
        print("[!] clairvoyance not found — pip install clairvoyance")
        return
    out_json = out_dir / "clairvoyance_schema.json"
    cmd = ["clairvoyance", "-o", str(out_json), url]
    for h in headers:
        cmd += ["-H", h]
    if wordlist and os.path.isfile(wordlist):
        cmd += ["-w", wordlist]
    _run(cmd, out_dir / "clairvoyance.log", timeout=1200)


def run_inql(url: str, headers: list[str], out_dir: Path) -> None:
    """InQL — auto-generate queries from the schema; surface auth/IDOR on
    mutations the operator wouldn't otherwise know existed.

    The CLI version writes one .gql file per detected query/mutation; we
    capture them all under inql_queries/. The Burp BApp does interactive
    fuzzing; outside the scope of this wrapper.
    """
    if not _which("inql"):
        print("[!] inql not found — pip install inql")
        return
    inql_dir = out_dir / "inql_queries"
    inql_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["inql", "-t", url, "-o", str(inql_dir)]
    for h in headers:
        cmd += ["-H", h]
    _run(cmd, out_dir / "inql.log", timeout=600)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="graphql_audit",
                                 description="Vikramaditya GraphQL DAST bundle")
    ap.add_argument("--url", required=True, help="GraphQL endpoint URL")
    ap.add_argument("--header", action="append", default=[],
                    help="HTTP header (repeatable, format 'Name: value')")
    ap.add_argument("--clairvoyance", action="store_true",
                    help="Run Clairvoyance schema reconstruction (slow)")
    ap.add_argument("--wordlist", default=None,
                    help="Wordlist for Clairvoyance brute-force")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    label = (urlparse(args.url).netloc or "graphql").replace("/", "_")
    out_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / label / "graphql"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] GraphQL audit — {args.url}")
    print(f"[*] Output: {out_dir}")

    run_graphw00f(args.url, args.header, out_dir)
    if args.clairvoyance:
        run_clairvoyance(args.url, args.header, args.wordlist, out_dir)
    run_inql(args.url, args.header, out_dir)

    summary = {
        "tool": "vikramaditya.graphql_audit",
        "version": "9.13.0",
        "url": args.url,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
sast_audit.py — Deep SAST beyond Semgrep (v9.14.0)

We have Semgrep for pattern-based static analysis; v9.14.0 adds
CodeQL (semantic taint-tracking, 88% accuracy / 5% FP per recent
benchmarks) and Bearer (privacy/data-flow focused for PII leaks
to logs/external services — useful for DPDP/GDPR scope).

Output: findings/<repo>/sast/{codeql_<lang>.sarif, bearer.json,
summary.json}

Usage:
    # CodeQL on a Python repo
    python3 sast_audit.py --path repo/ --language python

    # CodeQL on multiple languages
    python3 sast_audit.py --path repo/ --language javascript,python

    # Bearer-only (PII flow analysis)
    python3 sast_audit.py --path repo/ --tools bearer

    # Combined CodeQL + Bearer
    python3 sast_audit.py --path repo/ --language go --tools all

Tool requirements:
    CodeQL  — github.com/github/codeql-cli-binaries (download release for OS)
              brew install codeql  (on macOS)
    Bearer  — `brew install bearer/tap/bearer` or curl install script
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

REPO = Path(__file__).resolve().parent

CODEQL_LANG_PACKS = {
    "python": "codeql/python-queries",
    "javascript": "codeql/javascript-queries",
    "typescript": "codeql/javascript-queries",
    "java": "codeql/java-queries",
    "kotlin": "codeql/java-queries",
    "go": "codeql/go-queries",
    "ruby": "codeql/ruby-queries",
    "csharp": "codeql/csharp-queries",
    "cpp": "codeql/cpp-queries",
    "swift": "codeql/swift-queries",
}


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list[str], log_path: Path, timeout: int = 1800) -> int:
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


def run_codeql(path: str, languages: list[str], out_dir: Path) -> None:
    """CodeQL — semantic taint-tracking SAST."""
    if not _which("codeql"):
        print("[!] codeql not found.\n"
              "    macOS: brew install codeql\n"
              "    Linux: download https://github.com/github/codeql-cli-binaries/releases")
        return
    cq_dir = out_dir / "codeql"
    cq_dir.mkdir(parents=True, exist_ok=True)
    for lang in languages:
        if lang not in CODEQL_LANG_PACKS:
            print(f"[!] unsupported CodeQL language: {lang}")
            continue
        db_dir = cq_dir / f"db_{lang}"
        sarif = cq_dir / f"results_{lang}.sarif"
        # Build the database (autobuild for compiled languages)
        rc = _run(["codeql", "database", "create", str(db_dir),
                   "--language", lang, "--source-root", path,
                   "--overwrite"],
                  cq_dir / f"db_{lang}.log", timeout=2400)
        if rc != 0:
            continue
        # Run the standard query suite
        _run(["codeql", "database", "analyze", str(db_dir),
              CODEQL_LANG_PACKS[lang],
              "--format=sarif-latest", "--output", str(sarif),
              "--threads=4"],
             cq_dir / f"analyze_{lang}.log", timeout=3600)


def run_bearer(path: str, out_dir: Path) -> None:
    """Bearer — privacy/data-flow analysis. Finds PII flowing to logs,
    third-party services, etc. Useful for DPDP/GDPR engagements."""
    if not _which("bearer"):
        print("[!] bearer not found — brew install bearer/tap/bearer")
        return
    bearer_dir = out_dir / "bearer"
    bearer_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["bearer", "scan", path,
           "--format", "json",
           "--output", str(bearer_dir / "bearer.json"),
           "--quiet", "--exit-code", "0"]
    _run(cmd, bearer_dir / "bearer.log", timeout=1800)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sast_audit",
                                 description="Vikramaditya deep SAST (CodeQL + Bearer)")
    ap.add_argument("--path", required=True, help="Source root directory")
    ap.add_argument("--language", default="",
                    help="CSV of CodeQL languages (python,javascript,go,...)")
    ap.add_argument("--tools", default="all",
                    help="all | codeql | bearer")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    label = Path(args.path).resolve().name or "sast"
    out_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / label / "sast"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] SAST — path={args.path}  output={out_dir}")

    tools = {t.strip() for t in args.tools.split(",")}
    languages = [l.strip().lower() for l in args.language.split(",") if l.strip()]
    if (("all" in tools) or ("codeql" in tools)) and languages:
        run_codeql(args.path, languages, out_dir)
    if ("all" in tools) or ("bearer" in tools):
        run_bearer(args.path, out_dir)

    summary = {
        "tool": "vikramaditya.sast_audit",
        "version": "9.14.0",
        "path": args.path,
        "languages": languages,
        "tools": sorted(tools),
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

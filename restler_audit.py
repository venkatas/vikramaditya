#!/usr/bin/env python3
"""
restler_audit.py — Stateful REST API fuzzer (v9.12.0)

Wraps Microsoft Research's RESTler — the only OSS stateful REST fuzzer
that infers producer-consumer dependencies from an OpenAPI/Swagger spec
and reaches deep states (e.g. "create user → login as user → access
admin API as that user"). Complements (does not duplicate) schemathesis
which is property-based but stateless.

Output: findings/<host>/restler/{Compile/, Test/, Fuzz/, results/, summary.json}

Usage:
    # Full pipeline against an OpenAPI spec
    python3 restler_audit.py --spec openapi.json --base-url https://api.client.com
    python3 restler_audit.py --spec swagger.yaml --base-url URL --token "Bearer ..." --time-budget 4

    # Compile-only (validate the spec produces a usable grammar)
    python3 restler_audit.py --spec openapi.json --mode compile

    # Test stage only (covers each endpoint once with valid sequences)
    python3 restler_audit.py --spec openapi.json --base-url URL --mode test

    # Fuzz stage (smart payload mutation; long-running)
    python3 restler_audit.py --spec openapi.json --base-url URL --mode fuzz \\
        --time-budget 8

Tool requirements:
    Docker      — `docker pull mcr.microsoft.com/restlerfuzzer/restler:latest`
    OR
    Local build — git clone https://github.com/microsoft/restler-fuzzer
                  cd restler-fuzzer && python3 build-restler.py --dest_dir restler_bin
                  export RESTLER_BIN=$PWD/restler_bin/restler/Restler
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
RESTLER_DOCKER = "mcr.microsoft.com/restlerfuzzer/restler:latest"


def _which(name: str) -> str | None:
    return shutil.which(name)


def _resolve_restler() -> tuple[str, list[str]]:
    """Returns ('local'|'docker'|'none', [cmd-prefix-tokens])."""
    bin_path = os.environ.get("RESTLER_BIN")
    if bin_path and os.path.isfile(bin_path):
        return "local", [bin_path]
    if _which("docker"):
        return "docker", []
    return "none", []


def _run_restler(stage_args: list[str], spec_dir: str, work_dir: Path,
                 timeout: int) -> int:
    """Run a RESTler stage either via local binary or Docker."""
    mode, prefix = _resolve_restler()
    if mode == "none":
        print("[!] RESTler not found.\n"
              "    Local: clone https://github.com/microsoft/restler-fuzzer + build, export RESTLER_BIN\n"
              "    Docker: `docker pull " + RESTLER_DOCKER + "`")
        return 127
    work_dir.mkdir(parents=True, exist_ok=True)
    if mode == "local":
        cmd = prefix + stage_args
        env = os.environ.copy()
    else:
        cmd = ["docker", "run", "--rm",
               "-v", f"{os.path.abspath(spec_dir)}:/spec",
               "-v", f"{work_dir.resolve()}:/work",
               RESTLER_DOCKER] + stage_args
        env = os.environ.copy()
    print(f"[*] $ {' '.join(cmd)}")
    log = work_dir / f"stage_{stage_args[0] if stage_args else 'unknown'}.log"
    with open(log, "w") as fh:
        fh.write(f"# {' '.join(cmd)}\n# {datetime.now().isoformat(timespec='seconds')}\n\n")
        fh.flush()
        try:
            return subprocess.run(cmd, cwd=str(work_dir), env=env,
                                  stdout=fh, stderr=subprocess.STDOUT,
                                  timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            return 124


def compile_grammar(spec: str, work_dir: Path) -> int:
    """RESTler 'compile' — turn OpenAPI into a fuzzing grammar."""
    return _run_restler(["compile", "--api_spec", spec],
                        spec_dir=os.path.dirname(os.path.abspath(spec)),
                        work_dir=work_dir / "Compile", timeout=600)


def test_stage(work_dir: Path, base_url: str, token: str | None) -> int:
    """RESTler 'test' — smoke test each request once with valid sequences."""
    args = ["test", "--grammar_file",
            str(work_dir / "Compile" / "grammar.py"),
            "--dictionary_file",
            str(work_dir / "Compile" / "dict.json"),
            "--target_ip", urlparse(base_url).hostname or "",
            "--target_port", str(urlparse(base_url).port or
                                 (443 if base_url.startswith("https") else 80)),
            "--use_ssl" if base_url.startswith("https") else "--no_ssl"]
    if token:
        args += ["--token_refresh_cmd",
                 f"echo '{token}'", "--token_refresh_interval", "999999"]
    return _run_restler(args, spec_dir=str(work_dir / "Compile"),
                        work_dir=work_dir / "Test", timeout=1800)


def fuzz_stage(work_dir: Path, base_url: str, token: str | None,
               time_budget_h: float) -> int:
    """RESTler 'fuzz' — smart payload mutation; long-running."""
    args = ["fuzz", "--grammar_file",
            str(work_dir / "Compile" / "grammar.py"),
            "--dictionary_file",
            str(work_dir / "Compile" / "dict.json"),
            "--target_ip", urlparse(base_url).hostname or "",
            "--target_port", str(urlparse(base_url).port or
                                 (443 if base_url.startswith("https") else 80)),
            "--use_ssl" if base_url.startswith("https") else "--no_ssl",
            "--time_budget", str(time_budget_h)]
    if token:
        args += ["--token_refresh_cmd",
                 f"echo '{token}'", "--token_refresh_interval", "999999"]
    return _run_restler(args, spec_dir=str(work_dir / "Compile"),
                        work_dir=work_dir / "Fuzz",
                        timeout=int(time_budget_h * 3600 + 600))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="restler_audit",
                                 description="Vikramaditya RESTler stateful REST fuzzer")
    ap.add_argument("--spec", required=True, help="Path to OpenAPI/Swagger spec")
    ap.add_argument("--base-url", default="", help="Target base URL for test/fuzz")
    ap.add_argument("--token", default=None, help="Static auth token (optional)")
    ap.add_argument("--mode", default="all",
                    choices=["compile", "test", "fuzz", "all"])
    ap.add_argument("--time-budget", type=float, default=2.0,
                    help="Fuzz time budget in hours (default 2)")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    label = (urlparse(args.base_url).netloc or "restler").replace("/", "_")
    work_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / label / "restler"
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] RESTler — spec={args.spec}  base={args.base_url}  mode={args.mode}")
    print(f"[*] Output: {work_dir}")

    if args.mode in ("compile", "all"):
        rc = compile_grammar(args.spec, work_dir)
        if rc != 0:
            print("[!] compile failed; aborting later stages")
            return rc
    if args.mode in ("test", "all") and args.base_url:
        test_stage(work_dir, args.base_url, args.token)
    if args.mode in ("fuzz", "all") and args.base_url:
        fuzz_stage(work_dir, args.base_url, args.token, args.time_budget)

    summary = {
        "tool": "vikramaditya.restler_audit",
        "version": "9.12.0",
        "spec": args.spec,
        "base_url": args.base_url,
        "mode": args.mode,
        "time_budget_h": args.time_budget,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (work_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {work_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

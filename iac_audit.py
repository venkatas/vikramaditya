#!/usr/bin/env python3
"""
iac_audit.py — Infrastructure-as-Code dedicated scanner (v9.9.0)

Wraps Checkov (1,000+ policies, graph-based cross-resource) and KICS
(2,400+ Rego queries, broadest format coverage). Complements
`k8s_audit.py --iac` (Trivy config) with deeper, policy-driven scans.

Use Checkov as the primary (graph + cross-resource analysis) and KICS
as a second-pass with a different rule philosophy — combined they catch
~95% of IaC-class findings clients want listed in the report.

Output: findings/<label>/iac/{checkov.json, kics.json, summary.json}

Usage:
    python3 iac_audit.py --path path/to/terraform
    python3 iac_audit.py --path path/to/repo --frameworks terraform,kubernetes,helm
    python3 iac_audit.py --path . --tool checkov  # single scanner

Tool requirements:
    Checkov  — `pip install checkov`
    KICS     — `brew install kics`  or  Docker
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


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list[str], log_path: Path, timeout: int = 1200) -> int:
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


def run_checkov(path: str, frameworks: list[str], out_dir: Path) -> None:
    """Checkov — graph-based IaC policy engine (Bridgecrew/Prisma Cloud)."""
    if not _which("checkov"):
        print("[!] checkov not found — pip install checkov")
        return
    out_json = out_dir / "checkov.json"
    cmd = ["checkov", "-d", path, "-o", "json",
           "--output-file-path", str(out_json),
           "--soft-fail",   # never propagate exit code; we report, not gate
           "--quiet"]
    if frameworks:
        cmd += ["--framework", ",".join(frameworks)]
    _run(cmd, out_dir / "checkov.log", timeout=1800)


def run_kics(path: str, out_dir: Path) -> None:
    """KICS — Rego-based IaC scanner (Checkmarx). Falls back to Docker
    invocation if the native binary isn't installed."""
    kics_dir = out_dir / "kics"
    kics_dir.mkdir(parents=True, exist_ok=True)
    if _which("kics"):
        cmd = ["kics", "scan", "-p", path,
               "-o", str(kics_dir), "--report-formats", "json",
               "--silent"]
        _run(cmd, out_dir / "kics.log", timeout=1800)
        return
    if _which("docker"):
        cmd = ["docker", "run", "--rm",
               "-v", f"{os.path.abspath(path)}:/path",
               "-v", f"{kics_dir.resolve()}:/output",
               "checkmarx/kics:latest", "scan",
               "-p", "/path", "-o", "/output",
               "--report-formats", "json", "--silent"]
        _run(cmd, out_dir / "kics.log", timeout=1800)
        return
    print("[!] kics not found — brew install kics  OR  ensure Docker is available")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="iac_audit",
                                 description="Vikramaditya IaC scanner (Checkov + KICS)")
    ap.add_argument("--path", required=True, help="IaC root directory")
    ap.add_argument("--frameworks", default="",
                    help="Checkov frameworks csv: terraform,kubernetes,helm,cloudformation,...")
    ap.add_argument("--tool", default="all", choices=["all", "checkov", "kics"])
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    label = Path(args.path).resolve().name or "iac"
    out_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / label / "iac"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] IaC audit — path={args.path}  output={out_dir}")

    frameworks = [f.strip() for f in args.frameworks.split(",") if f.strip()]
    if args.tool in ("all", "checkov"):
        run_checkov(args.path, frameworks, out_dir)
    if args.tool in ("all", "kics"):
        run_kics(args.path, out_dir)

    summary = {
        "tool": "vikramaditya.iac_audit",
        "version": "9.9.0",
        "path": args.path,
        "frameworks": frameworks,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

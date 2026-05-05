#!/usr/bin/env python3
"""
llm_hunt.py — LLM red-teaming engine (v9.10.0)

Wraps Garak (NVIDIA, "nmap for LLMs"), PyRIT (Microsoft AI Red Team),
and Promptfoo (used by OpenAI + Anthropic internally) into a single
Vikramaditya-shaped session. Emerging client requirement — every B2B
SaaS now ships AI features and bug-bounty programs accept LLM findings.

Use Garak for breadth (37+ probes), PyRIT for depth (multi-turn
adaptive attacks like Crescendo / TAP), Promptfoo for repeatable
regression in CI.

Output: findings/<label>/llm/{garak/, pyrit/, promptfoo/, summary.json}

Usage:
    # Single endpoint — broad sweep
    python3 llm_hunt.py --target-url https://api.client.com/chat \\
        --auth-header 'Authorization: Bearer $TOK' --probes all

    # Specific probe set (jailbreak only)
    python3 llm_hunt.py --target-url URL --probes encoding,promptinject

    # Promptfoo-only (config-file-driven)
    python3 llm_hunt.py --promptfoo-config promptfoo.yaml --tools promptfoo

Tool requirements:
    Garak    — pip install garak
    PyRIT    — pip install pyrit (heavy; optional)
    Promptfoo — npm install -g promptfoo
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


def _run(cmd: list[str], log_path: Path, env: dict | None = None,
         timeout: int = 1800) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] $ {' '.join(cmd)}")
    try:
        with open(log_path, "w") as fh:
            fh.write(f"# {' '.join(cmd)}\n# {datetime.now().isoformat(timespec='seconds')}\n\n")
            fh.flush()
            return subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                  env={**os.environ, **(env or {})},
                                  timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return 124
    except FileNotFoundError:
        return 127


def run_garak(target_url: str, auth_header: str, probes: str, out_dir: Path) -> None:
    """Garak — 37+ probe modules for jailbreak/leakage/encoding bypass."""
    if not _which("garak"):
        print("[!] garak not found — pip install garak")
        return
    garak_dir = out_dir / "garak"
    garak_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["garak", "--model_type", "rest",
           "--model_name", target_url,
           "--report_prefix", str(garak_dir / "report")]
    if probes and probes != "all":
        cmd += ["--probes", probes]
    env = {"GARAK_REST_AUTH": auth_header} if auth_header else {}
    _run(cmd, garak_dir / "garak.log", env=env, timeout=3600)


def run_pyrit(target_url: str, out_dir: Path) -> None:
    """PyRIT — Microsoft AI Red Team multi-turn attacks (Crescendo / TAP).

    PyRIT is config-driven via Python orchestrators; we drop a stub
    config and invoke `pyrit run` if installed. For full multi-turn the
    operator should write a dedicated orchestrator script.
    """
    if not _which("pyrit"):
        print("[!] pyrit not found — pip install pyrit  (heavy install)")
        return
    pyrit_dir = out_dir / "pyrit"
    pyrit_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] PyRIT placeholder — write a dedicated orchestrator at {pyrit_dir / 'orchestrator.py'}")
    print("    See https://github.com/Azure/PyRIT for sample multi-turn Crescendo / TAP recipes")


def run_promptfoo(config_path: str, out_dir: Path) -> None:
    """Promptfoo — YAML config + 50+ vuln types, CI/CD-native."""
    if not _which("promptfoo"):
        print("[!] promptfoo not found — npm install -g promptfoo")
        return
    pf_dir = out_dir / "promptfoo"
    pf_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["promptfoo", "redteam", "run",
           "--config", config_path,
           "--output", str(pf_dir / "results.json")]
    _run(cmd, pf_dir / "promptfoo.log", timeout=3600)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="llm_hunt",
                                 description="Vikramaditya LLM red-teaming engine")
    ap.add_argument("--target-url", help="LLM endpoint URL (REST)")
    ap.add_argument("--auth-header", default="",
                    help="Auth header for the LLM endpoint, e.g. 'Authorization: Bearer ...'")
    ap.add_argument("--probes", default="all",
                    help="Garak probes csv (all|encoding|promptinject|continuation|...)")
    ap.add_argument("--promptfoo-config", default="",
                    help="Path to promptfoo redteam YAML config")
    ap.add_argument("--tools", default="all",
                    help="Subset to run: all | garak | pyrit | promptfoo")
    ap.add_argument("--label", default="llm-target",
                    help="Output label (default llm-target)")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    out_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / args.label / "llm"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] LLM red-team — output: {out_dir}")

    tools = {t.strip() for t in args.tools.split(",")}
    if (("all" in tools) or ("garak" in tools)) and args.target_url:
        run_garak(args.target_url, args.auth_header, args.probes, out_dir)
    if (("all" in tools) or ("pyrit" in tools)) and args.target_url:
        run_pyrit(args.target_url, out_dir)
    if (("all" in tools) or ("promptfoo" in tools)) and args.promptfoo_config:
        run_promptfoo(args.promptfoo_config, out_dir)

    summary = {
        "tool": "vikramaditya.llm_hunt",
        "version": "9.10.0",
        "target_url": args.target_url,
        "probes": args.probes,
        "tools": sorted(tools),
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

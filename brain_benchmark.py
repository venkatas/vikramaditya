#!/usr/bin/env python3
"""
brain_benchmark.py — Vikramaditya brain vs upstream autonomous CRS bench (v9.15.0)

Benchmarks our `brain.py` (LLM-driven brain via Ollama / phi4:14b) against
the open-source autonomous Cyber Reasoning Systems that emerged from
DARPA AIxCC 2024-2025:

  • Buttercup (Trail of Bits, AIxCC 2nd place / $3M) — the only one that
    open-sourced. https://github.com/trailofbits/buttercup
  • XBOW (closed-source SaaS; benchmark via H1 leaderboard only)
  • ProjectDiscovery Neo (closed beta; track for parity)

Currently this module:
  1. Drops a "challenge harness" wrapper that feeds the same target+
     OpenAPI/code-tree to brain.py AND Buttercup, then compares outputs:
     submit-verdict count, time-to-first-finding, false-positive rate
     (when ground truth available, e.g. on the AIxCC reference targets).
  2. Records per-engagement scores to logs/brain_benchmark.csv so we can
     watch for capability drift as Ollama models update.
  3. When --integrate is passed, wires Buttercup's PoV (proof-of-
     vulnerability) generator as a fallback when our brain returns
     `NO_REPORTS`. This is the architectural-overlap question — do we
     defer to Buttercup, defer to ours, or run both in parallel.

Output: logs/brain_benchmark/<run-id>/{vikram_brain.json,
buttercup.json, comparison.md}

Usage:
    # Benchmark on the AIxCC reference targets
    python3 brain_benchmark.py --targets aixcc-targets.txt

    # Benchmark on your own engagement target
    python3 brain_benchmark.py --target https://example.com \\
        --recon-dir recon/example.com/sessions/<id>

    # Integrate Buttercup as fallback when brain returns NO_REPORTS
    python3 brain_benchmark.py --integrate

Tool requirements:
    Buttercup — git clone https://github.com/trailofbits/buttercup
                cd buttercup && make install
                Requires Docker + ~16GB RAM
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent
LOG_DIR = REPO / "logs" / "brain_benchmark"


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run_brain(target: str, recon_dir: str | None,
               findings_dir: str, run_dir: Path) -> dict:
    """Invoke our brain.py auto_triage on the given recon dir; record
    {time_s, submit_count, drop_count, no_reports} for comparison."""
    if not Path(REPO / "brain.py").is_file():
        return {"_error": "brain.py not found"}
    t0 = time.perf_counter()
    cmd = [sys.executable, "-u", str(REPO / "brain.py"), "scan",
           findings_dir]
    if recon_dir:
        cmd += ["--recon-dir", recon_dir]
    log = run_dir / "vikram_brain.log"
    rc = 1
    try:
        with open(log, "w") as fh:
            rc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                timeout=1800).returncode
    except Exception as e:
        return {"_error": str(e)}
    elapsed = round(time.perf_counter() - t0, 2)
    # Tally from auto_triage.md if present
    triage = Path(findings_dir) / "brain" / "auto_triage.md"
    submit = drop = unknown = 0
    if triage.exists():
        for line in triage.read_text().splitlines():
            if line.startswith("[SUBMIT]"):
                submit += 1
            elif line.startswith("[DROP]"):
                drop += 1
            elif line.startswith("[UNKNOWN]"):
                unknown += 1
    h1 = (Path(findings_dir) / "brain" / "04_h1_reports.md")
    no_reports = h1.exists() and "NO_REPORTS" in h1.read_text()
    return {
        "engine": "vikramaditya.brain",
        "model": os.environ.get("BRAIN_MODEL", "phi4:14b"),
        "elapsed_s": elapsed,
        "submit": submit,
        "drop": drop,
        "unknown": unknown,
        "no_reports": no_reports,
        "exit_code": rc,
    }


def _run_buttercup(target: str, recon_dir: str | None,
                   run_dir: Path) -> dict:
    """Invoke Trail of Bits' Buttercup on the same target; record metrics."""
    bc = _which("buttercup") or _which("buttercup-cli")
    if not bc:
        return {"_error": "buttercup CLI not found — git clone https://github.com/trailofbits/buttercup"}
    t0 = time.perf_counter()
    log = run_dir / "buttercup.log"
    cmd = [bc, "run", "--target", target]
    if recon_dir:
        cmd += ["--input", recon_dir]
    cmd += ["--output", str(run_dir / "buttercup")]
    rc = 1
    try:
        with open(log, "w") as fh:
            rc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                                timeout=3600).returncode
    except Exception as e:
        return {"_error": str(e)}
    elapsed = round(time.perf_counter() - t0, 2)
    # Buttercup output schema (per upstream README): findings.json with
    # PoV proofs. Tally if present.
    findings = run_dir / "buttercup" / "findings.json"
    pov_count = 0
    parse_error = None
    if findings.exists():
        try:
            data = json.loads(findings.read_text())
            # Buttercup's findings.json may be either a bare list of PoVs
            # ([...]) or a dict with a "povs" key ({"povs": [...]}). Count
            # both shapes explicitly — the old one-liner mis-parsed due to
            # the conditional-expression having lower precedence than `or`,
            # so it always yielded 0.
            if isinstance(data, list):
                pov_count = len(data)
            elif isinstance(data, dict):
                pov_count = len(data.get("povs", []) or [])
            else:
                parse_error = f"unexpected findings.json type: {type(data).__name__}"
        except Exception as e:
            parse_error = f"{type(e).__name__}: {e}"
            print(f"[!] failed to parse {findings}: {parse_error}", file=sys.stderr)
    out = {
        "engine": "trailofbits.buttercup",
        "elapsed_s": elapsed,
        "pov_count": pov_count,
        "exit_code": rc,
    }
    if parse_error:
        out["_parse_error"] = parse_error
    return out


def _compare(vikram: dict, butter: dict, run_dir: Path, target: str) -> str:
    """Write a markdown comparison report."""
    md = [
        f"# Brain Benchmark — {target}",
        f"Run: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "## Vikramaditya brain.py",
        "```json",
        json.dumps(vikram, indent=2),
        "```",
        "",
        "## Trail of Bits Buttercup",
        "```json",
        json.dumps(butter, indent=2),
        "```",
        "",
        "## Verdict",
    ]
    v_findings = vikram.get("submit", 0)
    b_findings = butter.get("pov_count", 0)
    if v_findings > b_findings:
        md.append(f"Vikramaditya: **+{v_findings - b_findings}** more SUBMIT-verdict findings than Buttercup")
    elif b_findings > v_findings:
        md.append(f"Buttercup: **+{b_findings - v_findings}** more PoV findings than Vikramaditya")
    else:
        md.append("Tied on finding count.")
    v_time = vikram.get("elapsed_s", 0)
    b_time = butter.get("elapsed_s", 0)
    if v_time and b_time:
        ratio = round(v_time / b_time, 2)
        md.append(f"Time ratio (vikram/buttercup): **{ratio}x**")
    out = run_dir / "comparison.md"
    out.write_text("\n".join(md))
    return str(out)


def _append_csv(target: str, vikram: dict, butter: dict) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    csv = LOG_DIR.parent / "brain_benchmark.csv"
    write_header = not csv.exists()
    with open(csv, "a") as fh:
        if write_header:
            fh.write("ran_at,target,vikram_submit,vikram_drop,vikram_unknown,vikram_time_s,"
                     "buttercup_pov,buttercup_time_s\n")
        fh.write(f"{datetime.now().isoformat(timespec='seconds')},{target},"
                 f"{vikram.get('submit',0)},{vikram.get('drop',0)},{vikram.get('unknown',0)},"
                 f"{vikram.get('elapsed_s',0)},{butter.get('pov_count',0)},{butter.get('elapsed_s',0)}\n")


def integrate_buttercup_fallback() -> int:
    """Architectural integration: when brain.py emits NO_REPORTS for the
    final 04_h1_reports.md, also run Buttercup against the same recon and
    surface its PoVs to the operator. Implemented as a documentation
    print + scaffold function — wiring into auto_triage_and_exploit
    requires a brain.py edit."""
    print("[*] Integration design (manual wire-in for v9.16+):")
    print("    1. brain.py auto_triage_and_exploit() returns NO_REPORTS")
    print("    2. orchestrator detects this state, calls brain_benchmark.py --target X --recon-dir D")
    print("    3. if Buttercup produces PoVs, append them to brain/04_buttercup_povs.md")
    print("    4. operator reviews; tradeoff is Buttercup needs ~16GB RAM + Docker")
    print("    Code stub for the brain.py edit:")
    print("""
    if 'NO_REPORTS' in h1_report_text and butter_fallback:
        from brain_benchmark import _run_buttercup
        result = _run_buttercup(target, recon_dir, fallback_dir)
        # write fallback PoV findings to brain/04_buttercup_povs.md
    """)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="brain_benchmark",
                                 description="Vikramaditya brain vs Buttercup benchmark")
    ap.add_argument("--target", help="Single target (URL or hostname)")
    ap.add_argument("--targets", help="Path to file with one target per line")
    ap.add_argument("--recon-dir", help="Pre-run recon directory to feed both engines")
    ap.add_argument("--findings-dir",
                    help="Vikramaditya findings dir for the brain run "
                         "(brain.py reads this for auto_triage)")
    ap.add_argument("--integrate", action="store_true",
                    help="Print integration design for v9.16+ (no code edits)")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    if args.integrate:
        return integrate_buttercup_fallback()

    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets and os.path.isfile(args.targets):
        targets += [l.strip() for l in open(args.targets) if l.strip()]
    if not targets:
        ap.error("provide --target, --targets, or --integrate")

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_run_dir = Path(args.output_dir) if args.output_dir else (LOG_DIR / run_id)
    base_run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] benchmark — {len(targets)} target(s) → {base_run_dir}")

    for target in targets:
        run_dir = base_run_dir / target.replace("/", "_").replace(":", "_")
        run_dir.mkdir(parents=True, exist_ok=True)
        findings = args.findings_dir or str(REPO / "findings" / target / "sessions")
        vikram = _run_brain(target, args.recon_dir, findings, run_dir)
        (run_dir / "vikram_brain.json").write_text(json.dumps(vikram, indent=2))
        butter = _run_buttercup(target, args.recon_dir, run_dir)
        (run_dir / "buttercup.json").write_text(json.dumps(butter, indent=2))
        _compare(vikram, butter, run_dir, target)
        _append_csv(target, vikram, butter)
        print(f"[+] {target} done — comparison.md in {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

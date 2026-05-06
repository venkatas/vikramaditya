#!/usr/bin/env python3
"""
brain_model_bench.py — Brain LLM bake-off harness (v9.16.0)

Replays `brain.py scan <findings_dir>` against the SAME pre-computed
findings + recon directory using each candidate Ollama model in turn,
then scores them on:

  • elapsed wall time
  • SUBMIT / DROP / UNKNOWN verdicts in `auto_triage.md`
  • H1 report verdict (NO_REPORTS vs structured report)
  • brain artifact byte sum (proxy for engagement depth)
  • **hallucination rate** — SUBMIT verdicts that target a URL sqlmap
    explicitly tagged `false positive or unexploitable` in
    `sqli/sqlmap_results.txt`

Per-model artifacts are snapshotted under
`logs/brain_model_bench/<run_id>/<model_safe>/brain/` so the operator
can read each model's full reasoning side-by-side.

Final ranking is written to `logs/brain_model_bench/<run_id>/leaderboard.md`
and a one-row-per-model entry is appended to
`logs/brain_model_bench.csv` so capability drift is tracked over time.

This is the v9.1.3 phi4-vs-gemma4 head-to-head pattern, generalised to
N candidates and grounded in sqlmap's own FP labels.

Usage:
    # Required: an already-completed findings dir (e.g. from a recent
    # vikramaditya.py or hunt.py run); the bench replays only the
    # brain stage on top.
    python3 brain_model_bench.py \\
        --findings findings/clientb.com/sessions/20260506_xxx \\
        --recon recon/clientb.com/sessions/20260506_xxx \\
        --models phi4:14b qwen3:14b deepseek-r1:14b xploiter/the-xploiter:latest

    # Default models if --models is omitted:
    python3 brain_model_bench.py --findings <dir> --recon <dir>

    # Watch mode — poll for a runner-completion marker, then auto-fire:
    python3 brain_model_bench.py \\
        --watch-log logs/vikram_clientb_fresh_xxx.log \\
        --watch-pattern '==== END' \\
        --findings-glob 'findings/clientb.com/sessions/2026*' \\
        --recon-glob 'recon/clientb.com/sessions/2026*'
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent
LOG_DIR = REPO / "logs" / "brain_model_bench"

DEFAULT_MODELS = [
    "phi4:14b",
    "qwen3:14b",
    "deepseek-r1:14b",
    "xploiter/the-xploiter:latest",
]


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def _load_sqlmap_fps(findings_dir: Path) -> set[str]:
    """Return the set of URLs sqlmap labelled `false positive or
    unexploitable` — used as ground truth for hallucination scoring."""
    fps: set[str] = set()
    for p in findings_dir.glob("**/sqlmap_results.txt"):
        try:
            for line in p.read_text(errors="ignore").splitlines():
                if "false positive or unexploitable" in line.lower():
                    # First field is the URL
                    url = line.split(",")[0].strip()
                    if url and url.startswith("http"):
                        fps.add(url)
        except Exception:
            continue
    return fps


def _tally(brain_dir: Path) -> dict:
    """Count SUBMIT/DROP/UNKNOWN verdicts + NO_REPORTS / size / paths."""
    auto_triage = brain_dir / "auto_triage.md"
    h1 = brain_dir / "04_h1_reports.md"
    out = {"submit": 0, "drop": 0, "chain": 0, "unknown": 0,
           "no_reports": False, "brain_bytes": 0,
           "submit_urls": []}
    if auto_triage.exists():
        for line in auto_triage.read_text().splitlines():
            if line.startswith("[SUBMIT]"):
                out["submit"] += 1
                m = re.search(r"https?://\S+", line)
                if m:
                    out["submit_urls"].append(m.group(0).rstrip("'\")>,]"))
            elif line.startswith("[CHAIN]"):
                out["chain"] += 1
            elif line.startswith("[DROP]"):
                out["drop"] += 1
            elif line.startswith("[UNKNOWN]"):
                out["unknown"] += 1
    if h1.exists():
        out["no_reports"] = "NO_REPORTS" in h1.read_text()
    for f in brain_dir.glob("**/*"):
        if f.is_file():
            try:
                out["brain_bytes"] += f.stat().st_size
            except Exception:
                pass
    return out


def _score_hallucination(submit_urls: list[str], sqlmap_fps: set[str]) -> dict:
    """Of the SUBMIT-verdict URLs, how many were already labelled FP by
    sqlmap? Higher = worse model."""
    if not submit_urls:
        return {"submit_total": 0, "submit_fp": 0, "halluc_rate": 0.0}
    fp_hits = sum(1 for u in submit_urls
                  if any(fp in u or u in fp for fp in sqlmap_fps))
    return {"submit_total": len(submit_urls),
            "submit_fp": fp_hits,
            "halluc_rate": round(fp_hits / len(submit_urls), 3)}


def run_one_model(model: str, findings: Path, recon: Path,
                  out_dir: Path) -> dict:
    """Wipe findings/<sess>/brain, set BRAIN_MODEL+TRIAGE_MODEL env, run
    `brain.py scan <findings>`, snapshot brain/ to out_dir, return
    measurements dict."""
    brain_root = findings / "brain"
    snapshot = None
    if brain_root.exists():
        snapshot = findings.parent / f".brain_snapshot_{int(time.time())}"
        shutil.move(str(brain_root), str(snapshot))
    brain_root.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["BRAIN_MODEL"] = model
    env["TRIAGE_MODEL"] = model

    log = out_dir / "brain.log"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-u", str(REPO / "brain.py"), "scan",
           str(findings), "--recon-dir", str(recon)]
    print(f"[*] {model} — brain.py scan ...")
    t0 = time.perf_counter()
    rc = -1
    try:
        with open(log, "w") as fh:
            rc = subprocess.run(cmd, env=env, cwd=str(REPO),
                                stdout=fh, stderr=subprocess.STDOUT,
                                timeout=3600).returncode
    except subprocess.TimeoutExpired:
        rc = 124
    elapsed = round(time.perf_counter() - t0, 2)

    # Snapshot the produced brain/
    bake = out_dir / "brain"
    if bake.exists():
        shutil.rmtree(bake)
    if brain_root.exists() and any(brain_root.iterdir()):
        shutil.copytree(str(brain_root), str(bake))

    tally = _tally(brain_root)

    # Restore original brain/ if there was one
    if snapshot and snapshot.exists():
        shutil.rmtree(brain_root, ignore_errors=True)
        shutil.move(str(snapshot), str(brain_root))

    return {"model": model, "elapsed_s": elapsed, "exit": rc, **tally}


def write_leaderboard(rows: list[dict], sqlmap_fps: set[str],
                      out_path: Path, run_id: str,
                      findings: Path) -> None:
    """Write a markdown leaderboard ranking models by hallucination rate
    then by elapsed time."""
    enriched = []
    for r in rows:
        h = _score_hallucination(r.get("submit_urls", []), sqlmap_fps)
        enriched.append({**r, **h})
    # Lower halluc rate first; tie-break by elapsed
    enriched.sort(key=lambda d: (d["halluc_rate"], d["elapsed_s"]))

    lines = [
        f"# Brain Model Bake-off — {run_id}",
        f"Findings dir: `{findings}`",
        f"sqlmap-FP ground-truth URLs: {len(sqlmap_fps)}",
        "",
        "| # | Model | Elapsed (s) | SUBMIT | DROP | UNK | NO_REPORTS | Halluc rate (FP@SUBMIT) | Brain bytes |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(enriched, 1):
        lines.append(
            f"| {i} | `{r['model']}` | {r['elapsed_s']} | {r['submit']} | "
            f"{r['drop']} | {r['unknown']} | "
            f"{'yes' if r['no_reports'] else 'no'} | "
            f"{r['halluc_rate']} ({r['submit_fp']}/{r['submit_total']}) | "
            f"{r['brain_bytes']} |"
        )
    lines += [
        "",
        "## Verdict",
        "",
        f"Recommended `BRAIN_MODEL`: **`{enriched[0]['model']}`** "
        f"(lowest hallucination rate at acceptable elapsed time).",
        "",
        "Switch via:",
        "```bash",
        f"export BRAIN_MODEL={enriched[0]['model']}",
        f"export TRIAGE_MODEL={enriched[0]['model']}",
        "```",
    ]
    out_path.write_text("\n".join(lines))


def append_csv(rows: list[dict], sqlmap_fps: set[str], findings: Path) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = LOG_DIR.parent / "brain_model_bench.csv"
    write_header = not csv_path.exists()
    with open(csv_path, "a", newline="") as fh:
        w = csv.writer(fh)
        if write_header:
            w.writerow(["ran_at", "findings", "model", "elapsed_s",
                        "submit", "drop", "unknown", "no_reports",
                        "submit_total", "submit_fp", "halluc_rate",
                        "brain_bytes"])
        for r in rows:
            h = _score_hallucination(r.get("submit_urls", []), sqlmap_fps)
            w.writerow([
                datetime.now().isoformat(timespec="seconds"),
                str(findings), r["model"], r["elapsed_s"],
                r["submit"], r["drop"], r["unknown"],
                "yes" if r["no_reports"] else "no",
                h["submit_total"], h["submit_fp"], h["halluc_rate"],
                r["brain_bytes"],
            ])


def watch_for_completion(log_path: str, pattern: str,
                         poll_s: int = 60, timeout_s: int = 86400) -> bool:
    """Poll `log_path` until `pattern` appears or timeout. Returns True
    on success, False on timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if os.path.isfile(log_path):
                with open(log_path) as fh:
                    if pattern in fh.read():
                        return True
        except Exception:
            pass
        time.sleep(poll_s)
    return False


def newest_glob(pat: str) -> str | None:
    matches = sorted(glob.glob(pat))
    return matches[-1] if matches else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="brain_model_bench",
                                 description="Vikramaditya brain LLM bake-off")
    ap.add_argument("--findings", help="Findings dir to replay brain stage on")
    ap.add_argument("--recon", help="Recon dir companion to --findings")
    ap.add_argument("--models", nargs="+", default=DEFAULT_MODELS,
                    help=f"Ollama model tags (default: {' '.join(DEFAULT_MODELS)})")
    ap.add_argument("--watch-log",
                    help="Path to a log file to poll for the completion pattern")
    ap.add_argument("--watch-pattern", default="==== END",
                    help="Substring to look for in --watch-log")
    ap.add_argument("--findings-glob",
                    help="Glob to resolve --findings after completion fires")
    ap.add_argument("--recon-glob",
                    help="Glob to resolve --recon after completion fires")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    if args.watch_log:
        print(f"[watch] polling {args.watch_log} for '{args.watch_pattern}'")
        if not watch_for_completion(args.watch_log, args.watch_pattern):
            print("[watch] timeout — exiting without bench"); return 124
        if args.findings_glob and not args.findings:
            args.findings = newest_glob(args.findings_glob)
        if args.recon_glob and not args.recon:
            args.recon = newest_glob(args.recon_glob)

    if not args.findings or not args.recon:
        ap.error("--findings and --recon are required (directly or via --findings-glob / --recon-glob after --watch-log fires)")

    findings = Path(args.findings).resolve()
    recon = Path(args.recon).resolve()
    if not findings.is_dir() or not recon.is_dir():
        print(f"[!] missing dir(s): findings={findings} recon={recon}")
        return 2

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = (Path(args.output_dir).resolve() if args.output_dir
               else LOG_DIR / run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] bake-off run {run_id} → {run_dir}")
    print(f"[*] findings: {findings}")
    print(f"[*] recon:    {recon}")
    print(f"[*] models:   {args.models}")

    sqlmap_fps = _load_sqlmap_fps(findings)
    print(f"[*] sqlmap FP ground-truth URLs: {len(sqlmap_fps)}")

    rows = []
    for m in args.models:
        per = run_dir / _safe(m)
        per.mkdir(parents=True, exist_ok=True)
        row = run_one_model(m, findings, recon, per)
        rows.append(row)
        (per / "result.json").write_text(json.dumps(row, indent=2))
        print(f"  → {m}: {row['elapsed_s']}s "
              f"SUBMIT={row['submit']} DROP={row['drop']} "
              f"UNK={row['unknown']} NO_REPORTS={row['no_reports']}")

    write_leaderboard(rows, sqlmap_fps, run_dir / "leaderboard.md",
                      run_id, findings)
    append_csv(rows, sqlmap_fps, findings)
    print(f"[+] leaderboard → {run_dir / 'leaderboard.md'}")
    print(f"[+] csv         → {LOG_DIR.parent / 'brain_model_bench.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
k8s_audit.py — Kubernetes posture + runtime audit (v9.8.0)

Wraps Kubescape (CNCF-graduated, NSA/CISA + MITRE ATT&CK for K8s),
Trivy (cluster scan + image SBOM + IaC), and Falco (runtime detection
via eBPF) into a single Vikramaditya-shaped session output.

Output: findings/<context>/k8s/{kubescape.json, trivy_*.json,
falco_runtime.log, summary.json}

Usage:
    # Posture scan (Kubescape NSA/CISA framework)
    python3 k8s_audit.py --context client-prod --framework nsa

    # Image scan (Trivy on the deployment images)
    python3 k8s_audit.py --context client-prod --trivy-images

    # IaC scan on Helm charts / manifests
    python3 k8s_audit.py --iac path/to/charts/

    # Runtime tap (Falco for N seconds)
    python3 k8s_audit.py --context client-prod --falco-seconds 300

Tool requirements:
    Kubescape  — `brew install kubescape` or curl install script
    Trivy      — `brew install trivy`
    Falco      — `brew install falcosecurity/falco/falco`
    kubectl    — already required for any K8s engagement
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


def kubescape_posture(context: str, framework: str, out_dir: Path) -> None:
    """Kubescape posture scan against the named framework (nsa, mitre,
    cis, soc2, allcontrols)."""
    if not _which("kubescape"):
        print("[!] kubescape not found — brew install kubescape "
              "(or curl https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash)")
        return
    out_json = out_dir / f"kubescape_{framework}.json"
    cmd = ["kubescape", "scan", "framework", framework,
           "--kube-context", context,
           "--format", "json", "--output", str(out_json)]
    _run(cmd, out_dir / "kubescape.log", timeout=900)


def trivy_cluster(context: str, out_dir: Path) -> None:
    """Trivy cluster-wide scan: misconfigurations + secrets + RBAC."""
    if not _which("trivy"):
        print("[!] trivy not found — brew install trivy")
        return
    cmd = ["trivy", "k8s", "--context", context, "--report", "all",
           "--format", "json", "--output", str(out_dir / "trivy_cluster.json")]
    _run(cmd, out_dir / "trivy_cluster.log", timeout=1200)


def trivy_images(context: str, out_dir: Path) -> None:
    """Enumerate running images via kubectl and Trivy-scan each."""
    if not _which("kubectl") or not _which("trivy"):
        print("[!] kubectl + trivy required for --trivy-images")
        return
    proc = subprocess.run(
        ["kubectl", "--context", context, "get", "pods", "-A",
         "-o", "jsonpath={range .items[*]}{range .spec.containers[*]}{.image}{\"\\n\"}{end}{end}"],
        capture_output=True, text=True, timeout=60,
    )
    images = sorted(set(line.strip() for line in proc.stdout.splitlines() if line.strip()))
    if not images:
        print("[!] no images discovered in cluster")
        return
    print(f"[*] {len(images)} unique images to scan")
    img_dir = out_dir / "trivy_images"
    img_dir.mkdir(parents=True, exist_ok=True)
    for img in images:
        safe = img.replace("/", "_").replace(":", "_")
        _run(["trivy", "image", "--format", "json",
              "--output", str(img_dir / f"{safe}.json"), img],
             img_dir / f"{safe}.log", timeout=600)


def trivy_iac(path: str, out_dir: Path) -> None:
    """Trivy IaC scan on Helm charts / K8s manifests / Terraform."""
    if not _which("trivy"):
        return
    _run(["trivy", "config", "--format", "json",
          "--output", str(out_dir / "trivy_iac.json"), path],
         out_dir / "trivy_iac.log", timeout=600)


def falco_runtime(context: str, seconds: int, out_dir: Path) -> None:
    """Falco runtime tap — capture eBPF events for N seconds."""
    if not _which("falco"):
        print("[!] falco not found — brew install falcosecurity/falco/falco")
        return
    log_path = out_dir / "falco_runtime.log"
    print(f"[*] Falco capture for {seconds}s — Ctrl-C to stop early")
    proc = subprocess.Popen(["falco", "--json"],
                            stdout=open(log_path, "w"),
                            stderr=subprocess.STDOUT)
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    print(f"[+] Falco events → {log_path}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="k8s_audit",
                                 description="Vikramaditya Kubernetes posture + runtime audit")
    ap.add_argument("--context", help="kubectl context (required for cluster modes)")
    ap.add_argument("--framework", default="nsa",
                    choices=["nsa", "mitre", "cis", "soc2", "allcontrols", "armobest"])
    ap.add_argument("--trivy-cluster", action="store_true")
    ap.add_argument("--trivy-images", action="store_true")
    ap.add_argument("--iac", help="Local IaC path for Trivy config scan")
    ap.add_argument("--falco-seconds", type=int, default=0,
                    help="Run Falco runtime tap for N seconds")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    label = (args.context or "iac-only").replace("/", "_")
    out_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / label / "k8s"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] K8s audit — output: {out_dir}")

    if args.context:
        kubescape_posture(args.context, args.framework, out_dir)
    if args.context and args.trivy_cluster:
        trivy_cluster(args.context, out_dir)
    if args.context and args.trivy_images:
        trivy_images(args.context, out_dir)
    if args.iac:
        trivy_iac(args.iac, out_dir)
    if args.context and args.falco_seconds > 0:
        falco_runtime(args.context, args.falco_seconds, out_dir)

    summary = {
        "tool": "vikramaditya.k8s_audit",
        "version": "9.8.0",
        "context": args.context,
        "framework": args.framework,
        "iac_path": args.iac,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

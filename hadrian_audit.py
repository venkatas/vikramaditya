#!/usr/bin/env python3
"""
hadrian_audit.py — Praetorian Hadrian API authorization tester (thin wrapper)

Hadrian (Apache-2.0, github.com/praetorian-inc/hadrian) is purpose-built for
API authz: role-permutation BOLA/BFLA/BOPLA checks across REST (OpenAPI),
GraphQL, and gRPC. Complements schemathesis (schema conformance / property-
based) and RESTler (stateful fuzz) — those do not systematically cross-test
roles the way Hadrian does.

On-demand only: never runs in the default scan path. Requires an API spec
(or GraphQL/gRPC target) plus roles.yaml + auth.yaml (tokens per role).

Output: findings/<label>/hadrian/{report.json, findings.json, summary.json, hadrian.log}

Usage:
    python3 hadrian_audit.py --protocol rest \
        --api openapi.yaml --roles roles.yaml --auth auth.yaml

    python3 hadrian_audit.py --protocol graphql \
        --target https://api.example.invalid/graphql \
        --roles roles.yaml --auth auth.yaml

    # Preview only (no requests)
    python3 hadrian_audit.py --protocol rest --api openapi.yaml \
        --roles roles.yaml --auth auth.yaml --dry-run

Tool requirements:
    go install github.com/praetorian-inc/hadrian/cmd/hadrian@latest
    OR export HADRIAN_BIN=/path/to/hadrian
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

try:
    from tool_parsers import parse_hadrian_json
except Exception:  # pragma: no cover — allow standalone import during early boot
    parse_hadrian_json = None  # type: ignore


def _which(name: str) -> str | None:
    return shutil.which(name)


def resolve_hadrian_bin() -> str | None:
    """Locate the Hadrian CLI. Prefer HADRIAN_BIN, then PATH."""
    env = (os.environ.get("HADRIAN_BIN") or "").strip()
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    return _which("hadrian")


def build_hadrian_cmd(
    *,
    binary: str,
    protocol: str,
    api: str,
    target: str,
    proto: str,
    roles: str,
    auth: str,
    category: str,
    output_file: Path,
    dry_run: bool,
    insecure: bool,
    proxy: str,
    templates_dir: str,
) -> list[str]:
    """Assemble the Hadrian CLI argv (no network). Fail closed on missing inputs."""
    protocol = (protocol or "rest").strip().lower()
    if protocol not in ("rest", "graphql", "grpc"):
        raise SystemExit(f"[!] unsupported --protocol: {protocol!r} (rest|graphql|grpc)")
    if not roles or not os.path.isfile(roles):
        raise SystemExit(f"[!] --roles file missing: {roles!r}")
    if not auth or not os.path.isfile(auth):
        raise SystemExit(f"[!] --auth file missing: {auth!r}")

    cmd: list[str] = [binary, "test", protocol]
    if protocol == "rest":
        if not api or not os.path.isfile(api):
            raise SystemExit(f"[!] --api OpenAPI/Swagger file required for rest: {api!r}")
        cmd += ["--api", api]
    elif protocol == "graphql":
        if not (target or "").strip():
            raise SystemExit("[!] --target URL required for graphql")
        cmd += ["--target", target.strip()]
    else:  # grpc
        if not (target or "").strip():
            raise SystemExit("[!] --target host:port required for grpc")
        if not proto or not os.path.isfile(proto):
            raise SystemExit(f"[!] --proto file required for grpc: {proto!r}")
        cmd += ["--target", target.strip(), "--proto", proto]

    cmd += ["--roles", roles, "--auth", auth]
    if category:
        cmd += ["--category", category]
    if templates_dir:
        if not os.path.isdir(templates_dir):
            raise SystemExit(f"[!] --templates-dir missing: {templates_dir!r}")
        cmd += ["--template-dir", templates_dir]
    cmd += ["--output", "json", "--output-file", str(output_file)]
    if dry_run:
        cmd.append("--dry-run")
    if insecure:
        cmd.append("--insecure")
    if proxy:
        cmd += ["--proxy", proxy]
    return cmd


def _label_for(api: str, target: str, output_dir: str | None) -> str:
    if output_dir:
        return Path(output_dir).name
    if target:
        host = (urlparse(target if "://" in target else "https://" + target).hostname or "hadrian")
        return host.replace("/", "_")
    if api:
        return Path(api).stem.replace(" ", "_") or "hadrian"
    return "hadrian"


def run_hadrian(cmd: list[str], log_path: Path, timeout: int) -> int:
    """Execute Hadrian; tee stdout/stderr to log. Returns process rc."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # Never echo tokens — cmd references file paths only.
    print(f"[*] $ {' '.join(cmd)}")
    try:
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.write(f"# {' '.join(cmd)}\n# {datetime.now().isoformat(timespec='seconds')}\n\n")
            fh.flush()
            return subprocess.run(
                cmd, stdout=fh, stderr=subprocess.STDOUT, timeout=timeout
            ).returncode
    except subprocess.TimeoutExpired:
        return 124
    except FileNotFoundError:
        return 127


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hadrian_audit",
        description="Vikramaditya wrapper for Praetorian Hadrian (API authz)",
    )
    ap.add_argument("--protocol", default="rest", choices=["rest", "graphql", "grpc"],
                    help="Hadrian protocol mode (default: rest)")
    ap.add_argument("--api", default="", help="OpenAPI/Swagger spec (rest)")
    ap.add_argument("--target", default="", help="GraphQL URL or gRPC host:port")
    ap.add_argument("--proto", default="", help="gRPC .proto file")
    ap.add_argument("--roles", required=True, help="Hadrian roles.yaml")
    ap.add_argument("--auth", required=True, help="Hadrian auth.yaml (tokens per role)")
    ap.add_argument("--category", default="all",
                    help="Hadrian --category (default: all). Use dry-run first on live targets.")
    ap.add_argument("--templates-dir", default="",
                    help="Optional custom Hadrian YAML templates directory")
    ap.add_argument("--dry-run", action="store_true",
                    help="Preview planned tests; send no requests")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verify")
    ap.add_argument("--proxy", default="", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    ap.add_argument("--timeout", type=int, default=3600, help="Wall-clock timeout seconds")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    binary = resolve_hadrian_bin()
    if not binary:
        print("[!] Hadrian CLI not found.\n"
              "    Install: go install github.com/praetorian-inc/hadrian/cmd/hadrian@latest\n"
              "    Or: export HADRIAN_BIN=/path/to/hadrian\n"
              "    setup.sh installs it with the other Go tools.")
        return 127

    label = _label_for(args.api, args.target, args.output_dir)
    out_dir = Path(args.output_dir) if args.output_dir else (REPO / "findings" / label / "hadrian")
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.json"
    findings_path = out_dir / "findings.json"
    summary_path = out_dir / "summary.json"
    log_path = out_dir / "hadrian.log"

    try:
        cmd = build_hadrian_cmd(
            binary=binary,
            protocol=args.protocol,
            api=args.api,
            target=args.target,
            proto=args.proto,
            roles=args.roles,
            auth=args.auth,
            category=args.category,
            output_file=report_path,
            dry_run=args.dry_run,
            insecure=args.insecure,
            proxy=args.proxy,
            templates_dir=args.templates_dir,
        )
    except SystemExit as e:
        print(e)
        return 2

    print(f"[*] Hadrian — protocol={args.protocol} dry_run={args.dry_run}")
    print(f"[*] Output: {out_dir}")
    if not args.dry_run:
        print("[!] Hadrian mutation templates may create/modify/delete resources. Prefer staging.")

    rc = run_hadrian(cmd, log_path, timeout=max(30, int(args.timeout)))

    parsed: list[dict] = []
    if report_path.is_file() and parse_hadrian_json is not None:
        try:
            parsed = parse_hadrian_json(str(report_path))
        except Exception as exc:  # pragma: no cover
            print(f"[!] parse_hadrian_json failed: {exc}")
            parsed = []
    findings_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")

    summary = {
        "tool": "vikramaditya.hadrian_audit",
        "hadrian_bin": binary,
        "protocol": args.protocol,
        "api": args.api,
        "target": args.target,
        "roles": args.roles,
        "auth": args.auth,
        "category": args.category,
        "dry_run": bool(args.dry_run),
        "finding_count": len(parsed),
        "report": str(report_path) if report_path.is_file() else "",
        "ran_at": datetime.now().isoformat(timespec="seconds"),
        "rc": rc,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[+] findings={len(parsed)} → {findings_path}")
    print(f"[+] summary → {summary_path}")
    # Hadrian returns non-zero when vulns are found; surface that but still emit artefacts.
    return 0 if rc in (0, 1) else rc


if __name__ == "__main__":
    sys.exit(main())

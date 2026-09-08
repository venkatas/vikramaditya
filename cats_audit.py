#!/usr/bin/env python3
"""
cats_audit.py — Endava CATS OpenAPI negative fuzz / contract+security wrapper

Opt-in thin wrapper around Endava CATS (Contract API Testing and Security).
Complements Schemathesis (property-based/stateless) and RESTler (stateful):
CATS generates 100+ negative/boundary fuzzers from an OpenAPI contract.

Not part of the default scan path — invoke only via --cats / this CLI.

Output (artifact dir):
    findings/<host>/cats/
      cats-summary-report.json   # CATS native summary (errors/warns/testCases)
      index.html                 # CATS HTML report
      Test*.json                 # per-test JSON (replayable)
      summary.json               # Vikramaditya run metadata + parsed error leads

Usage:
    python3 cats_audit.py --contract openapi.yml --server https://api.example.com
    python3 cats_audit.py --contract openapi.yml --server URL \\
        --header "Authorization=Bearer $TOK" --blackbox
    python3 cats_audit.py --contract openapi.yml --server URL --token "Bearer $TOK"

Install CATS (optional; not required for core VAPT):
    brew tap endava/tap && brew install cats
    # or native binary / uberjar from https://github.com/Endava/cats/releases
    # CATS_BIN=/path/to/cats   or   CATS_JAR=/path/to/cats.jar (needs Java)

Docs: https://endava.github.io/cats/  · License: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent
WRAPPER_VERSION = "1.0.0"


def _which(name: str) -> str | None:
    return shutil.which(name)


def resolve_cats_cmd() -> tuple[str, list[str]]:
    """Return ('native'|'jar'|'none', command prefix tokens).

    Priority: CATS_BIN env → `cats` on PATH → CATS_JAR / java -jar.
    """
    bin_path = (os.environ.get("CATS_BIN") or "").strip()
    if bin_path and os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        return "native", [bin_path]
    on_path = _which("cats")
    if on_path:
        return "native", [on_path]
    jar = (os.environ.get("CATS_JAR") or "").strip()
    if jar and os.path.isfile(jar):
        java = _which("java")
        if not java:
            return "none", []
        return "jar", [java, "-jar", jar]
    return "none", []


def install_hint() -> str:
    return (
        "CATS not found.\n"
        "  Homebrew: brew tap endava/tap && brew install cats\n"
        "  Binary/JAR: https://github.com/Endava/cats/releases\n"
        "  Then: export CATS_BIN=/path/to/cats  OR  CATS_JAR=/path/to/cats.jar"
    )


def _host_label(server: str) -> str:
    raw = (server or "").strip()
    candidate = raw if "://" in raw else "https://" + raw
    host = (urlparse(candidate).netloc or "cats").replace("/", "_")
    return host or "cats"


def build_cats_argv(
    *,
    contract: str,
    server: str,
    output_dir: Path,
    headers: list[str],
    token: str | None,
    headers_file: str | None,
    blackbox: bool,
    paths: str | None,
    skip_ssl: bool,
    dry_run: bool,
    extra: list[str],
) -> list[str]:
    """Build CATS CLI args (without the binary prefix)."""
    args: list[str] = [
        f"--contract={contract}",
        f"--server={server}",
        f"--output={str(output_dir)}",
    ]
    for h in headers:
        h = h.strip()
        if not h:
            continue
        # Accept "Name: Value" (Vikramaditya --header style) or CATS "Name=Value"
        if "=" not in h.split(":", 1)[0] and ":" in h:
            name, val = h.split(":", 1)
            h = f"{name.strip()}={val.strip()}"
        args.append("-H")
        args.append(h)
    if token:
        # Convenience: map --token to Authorization header (Bearer-ready string ok)
        auth = token.strip()
        if not auth.lower().startswith("authorization="):
            auth = f"Authorization={auth}"
        args.extend(["-H", auth])
    if headers_file:
        args.append(f"--headers={headers_file}")
    if blackbox:
        # Only surface 5xx as errors in blackbox mode (CATS docs fast-track)
        args.extend(["--blackbox", "-k"])
    if paths:
        args.append(f"--paths={paths}")
    if skip_ssl:
        # CATS uses --ssl* for keystores; skip TLS verify via common flag if present.
        # Prefer documenting; many builds accept no dedicated skip — pass through extra.
        pass
    if dry_run:
        args.append("--dryRun")
    args.extend(extra)
    return args


def run_cats(cmd: list[str], work_dir: Path, timeout: int) -> int:
    work_dir.mkdir(parents=True, exist_ok=True)
    log_path = work_dir / "cats_run.log"
    print(f"[*] $ {' '.join(cmd)}")
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write(f"# {' '.join(cmd)}\n")
        fh.write(f"# {datetime.now(timezone.utc).isoformat()}\n\n")
        fh.flush()
        try:
            return subprocess.run(
                cmd,
                cwd=str(work_dir),
                stdout=fh,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            ).returncode
        except subprocess.TimeoutExpired:
            fh.write("\n# TIMEOUT\n")
            return 124


def _result_norm(val: Any) -> str:
    return str(val or "").strip().lower()


def parse_cats_summary(report_dir: Path) -> dict[str, Any]:
    """Parse CATS cats-summary-report.json into a compact summary + error leads.

    Clean pattern: CATS writes cats-summary-report.json with errors/warnings/
    success/totalTests and testCases[].result in {success,warn,error,...}.
    """
    summary_path = report_dir / "cats-summary-report.json"
    out: dict[str, Any] = {
        "report_dir": str(report_dir),
        "html_report": str(report_dir / "index.html"),
        "cats_summary": str(summary_path) if summary_path.is_file() else None,
        "errors": 0,
        "warnings": 0,
        "success": 0,
        "total_tests": 0,
        "error_leads": [],
        "warn_leads": [],
    }
    if not summary_path.is_file():
        # Fallback: scan Test*.json if present
        leads = []
        for p in sorted(report_dir.glob("Test*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if _result_norm(data.get("result")) == "error":
                leads.append(_lead_from_case(data, source=p.name))
        out["error_leads"] = leads
        out["errors"] = len(leads)
        out["parse_note"] = "cats-summary-report.json missing; scanned Test*.json"
        return out

    try:
        report = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        out["parse_error"] = str(e)
        return out

    out["errors"] = int(report.get("errors") or 0)
    out["warnings"] = int(report.get("warnings") or 0)
    out["success"] = int(report.get("success") or 0)
    out["total_tests"] = int(report.get("totalTests") or report.get("total_tests") or 0)
    out["cats_version"] = report.get("catsVersion") or report.get("cats_version")
    out["timestamp"] = report.get("timestamp")

    error_leads: list[dict[str, Any]] = []
    warn_leads: list[dict[str, Any]] = []
    for case in report.get("testCases") or []:
        if not isinstance(case, dict):
            continue
        result = _result_norm(case.get("result"))
        lead = _lead_from_case(case)
        if result == "error":
            error_leads.append(lead)
        elif result in ("warn", "warning"):
            warn_leads.append(lead)
    out["error_leads"] = error_leads
    out["warn_leads"] = warn_leads[:50]  # cap noise
    return out


def _lead_from_case(case: dict[str, Any], source: str | None = None) -> dict[str, Any]:
    return {
        "id": case.get("id") or case.get("testId"),
        "result": case.get("result"),
        "result_reason": case.get("resultReason") or case.get("result_reason"),
        "path": case.get("path") or case.get("contractPath"),
        "http_method": case.get("httpMethod") or case.get("http_method"),
        "http_response_code": case.get("httpResponseCode") or case.get("http_response_code"),
        "fuzzer": case.get("fuzzer"),
        "scenario": (case.get("scenario") or "")[:300],
        "result_details": (case.get("resultDetails") or case.get("result_details") or "")[:500],
        "source": source,
    }


def write_error_leads_json(report_dir: Path, parsed: dict[str, Any]) -> Path | None:
    """Write error leads next to the HTML report for easy intake."""
    leads = parsed.get("error_leads") or []
    if not leads:
        return None
    path = report_dir / "error_leads.json"
    path.write_text(json.dumps(leads, indent=2), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="cats_audit",
        description="Vikramaditya opt-in wrapper for Endava CATS OpenAPI negative fuzz",
    )
    ap.add_argument("--contract", "--spec", dest="contract", required=True,
                    help="OpenAPI/Swagger contract file or URL")
    ap.add_argument("--server", "--base-url", dest="server", required=True,
                    help="API base URL (https://api.example.com)")
    ap.add_argument("--header", action="append", default=[],
                    help='Auth/header: "Authorization=Bearer ..." or "Name: Value" (repeatable)')
    ap.add_argument("--token", default=None,
                    help='Convenience auth value → -H Authorization=<token> (e.g. "Bearer xxx")')
    ap.add_argument("--headers-file", default=None,
                    help="CATS YAML headers file (--headers) for per-path auth")
    ap.add_argument("--blackbox", action="store_true",
                    help="CATS --blackbox -k (only treat 5xx as errors)")
    ap.add_argument("--paths", default=None,
                    help="Comma-separated OpenAPI paths to include")
    ap.add_argument("--output-dir", default=None,
                    help="Report dir (default: findings/<host>/cats)")
    ap.add_argument("--timeout", type=int, default=7200,
                    help="Subprocess timeout seconds (default 7200)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Pass CATS --dryRun (generate only)")
    ap.add_argument("--skip-ssl-verify", action="store_true",
                    help="Reserved; pass via --cats-arg if your CATS build supports it")
    ap.add_argument("--cats-arg", action="append", default=[],
                    help="Extra raw arg passed to CATS (repeatable)")
    ap.add_argument("--parse-only", default=None,
                    help="Only parse an existing CATS report dir (no binary run)")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    if args.parse_only:
        report_dir = Path(args.parse_only)
        parsed = parse_cats_summary(report_dir)
        leads_path = write_error_leads_json(report_dir, parsed)
        summary = {
            "tool": "vikramaditya.cats_audit",
            "version": WRAPPER_VERSION,
            "mode": "parse-only",
            "ran_at": datetime.now(timezone.utc).isoformat(),
            "parsed": parsed,
            "error_leads_path": str(leads_path) if leads_path else None,
        }
        out = report_dir / "summary.json"
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"[+] parsed errors={parsed.get('errors')} warns={parsed.get('warnings')} → {out}")
        return 0

    mode, prefix = resolve_cats_cmd()
    if mode == "none":
        print(f"[!] {install_hint()}")
        return 127

    label = _host_label(args.server)
    report_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / label / "cats"
    )
    report_dir.mkdir(parents=True, exist_ok=True)

    cats_argv = build_cats_argv(
        contract=args.contract,
        server=args.server,
        output_dir=report_dir,
        headers=list(args.header or []),
        token=args.token,
        headers_file=args.headers_file,
        blackbox=bool(args.blackbox),
        paths=args.paths,
        skip_ssl=bool(args.skip_ssl_verify),
        dry_run=bool(args.dry_run),
        extra=list(args.cats_arg or []),
    )
    cmd = prefix + cats_argv
    print(f"[*] CATS ({mode}) — contract={args.contract} server={args.server}")
    print(f"[*] Output: {report_dir}")

    rc = run_cats(cmd, report_dir, timeout=int(args.timeout))
    parsed = parse_cats_summary(report_dir)
    leads_path = write_error_leads_json(report_dir, parsed)

    summary = {
        "tool": "vikramaditya.cats_audit",
        "version": WRAPPER_VERSION,
        "cats_resolve": mode,
        "contract": args.contract,
        "server": args.server,
        "blackbox": bool(args.blackbox),
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "worst_rc": rc,
        "parsed": parsed,
        "error_leads_path": str(leads_path) if leads_path else None,
        "artifact_html": str(report_dir / "index.html"),
        "artifact_summary": str(report_dir / "cats-summary-report.json"),
    }
    (report_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[+] CATS rc={rc} errors={parsed.get('errors')} warns={parsed.get('warnings')}")
    print(f"[+] summary → {report_dir / 'summary.json'}")
    print(f"[+] HTML report → {report_dir / 'index.html'}")
    # CATS exit code is often the error count; preserve it for orchestrators.
    return rc


if __name__ == "__main__":
    sys.exit(main())

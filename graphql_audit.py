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


# graphql-cop resource-heavy DoS probes — gated behind --graphql-cop-aggressive.
_GQL_COP_DOS_TESTS = ("alias_overloading", "batch_query",
                      "directive_overloading", "circular_query_introspection")


def _graphql_cop_script() -> Path | None:
    p = REPO / "tools" / "graphql-cop" / "graphql-cop.py"
    return p if p.is_file() else None


def _headers_to_gcop_json(headers: list[str]) -> str | None:
    """graphql-cop's -H takes a JSON dict; merge the 'Name: value' list into one."""
    d: dict[str, str] = {}
    for h in headers or []:
        if ":" in h:
            name, _, value = h.partition(":")
            name, value = name.strip(), value.strip()
            if name:
                d[name] = value
    return json.dumps(d) if d else None


def parse_graphql_cop_output(stdout_text: str) -> list[dict]:
    """graphql-cop -o json prints a JSON list (possibly after a plain 'not GraphQL'
    line). Keep only the result==True entries — those are the fired checks."""
    data = None
    for line in (stdout_text or "").splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, list):
            data = parsed
            break
    if data is None:
        return []
    findings = []
    for e in data:
        if not isinstance(e, dict) or not e.get("result"):
            continue
        findings.append({
            "title": e.get("title"),
            "description": e.get("description"),
            "impact": e.get("impact"),
            "severity": (e.get("severity") or "info").lower(),
            "curl_verify": e.get("curl_verify", ""),
        })
    return findings


def _run_capture(cmd: list[str], log_path: Path, timeout: int = 600) -> str:
    """Like _run but RETURNS stdout (graphql-cop writes its JSON to stdout)."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] $ {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        log_path.write_text(
            f"# {' '.join(cmd)}\n# {datetime.now().isoformat(timespec='seconds')}\n\n"
            f"{r.stdout}\n--- stderr ---\n{r.stderr}")
        return r.stdout or ""
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        return ""


def run_graphql_cop(url: str, headers: list[str], out_dir: Path, *,
                    aggressive: bool = False, runner=None) -> dict | None:
    """graphql-cop (MIT) — the GraphQL DoS / CSRF / info-leak matrix graphw00f,
    Clairvoyance and InQL don't cover. Heavy DoS probes are gated behind aggressive."""
    script = _graphql_cop_script()
    if script is None and runner is None:
        print("[!] graphql-cop not found — clone to tools/graphql-cop (see setup.sh)")
        return None
    gc_dir = out_dir / "graphql_cop"
    gc_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(script) if script else "graphql-cop.py",
           "-t", url, "-o", "json"]
    hdr = _headers_to_gcop_json(headers)
    if hdr:
        cmd += ["-H", hdr]
    if not aggressive:
        cmd += ["-e", ",".join(_GQL_COP_DOS_TESTS)]  # skip resource-heavy DoS probes
    stdout = (runner or _run_capture)(cmd, gc_dir / "graphql_cop.log")
    findings = parse_graphql_cop_output(stdout)
    (gc_dir / "findings.json").write_text(json.dumps(findings, indent=2))
    print(f"[+] graphql-cop: {len(findings)} finding(s) → {gc_dir / 'findings.json'}")
    return {"findings": findings}


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
    ap.add_argument("--graphql-cop-aggressive", action="store_true",
                    help="Run graphql-cop's resource-heavy DoS probes (alias/batch/directive/circular)")
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
    gcop = run_graphql_cop(args.url, args.header, out_dir,
                           aggressive=args.graphql_cop_aggressive)

    gcop_findings = (gcop or {}).get("findings", []) or []
    summary = {
        "tool": "vikramaditya.graphql_audit",
        "version": "9.13.0",
        "url": args.url,
        "graphql_cop_finding_count": len(gcop_findings),
        "graphql_cop_findings": gcop_findings,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

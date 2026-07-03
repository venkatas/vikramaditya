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


def _garak_bin() -> str | None:
    """Resolve garak from the isolated venv (setup.sh) or PATH."""
    for c in (os.path.expanduser("~/.venvs/garak/bin/garak"), _which("garak")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def _split_auth_header(auth_header: str):
    """'Authorization: Bearer tok' -> ('Authorization', '$KEY', 'Bearer tok').

    The FULL header value (scheme included) becomes the REST_API_KEY secret and the
    header value in the options file is the '$KEY' placeholder — so no token is ever
    written to the options file OR the command line.
    """
    if not auth_header or ":" not in auth_header:
        return None, None, None
    name, _, value = auth_header.partition(":")
    name, value = name.strip(), value.strip()
    if not name or not value:
        return None, None, None
    return name, "$KEY", value


def garak_rest_options(target_url: str, auth_header: str = "", *,
                       req_field: str = "prompt", resp_field: str = "$.response",
                       method: str = "post"):
    """Build a garak RestGenerator options object + the api_key to pass via env.

    Verified format (garak.generators.rest): $KEY in headers is substituted from
    REST_API_KEY; $INPUT is the prompt. req/resp fields are target-specific so they
    are operator-configurable (a chat API's schema varies).
    """
    headers = {"Content-Type": "application/json"}
    name, tmpl, api_key = _split_auth_header(auth_header)
    if name:
        headers[name] = tmpl  # "$KEY" — real token supplied via REST_API_KEY env
    opts = {
        "rest": {
            "RestGenerator": {
                "name": "vikramaditya-llm-target",
                "uri": target_url,
                "method": method,
                "headers": headers,
                "req_template_json_object": {req_field: "$INPUT"},
                "response_json": True,
                "response_json_field": resp_field,
            }
        }
    }
    return opts, api_key


def parse_garak_report(report_path) -> list[dict]:
    """Parse garak's report.jsonl 'eval' entries into findings.

    An eval where the model PASSED fewer than TOTAL attempts means some attacks
    succeeded (a real LLM weakness). Severity scales with the failure rate.
    """
    findings: list[dict] = []
    try:
        with open(report_path, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("entry_type") != "eval":
                    continue
                # garak v0.15.x eval entry: total_evaluated/total_processed + fails
                # (older builds used "total"); keep all fallbacks.
                total = (e.get("total_evaluated") or e.get("total_processed")
                         or e.get("total") or 0)
                passed = e.get("passed")
                if passed is None or total <= 0:
                    continue
                failed = e.get("fails")
                if failed is None:
                    failed = total - passed
                if failed <= 0:
                    continue  # model resisted every attempt — not a finding
                rate = failed / total
                sev = "high" if rate >= 0.5 else "medium" if rate >= 0.1 else "low"
                findings.append({
                    "probe": e.get("probe"),
                    "detector": e.get("detector"),
                    "failed": failed,
                    "total": total,
                    "failure_rate": round(rate, 3),
                    "severity": sev,
                })
    except OSError:
        return []
    return findings


def _find_garak_report(garak_dir: Path):
    reports = sorted(garak_dir.glob("*report*.jsonl"), key=lambda p: p.stat().st_mtime)
    return reports[-1] if reports else None


def run_garak(target_url: str, auth_header: str, probes: str, out_dir: Path, *,
              req_field: str = "prompt", resp_field: str = "$.response",
              method: str = "post", runner=None) -> dict | None:
    """Garak — 37+ probe modules for jailbreak/leakage/encoding bypass.

    Fixed wiring: writes a real RestGenerator options file (auth via REST_API_KEY,
    never on the CLI) and parses the report into findings. The old code passed a
    GARAK_REST_AUTH env garak ignores + no generator config, so it could not
    authenticate or match a real chat schema.
    """
    garak = _garak_bin()
    if garak is None and runner is None:
        print("[!] garak not found — install in an isolated venv (see setup.sh) "
              "or: python3 -m venv ~/.venvs/garak && ~/.venvs/garak/bin/pip install garak")
        return None
    garak_dir = out_dir / "garak"
    garak_dir.mkdir(parents=True, exist_ok=True)
    opts, api_key = garak_rest_options(target_url, auth_header, req_field=req_field,
                                       resp_field=resp_field, method=method)
    opts_file = garak_dir / "rest_options.json"
    opts_file.write_text(json.dumps(opts, indent=2))  # NO secret — $KEY placeholder
    cmd = [garak or "garak", "--model_type", "rest",
           "-G", str(opts_file),
           "--report_prefix", str(garak_dir / "report")]
    if probes and probes != "all":
        cmd += ["--probes", probes]
    # Auth via REST_API_KEY env ONLY — never on the CLI (the cmd is printed + logged).
    env = {"REST_API_KEY": api_key} if api_key else {}
    rc = (runner or _run)(cmd, garak_dir / "garak.log", env=env, timeout=3600)
    report = _find_garak_report(garak_dir)
    findings = parse_garak_report(report) if report else []
    (garak_dir / "findings.json").write_text(json.dumps(findings, indent=2))
    print(f"[+] garak: {len(findings)} finding(s) → {garak_dir / 'findings.json'}")
    return {"rc": rc, "findings": findings, "report": str(report) if report else None}


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
    ap.add_argument("--req-field", default="prompt",
                    help="JSON key for the prompt in the request body (prompt|message|input|text|query)")
    ap.add_argument("--resp-field", default="$.response",
                    help="JSONPath to the model reply in the response (e.g. $.choices[0].message.content)")
    ap.add_argument("--method", default="post", help="HTTP method for the LLM endpoint")
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
    garak_result = None
    if (("all" in tools) or ("garak" in tools)) and args.target_url:
        garak_result = run_garak(args.target_url, args.auth_header, args.probes, out_dir,
                                 req_field=args.req_field, resp_field=args.resp_field,
                                 method=args.method)
    if (("all" in tools) or ("pyrit" in tools)) and args.target_url:
        run_pyrit(args.target_url, out_dir)
    if (("all" in tools) or ("promptfoo" in tools)) and args.promptfoo_config:
        run_promptfoo(args.promptfoo_config, out_dir)

    garak_findings = (garak_result or {}).get("findings", []) or []
    summary = {
        "tool": "vikramaditya.llm_hunt",
        "version": "9.10.0",
        "target_url": args.target_url,
        "probes": args.probes,
        "tools": sorted(tools),
        "garak_finding_count": len(garak_findings),
        "garak_findings": garak_findings,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

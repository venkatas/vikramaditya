#!/usr/bin/env python3
"""nuclei DAST (fuzzing) pass — turns on the engine that ships but is never run.

Vikramaditya only ever invokes nuclei with static tags; its whole parameter /
OpenAPI fuzzing + OOB layer (``-dast``) is off. This module runs ``nuclei -dast``
over recon's param-URL corpus (urls/with_params.txt), scope-locked to the target,
and writes findings/dast/nuclei_dast.txt which reporter ingests at nuclei's own
severity (a fired fuzzing template is a real detection, not a fabricated marker).

Opt-in (NUCLEI_DAST=1): active fuzzing, slower. Version-guarded: warns on nuclei
< 3.8.0 (GHSA-29rg-wmcw-hpf4 template file-read). Default ``-ni`` (no OAST) so
client request/response data is NEVER exfiltrated to public interactsh servers —
blind/OOB testing requires an explicitly-supplied self-hosted interactsh server.
Subprocess launches go through procutil (os.posix_spawn, fork-safe).
"""
from __future__ import annotations

import os
import re
import shutil
from typing import Callable, Optional

# nuclei < this carries the community-template file-read advisory.
_MIN_SAFE = (3, 8, 0)
# nuclei >= this has the -dast/fuzzing engine.
_MIN_DAST = (3, 1, 0)
_HOME = os.path.expanduser("~")
_VER_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def find_binary(explicit: Optional[str] = None) -> Optional[str]:
    for cand in (explicit, os.path.join(_HOME, "go", "bin", "nuclei"), shutil.which("nuclei")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def parse_version(text: str):
    m = _VER_RE.search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def supports_dast(ver) -> bool:
    return bool(ver) and ver >= _MIN_DAST


def cve_safe(ver) -> bool:
    return bool(ver) and ver >= _MIN_SAFE


def scope_regex(domain: str) -> str:
    """In-scope fuzz regex: the domain itself or a subdomain of it (with port)."""
    d = re.escape(domain)
    return rf"^https?://([a-zA-Z0-9._-]+\.)?{d}(:\d+)?(/|$|\?)"


def _default_runner(argv, timeout):
    from procutil import run_capture
    return run_capture(argv, timeout=timeout, shell=False, merge_stderr=True)


def get_version(binary: str, runner: Optional[Callable] = None):
    runner = runner or _default_runner
    res = runner([binary, "-version"], 20)
    if isinstance(res, dict):
        text = f"{res.get('stdout', '')}\n{res.get('stderr', '')}"
    else:
        text = str(res)
    return parse_version(text)


def build_cmd(binary: str, input_file: str, out_file: str, domain: str, *,
              aggression: str = "low", rate: int = 50, concurrency: int = 25,
              oob_server: Optional[str] = None, oob_token: Optional[str] = None,
              input_mode: Optional[str] = None) -> list:
    argv = [binary, "-l", input_file, "-dast",
            "-fa", aggression, "-cs", scope_regex(domain),
            "-rl", str(int(rate)), "-c", str(int(concurrency)),
            "-retries", "0", "-silent", "-o", out_file]
    if input_mode:
        argv += ["-im", input_mode]
    if oob_server:
        argv += ["-iserver", oob_server]
        if oob_token:
            argv += ["-itoken", oob_token]
    else:
        # No OAST: never exfil client req/resp to public oast.* servers.
        argv += ["-ni"]
    return argv


def run(input_file: str, out_dir: str, domain: str, *, binary: Optional[str] = None,
        aggression: str = "low", rate: int = 50, concurrency: int = 25,
        timeout: int = 1800, oob_server: Optional[str] = None,
        oob_token: Optional[str] = None, input_mode: Optional[str] = None,
        runner: Optional[Callable] = None) -> dict:
    """Run the nuclei DAST fuzzing pass. Returns a summary dict."""
    result = {"ran": False, "reason": "", "findings": 0, "out_file": None,
              "cve_warn": False, "version": None}
    binary = find_binary(binary)
    if not binary:
        result["reason"] = "nuclei not installed"
        return result
    if not input_file or not os.path.isfile(input_file) or os.path.getsize(input_file) == 0:
        result["reason"] = "no param URLs to fuzz (urls/with_params.txt empty)"
        return result
    ver = get_version(binary, runner=runner)
    result["version"] = ver
    if not supports_dast(ver):
        result["reason"] = f"nuclei {ver} lacks -dast (need >= {_MIN_DAST})"
        return result
    result["cve_warn"] = not cve_safe(ver)

    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "nuclei_dast.txt")
    argv = build_cmd(binary, input_file, out_file, domain, aggression=aggression,
                     rate=rate, concurrency=concurrency, oob_server=oob_server,
                     oob_token=oob_token, input_mode=input_mode)
    (runner or _default_runner)(argv, timeout)

    n = 0
    if os.path.isfile(out_file):
        with open(out_file, errors="replace") as f:
            n = sum(1 for ln in f if ln.strip() and not ln.startswith("#"))
    result["ran"] = True
    result["findings"] = n
    result["out_file"] = out_file if n else None
    return result


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="nuclei -dast fuzzing pass over param URLs")
    ap.add_argument("--input", required=True, help="urls/with_params.txt")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--aggression", default="low", choices=["low", "medium", "high"])
    ap.add_argument("--interactsh-server", default=None)
    ap.add_argument("--interactsh-token", default=None)
    ap.add_argument("--input-mode", default=None)
    args = ap.parse_args(argv)
    res = run(args.input, args.out_dir, args.domain, aggression=args.aggression,
              oob_server=args.interactsh_server, oob_token=args.interactsh_token,
              input_mode=args.input_mode)
    if res["cve_warn"]:
        print("[nuclei-dast] WARNING: nuclei < 3.8.0 has GHSA-29rg-wmcw-hpf4 "
              "(template file-read) — upgrade: brew upgrade nuclei")
    if not res["ran"]:
        print(f"[nuclei-dast] skipped: {res['reason']}")
        return 0
    print(f"[nuclei-dast] {res['findings']} fuzzing finding(s) -> {res['out_file'] or '(none)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

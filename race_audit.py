#!/usr/bin/env python3
"""
race_audit.py — Generic threaded race-condition tester (v9.4.0)

Adapted from `shuvonsec/claude-bug-bounty/tools/h1_race.py` (MIT). Stripped
the HackerOne-specific bounty / 2FA / email-change tests and replaced them
with a generic harness that fires N parallel requests at any URL+method+body
combination. Use during VAPT to surface:
  • coupon/credit/promo double-spend
  • wallet/balance debit/credit ordering
  • OTP send-rate not enforced server-side (per-account flood)
  • duplicate-resource creation (multiple records for the same idempotent op)
  • 2FA/PIN attempts not rate-limited

The N requests are released by a `threading.Barrier(N)` so they leave the
client at the same instant — the actual server-side ordering is what we're
measuring. Output is one row per request: HTTP code, response length, hash
of body, latency. A summary block flags status-code variance (the cheapest
race signal).

Usage:
    # Anonymous coupon redemption double-spend
    python3 race_audit.py --url https://example.com/api/redeem \\
        --method POST --json '{"code":"WELCOME10"}' --threads 30

    # Authenticated debit ordering
    python3 race_audit.py --url https://example.com/api/wallet/debit \\
        --method POST --json '{"amount":1.00}' \\
        --header "Authorization: Bearer $TOK" --threads 50

    # GET-based race (cache poisoning, etc.)
    python3 race_audit.py --url https://example.com/profile?id=42 --threads 20

Exit code: 0 if completed, 2 if threading layer crashed, 130 on Ctrl-C.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
from datetime import datetime
from typing import Any
import urllib.error
import urllib.request


def _send(method: str, url: str, body: bytes | None, headers: dict[str, str],
          timeout: float) -> tuple[int, int, str, float]:
    """One HTTP request. Returns (status, body_len, body_sha256_hex_short, elapsed_ms)."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content = r.read()
            return r.status, len(content), hashlib.sha256(content).hexdigest()[:12], (time.perf_counter() - t0) * 1000
    except urllib.error.HTTPError as e:
        try:
            content = e.read()
        except Exception:
            content = b""
        return e.code, len(content), hashlib.sha256(content).hexdigest()[:12], (time.perf_counter() - t0) * 1000
    except Exception as e:
        return 0, 0, f"err:{type(e).__name__}", (time.perf_counter() - t0) * 1000


def race(url: str, method: str = "GET", body: bytes | None = None,
         headers: dict[str, str] | None = None, threads: int = 20,
         timeout: float = 10.0, settle_ms: int = 0) -> list[dict[str, Any]]:
    """Fire `threads` parallel requests against `url`. Returns one dict per
    request: {tid, status, length, sha12, elapsed_ms}.

    `settle_ms` adds a per-thread post-fire sleep before joining so a server
    that responds super-fast doesn't let the harness exit before all replies
    are decoded — almost never needed; default 0.
    """
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "Vikramaditya/9.4 race_audit (authorized VAPT)")
    if body is not None and "Content-Type" not in {k.title() for k in headers}:
        headers["Content-Type"] = "application/json"

    results: list[dict[str, Any]] = []
    lock = threading.Lock()
    barrier = threading.Barrier(threads)

    def worker(tid: int) -> None:
        try:
            barrier.wait(timeout=timeout)
        except threading.BrokenBarrierError:
            with lock:
                results.append({"tid": tid, "status": -1, "length": 0,
                                "sha12": "barrier-broken", "elapsed_ms": 0.0})
            return
        status, length, sha, ms = _send(method, url, body, headers, timeout)
        if settle_ms:
            time.sleep(settle_ms / 1000.0)
        with lock:
            results.append({"tid": tid, "status": status, "length": length,
                            "sha12": sha, "elapsed_ms": round(ms, 2)})

    workers = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=timeout + 5.0)

    results.sort(key=lambda d: d["tid"])
    return results


def summarise(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Identify race signals: status-code variance, body-hash variance, p50/p99 latency."""
    if not results:
        return {"signal": "no-results"}
    statuses = [r["status"] for r in results]
    sha_set = {r["sha12"] for r in results if r["sha12"] and not r["sha12"].startswith("err")}
    times = sorted(r["elapsed_ms"] for r in results)
    n = len(times)
    p50 = times[n // 2]
    p99 = times[max(0, int(n * 0.99) - 1)]
    status_set = set(statuses)
    return {
        "threads": n,
        "unique_status_codes": sorted(status_set),
        "unique_body_hashes": len(sha_set),
        "p50_ms": p50,
        "p99_ms": p99,
        "first_status_count": sum(1 for s in statuses if s == statuses[0]),
        "race_signal": (
            "STRONG: multiple distinct status codes (server saw concurrent state)"
            if len(status_set) > 1
            else "WEAK: identical status — check unique_body_hashes for variance"
            if len(sha_set) > 1
            else "NONE: identical responses"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="race_audit",
        description="Generic threaded race-condition tester for VAPT engagements",
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="GET",
                        help="HTTP method (default GET)")
    parser.add_argument("--json", default=None,
                        help="JSON body string (sets Content-Type: application/json)")
    parser.add_argument("--data", default=None,
                        help="Raw form/text body (no auto Content-Type)")
    parser.add_argument("--header", action="append", default=[],
                        help="Add HTTP header (repeatable, format: 'Name: value')")
    parser.add_argument("--threads", type=int, default=20,
                        help="Parallel request count (default 20)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Per-request timeout (s, default 10)")
    parser.add_argument("--settle-ms", type=int, default=0,
                        help="Per-thread post-fire sleep (rarely needed)")
    parser.add_argument("--output", default=None,
                        help="Write JSON results to this path; else stdout")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    headers: dict[str, str] = {}
    for raw in args.header:
        if ":" not in raw:
            print(f"[!] header missing ':' — skipping: {raw}", file=sys.stderr)
            continue
        name, _, value = raw.partition(":")
        headers[name.strip()] = value.strip()

    body: bytes | None = None
    if args.json is not None:
        try:
            body = json.dumps(json.loads(args.json)).encode()
        except json.JSONDecodeError as e:
            print(f"[!] --json is not valid JSON: {e}", file=sys.stderr)
            return 2
    elif args.data is not None:
        body = args.data.encode()

    print(f"[*] target={args.url}  method={args.method}  threads={args.threads}", flush=True)
    print(f"[*] firing barrier-released parallel requests at {datetime.now().isoformat(timespec='seconds')}",
          flush=True)
    try:
        results = race(args.url, args.method, body, headers,
                       threads=args.threads, timeout=args.timeout,
                       settle_ms=args.settle_ms)
    except KeyboardInterrupt:
        return 130

    summary = summarise(results)
    print(f"\n[summary] {json.dumps(summary)}\n")
    print(f"{'TID':<4} {'STATUS':<7} {'LEN':<7} {'SHA12':<14} {'MS':<8}")
    for r in results:
        print(f"{r['tid']:<4} {r['status']:<7} {r['length']:<7} {r['sha12']:<14} {r['elapsed_ms']:<8}")

    payload = {
        "tool": "vikramaditya.race_audit",
        "version": "9.4.0",
        "url": args.url,
        "method": args.method.upper(),
        "threads": args.threads,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summary,
        "results": results,
    }
    if args.output:
        with open(args.output, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\n[+] JSON → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

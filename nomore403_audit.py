#!/usr/bin/env python3
"""Calibrated 401/403 bypass audit built on nomore403 (MIT, github.com/devploit/nomore403).

Replaces fuzzer.py's uncalibrated "first 200 == HIGH" routine. Runs nomore403
against recon's 401/403 URLs and CALIBRATES each result against the per-URL
baseline: a host that answered 40x only counts as bypassed when a technique
flips it to a 2xx/3xx. Output goes to ``findings/auth_bypass/403_bypass_hits.txt``
— a path brain.py (403-bypass section) and hunt.py (signal counter) already
consume but nothing previously produced.

Anti-fabrication (see feedback_reporter_fabrication_verify): every emitted line
is prefixed ``[403-BYPASS-CANDIDATE]`` and reporter.py suppresses that prefix, so
a calibrated bypass is a strong LEAD the brain/operator verifies — NOT an
auto-shipped CRITICAL (the auth_bypass template default). Subprocess launches go
through procutil (os.posix_spawn) to stay clear of the macOS fork-SIGSEGV class.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Callable, Optional, Sequence

CANDIDATE_PREFIX = "[403-BYPASS-CANDIDATE]"

# Success codes that constitute a bypass when the baseline was forbidden.
# Redirects (301/302/303/307/308) are DELIBERATELY excluded: nomore403 runs
# without -r, so we only see the first-hop status and no Location header, and a
# 40x->30x is usually a redirect-to-login or a canonicalisation bounce back to
# the same 403 — not access. Only a real 2xx flip counts (anti-false-positive).
_BYPASS_OK = frozenset({200, 201, 202, 203, 204, 206})
# Baseline codes a bypass can "open".
_FORBIDDEN = frozenset({401, 402, 403, 405, 407})

_DEFAULT_TIMEOUT = 900
_HERE = os.path.dirname(os.path.abspath(__file__))


def extract_url(line: str) -> str:
    """First whitespace token of an httpx status_403.txt / status_401.txt line."""
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return ""
    return line.split()[0]


def find_binary(explicit: Optional[str] = None) -> Optional[str]:
    home = os.path.expanduser("~")
    for cand in (
        explicit,
        os.path.join(_HERE, "tools", "nomore403", "nomore403"),
        os.path.join(home, "go", "bin", "nomore403"),
        shutil.which("nomore403"),
    ):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def find_payloads_dir(binary: Optional[str] = None) -> Optional[str]:
    cands = [os.path.join(_HERE, "tools", "nomore403", "payloads")]
    if binary:
        cands.append(os.path.join(os.path.dirname(binary), "payloads"))
    for c in cands:
        if c and os.path.isdir(c):
            return c
    return None


def calibrate_hits(results: Sequence[dict], recon_status: int) -> list[dict]:
    """Return the genuine bypass entries from nomore403 --json results for ONE URL.

    Calibration (anti-false-positive):
      * recon must have labelled the URL forbidden (40x);
      * nomore403's own baseline row (technique == "default") must ALSO be
        forbidden — else the host is not really gated and every "200" is noise;
      * a hit is a non-default technique whose status flipped to 2xx/3xx;
      * de-duplicated by (technique, status, length);
      * if many candidates collapse to ONE identical (status, length) signature,
        treat it as catch-all noise and drop them all.
    """
    if recon_status not in _FORBIDDEN:
        return []
    default = next((r for r in results if r.get("technique") == "default"), None)
    base_status = default.get("status_code") if default else recon_status
    if base_status not in _FORBIDDEN:
        return []

    hits: list[dict] = []
    seen = set()
    for r in results:
        if r.get("technique") == "default":
            continue
        st = r.get("status_code")
        if st not in _BYPASS_OK:
            continue
        key = (r.get("technique"), st, r.get("content_length"))
        if key in seen:
            continue
        seen.add(key)
        hits.append(r)

    if len(hits) >= 5:
        sigs = {(h.get("status_code"), h.get("content_length")) for h in hits}
        # Catch-all noise ONLY when EVERY non-default technique flipped to that one
        # signature (the server answers 2xx for everything). If some techniques
        # still returned a 40x, the flips are a genuine multi-vector bypass (e.g.
        # several IP headers opening the same admin page) — keep them.
        non_default = [r for r in results if r.get("technique") != "default"]
        still_forbidden = any(r.get("status_code") in _FORBIDDEN for r in non_default)
        if len(sigs) == 1 and not still_forbidden:
            return []
    return hits


def format_hit_line(url: str, hit: dict, base_status: int, base_len) -> str:
    st = hit.get("status_code")
    clen = hit.get("content_length")
    tech = hit.get("technique", "?")
    payload = hit.get("payload", "")
    seg = f"{CANDIDATE_PREFIX} {url}  {base_status}→{st}  technique={tech}"
    if base_len is not None and clen is not None:
        seg += f"  len {base_len}→{clen}"
    if payload and payload != url:
        seg += f"  via={payload}"
    return seg


def _default_runner(argv, timeout):
    from procutil import run_capture
    return run_capture(argv, timeout=timeout, shell=False, merge_stderr=False)


def run_nomore403(binary: str, url: str, *, payloads: Optional[str] = None,
                  headers: Optional[Sequence[str]] = None,
                  rate_limit_ms: int = 0, max_goroutines: int = 10,
                  timeout: int = _DEFAULT_TIMEOUT,
                  runner: Optional[Callable] = None) -> list[dict]:
    """Run nomore403 against one URL; return the parsed --json result list ([] on failure)."""
    runner = runner or _default_runner
    out_fd, out_path = tempfile.mkstemp(prefix="nomore403_", suffix=".json")
    os.close(out_fd)
    try:
        argv = [binary, "-u", url, "--json", "-o", out_path, "--no-banner"]
        if payloads:
            argv += ["-f", payloads]
        for h in (headers or []):
            argv += ["-H", h]
        if max_goroutines and max_goroutines > 0:
            argv += ["-m", str(int(max_goroutines))]  # concurrency cap (politeness)
        if rate_limit_ms and rate_limit_ms > 0:
            argv += ["-d", str(int(rate_limit_ms))]
        runner(argv, timeout)
        try:
            with open(out_path, errors="replace") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        return data if isinstance(data, list) else []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def audit(targets, out_dir: str, *, binary: Optional[str] = None,
          payloads: Optional[str] = None, headers: Optional[Sequence[str]] = None,
          max_urls: int = 25, rate_limit_ms: int = 0, max_goroutines: int = 10,
          timeout: int = _DEFAULT_TIMEOUT, runner: Optional[Callable] = None,
          results_fn: Optional[Callable[[str], list]] = None) -> dict:
    """Run the calibrated 403/401 bypass audit.

    ``targets`` is an iterable of ``(url, recon_status)`` pairs (recon_status = 401/403).
    Writes ``<out_dir>/403_bypass_hits.txt`` with ``[403-BYPASS-CANDIDATE]`` lines.
    ``results_fn`` (test seam) overrides the real nomore403 invocation.
    """
    result = {"ran": False, "reason": "", "urls_tested": 0, "hits": 0,
              "errors": 0, "out_file": None}
    if results_fn is None:
        binary = find_binary(binary)
        if not binary:
            result["reason"] = "nomore403 not installed"
            return result
        if payloads is None:
            payloads = find_payloads_dir(binary)

    seen_urls = set()
    ordered = []
    for url, status in targets:
        url = (url or "").strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        ordered.append((url, status))
        if len(ordered) >= max_urls:
            break

    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "403_bypass_hits.txt")
    lines: list[str] = []
    tested = 0
    errors = 0
    for url, status in ordered:
        try:
            if results_fn is not None:
                results = results_fn(url)
            else:
                results = run_nomore403(binary, url, payloads=payloads, headers=headers,
                                        rate_limit_ms=rate_limit_ms,
                                        max_goroutines=max_goroutines,
                                        timeout=timeout, runner=runner)
        except Exception:  # noqa: BLE001 — isolate one URL's failure from the phase
            errors += 1
            continue
        tested += 1
        if not results:
            continue
        default = next((r for r in results if r.get("technique") == "default"), None)
        base_status = default.get("status_code") if default else status
        base_len = default.get("content_length") if default else None
        for hit in calibrate_hits(results, status):
            lines.append(format_hit_line(url, hit, base_status, base_len))

    result["ran"] = True
    result["urls_tested"] = tested
    result["errors"] = errors
    result["hits"] = len(lines)
    if lines:
        with open(out_file, "w") as f:
            f.write("\n".join(lines) + "\n")
        result["out_file"] = out_file
    return result


def read_targets(recon_dir: str) -> list:
    """Collect (url, status) from recon live/status_403.txt + status_401.txt."""
    targets = []
    for fn, status in (("status_403.txt", 403), ("status_401.txt", 401)):
        p = os.path.join(recon_dir, "live", fn)
        if os.path.isfile(p):
            with open(p, errors="replace") as f:
                for line in f:
                    u = extract_url(line)
                    if u:
                        targets.append((u, status))
    return targets


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Calibrated 401/403 bypass audit (nomore403)")
    ap.add_argument("--recon-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--max-urls", type=int, default=25)
    ap.add_argument("--rate-limit-ms", type=int, default=0)
    args = ap.parse_args(argv)

    targets = read_targets(args.recon_dir)
    if not targets:
        print("[nomore403] no 401/403 URLs in recon — nothing to test")
        return 0
    res = audit(targets, args.out_dir, headers=args.header or None,
                max_urls=args.max_urls, rate_limit_ms=args.rate_limit_ms)
    if not res["ran"]:
        print(f"[nomore403] skipped: {res['reason']}")
        return 0
    print(f"[nomore403] tested {res['urls_tested']} URL(s), "
          f"{res['hits']} calibrated bypass candidate(s) -> {res['out_file'] or '(none)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

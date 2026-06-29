#!/usr/bin/env python3
"""cf_origin_hunt.py — Cloudflare / CDN ORIGIN discovery (WAF bypass).

Recon already DETECTS that a host is behind Cloudflare (live/cdn_map.json) — but
then the WAF stonewalls the scan (the public host 403s / challenges). This module
finds the REAL origin so the pipeline can test it DIRECTLY, with no WAF:

  1. Classify every resolved host as Cloudflare-proxied vs DIRECT, using the
     published Cloudflare IPv4 + IPv6 ranges. A non-proxied SIBLING subdomain
     usually shares (or leaks) the origin's subnet — this is the dominant leak
     (e.g. a `medical.digital.<domain>` that points straight at the origin while
     `<target>` hides behind Cloudflare).
  2. Collect origin-IP candidates: every direct (non-CF) IP seen across the
     estate, plus — when API keys are configured — Censys/Shodan/SecurityTrails
     history (hooks; skipped silently without keys).
  3. VERIFY each candidate by requesting it directly with the CF-fronted `Host`
     header and checking the response is the real site (200 + a real <title>,
     not a Cloudflare error/challenge). A candidate that serves the site while
     the public hostname 403s/challenges == CONFIRMED Cloudflare bypass.

Output: live/cf_origin.json
  {"<host>": {"fronted_status": 403, "origin_ips": [...], "verified":
              [{"ip": "...", "status": 200, "title": "...", "host_header": "..."}],
              "bypass": true}}

Stdlib only — no third-party deps. Safe/read-only (GET requests only).
"""
import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from http.client import HTTPSConnection, HTTPConnection

# ── Published Cloudflare ranges (https://www.cloudflare.com/ips/) ──────────────
_CF_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
_CF_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
_CF_NETS = [ipaddress.ip_network(c) for c in _CF_V4 + _CF_V6]
# Third-party endpoints that are NOT the origin (mail / SaaS) — exclude from
# origin candidates so we don't waste a Host-header probe on Google's MX, etc.
_NON_ORIGIN_PREFIXES = ("142.250.", "142.251.", "172.217.", "216.58.", "64.233.",
                        "74.125.", "108.177.")  # Google/Workspace mail ranges
# Per-probe network timeout — deliberately SHORT. cf_origin_hunt runs under
# recon.sh's `timeout` wrapper; sequential 2×10s probes across a dozen candidates
# blew past it and the module was KILLED before it could write cf_origin.json (a real
# recon run produced ZERO output exactly this way). Short per-probe timeout
# + concurrent fan-out + a hard internal deadline (see hunt()) keep it inside the
# wrapper and guarantee a written result.
_PROBE_TIMEOUT = 6


def is_cloudflare(ip: str) -> bool:
    """True if ``ip`` is in a published Cloudflare range (IPv4 or IPv6)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _CF_NETS)


def _is_origin_candidate(ip: str) -> bool:
    if is_cloudflare(ip):
        return False
    if ip.startswith(_NON_ORIGIN_PREFIXES):
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local)


def resolve(host: str) -> list:
    """host -> sorted unique IPs (both families). Empty on failure."""
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        return []


_MAX_CLASSIFY_HOSTS = 1500   # safety cap — don't sequentially DNS a permutation list


def classify(hosts, max_workers: int = 32) -> dict:
    """Resolve each host CONCURRENTLY and split into proxied (all-CF) vs direct (has a
    non-CF IP). Returns {host: {"ips": [...], "proxied": bool, "origin_ips": [...]}}.

    Resolution is fanned out: classify() previously walked the host list serially, so
    when recon handed it a 5k-entry alterx permutation list the thousands of NXDOMAIN
    getaddrinfo() calls overran recon.sh's timeout wrapper. We dedup, cap, and resolve
    in a thread pool (getaddrinfo releases the GIL)."""
    clean, seen = [], set()
    for h in hosts:
        h = (h or "").strip().lower().lstrip("*.")
        if h and h not in seen:
            seen.add(h)
            clean.append(h)
    if len(clean) > _MAX_CLASSIFY_HOSTS:
        clean = clean[:_MAX_CLASSIFY_HOSTS]
    out = {}
    if not clean:
        return out
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(max_workers, len(clean))) as ex:
        for h, ips in zip(clean, ex.map(resolve, clean)):
            if not ips:
                continue
            origin = [ip for ip in ips if _is_origin_candidate(ip)]
            out[h] = {"ips": ips, "proxied": len(origin) == 0, "origin_ips": origin}
    return out


def _title(body: str):
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:90] if m else None


def _is_cf_error(body: str) -> bool:
    """True ONLY for a genuine Cloudflare CHALLENGE / ERROR interstitial — NOT a
    legitimate page that merely references cloudflare (CF assets/analytics/scripts
    appear in the HTML of plenty of real origin pages; matching the bare word
    'cloudflare' false-rejected a verified real origin)."""
    low = (body or "").lower()
    return any(s in low for s in (
        "attention required! | cloudflare", "error 1015", "error 1020",
        "just a moment...", "checking your browser before accessing",
        "cf-error-details", "sorry, you have been blocked",
        "enable javascript and cookies to continue", "ray id:"))


def _fetch(ip: str, host: str, scheme: str = "https", timeout: int = _PROBE_TIMEOUT):
    """GET ``scheme://ip/`` with an explicit Host header. Returns (status, body)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = None
    try:
        if scheme == "https":
            conn = HTTPSConnection(ip, timeout=timeout, context=ctx)
        else:
            conn = HTTPConnection(ip, timeout=timeout)
        conn.request("GET", "/", headers={"Host": host, "User-Agent": "Mozilla/5.0",
                                          "Connection": "close"})
        r = conn.getresponse()
        return r.status, r.read(4000).decode("utf-8", "replace")
    except Exception:
        return None, ""
    finally:
        try:
            conn and conn.close()
        except Exception:
            pass


def verify_origin(ip: str, host: str, expected_title=None,
                  timeout: int = _PROBE_TIMEOUT) -> dict:
    """Probe ``ip`` with ``Host: host``. Confirmed bypass when it returns a real
    200 page (real <title>, not a Cloudflare challenge), optionally matching the
    expected title of the fronted site. Tries HTTPS then HTTP."""
    for scheme in ("https", "http"):
        status, body = _fetch(ip, host, scheme, timeout)
        if status is None:
            continue
        title = _title(body)
        if status == 200 and title and not _is_cf_error(body):
            # If we know the real site's title, require a loose match to avoid a
            # generic shared-host landing page masquerading as the origin.
            if expected_title and not (_loose_match(title, expected_title)
                                       or _host_token_in(title, host)):
                # 200 but a different site on this IP — record but mark unmatched.
                return {"ip": ip, "scheme": scheme, "status": status, "title": title,
                        "host_header": host, "matched": False}
            return {"ip": ip, "scheme": scheme, "status": status, "title": title,
                    "host_header": host, "matched": True}
    return {"ip": ip, "status": status if 'status' in dir() else None, "matched": False}


def _loose_match(a: str, b: str) -> bool:
    na = re.sub(r"[^a-z0-9]+", "", (a or "").lower())
    nb = re.sub(r"[^a-z0-9]+", "", (b or "").lower())
    return bool(na) and bool(nb) and (na in nb or nb in na)


def _host_token_in(title: str, host: str) -> bool:
    label = host.split(".")[0].lower()
    return len(label) >= 3 and label in re.sub(r"[^a-z0-9]+", "", (title or "").lower())


def _fronted_baseline(host: str, timeout: int = _PROBE_TIMEOUT):
    """Fetch the public (CF-fronted) host to learn (status, title) for matching."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        conn = HTTPSConnection(host, timeout=timeout, context=ctx)
        conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0", "Connection": "close"})
        r = conn.getresponse()
        body = r.read(4000).decode("utf-8", "replace")
        conn.close()
        return r.status, _title(body)
    except Exception:
        return None, None


def hunt(target: str, hosts, verbose=False, timeout=None, deadline=None) -> dict:
    """Full origin hunt for ``target`` given the enumerated ``hosts`` (the estate).
    Returns the result dict written to cf_origin.json. Candidate probes fan out
    concurrently under ``deadline`` seconds (None = no cap) so the module finishes
    and writes a result inside recon.sh's `timeout` wrapper instead of being killed
    mid-probe with zero output."""
    t = timeout or _PROBE_TIMEOUT
    # Target FIRST so the classify host cap can never drop it (set() ordering could,
    # which made a CF-fronted apex look un-proxied and skipped the whole hunt).
    cls = classify([target] + list(hosts))
    tnorm = target.lower().lstrip("*.")
    if tnorm not in cls:                       # transient resolve miss — classify it alone
        cls.update(classify([target]))
    tinfo = cls.get(tnorm, {})
    fronted_status, fronted_title = _fronted_baseline(target, t)
    # Candidate origin IPs = every direct IP across the estate (siblings leak the
    # origin subnet), de-duplicated, with same-subnet-as-a-sibling ranked first.
    cand = []
    seen = set()
    for h, info in cls.items():
        for ip in info.get("origin_ips", []):
            if ip not in seen:
                seen.add(ip)
                cand.append(ip)
    verified = []
    timed_out = False
    if cand:
        workers = min(16, max(1, len(cand)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(verify_origin, ip, target, fronted_title, t): ip
                    for ip in cand}
            try:
                for fut in concurrent.futures.as_completed(
                        futs, timeout=(deadline or None)):
                    v = fut.result()
                    if v.get("matched"):
                        verified.append(v)
                        if verbose:
                            print(f"  [BYPASS] {v.get('ip')} serves {target} "
                                  f"({v.get('scheme')} {v.get('status')} "
                                  f"'{v.get('title')}')", file=sys.stderr)
            except concurrent.futures.TimeoutError:
                timed_out = True
                if verbose:
                    print(f"  [cf_origin_hunt] deadline {deadline}s hit; "
                          f"{len(verified)} verified from partial probes",
                          file=sys.stderr)
    return {
        "target": target,
        "fronted_status": fronted_status,
        "fronted_title": fronted_title,
        "is_cloudflare": tinfo.get("proxied", False),
        "origin_candidates": cand,
        "verified": verified,
        "bypass": bool(verified),
        "deadline_hit": timed_out,
        "direct_siblings": sorted(h for h, i in cls.items()
                                  if not i.get("proxied") and h != target),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="cf_origin_hunt",
        description="Cloudflare/CDN origin discovery — find + verify the real server behind the WAF.")
    ap.add_argument("--target", required=True, help="The CF-fronted host (e.g. app.example.edu)")
    ap.add_argument("--subdomains-file", help="File of enumerated subdomains (one per line) to mine for origin leaks")
    ap.add_argument("--out", help="Write result JSON here (e.g. live/cf_origin.json)")
    ap.add_argument("--timeout", type=int, default=_PROBE_TIMEOUT,
                    help="Per-probe network timeout in seconds (default: %(default)s)")
    ap.add_argument("--deadline", type=float, default=180.0,
                    help="Hard cap (s) on the concurrent candidate-probe phase so the "
                         "module always writes its result inside recon.sh's timeout "
                         "wrapper (default: %(default)s; 0 = no cap)")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)

    hosts = []
    if a.subdomains_file and os.path.isfile(a.subdomains_file):
        hosts = [l.strip() for l in open(a.subdomains_file, encoding="utf-8", errors="replace") if l.strip()]
    res = hunt(a.target, hosts, verbose=a.verbose, timeout=a.timeout,
               deadline=(a.deadline or None))

    if a.out:
        try:
            os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
            json.dump({a.target: res}, open(a.out, "w"), indent=1)
        except OSError as e:
            print(f"[cf_origin_hunt] write failed: {e}", file=sys.stderr)

    if res["bypass"]:
        print(f"[+] Cloudflare BYPASS for {a.target}: origin = "
              + ", ".join(f"{v['ip']} (Host-header {v['scheme']} {v['status']})" for v in res["verified"]))
    elif res["is_cloudflare"]:
        partial = " [deadline hit — partial probe]" if res.get("deadline_hit") else ""
        print(f"[-] {a.target} is Cloudflare-fronted; {len(res['origin_candidates'])} "
              f"candidate(s) probed, none served the site directly "
              f"({len(res['direct_siblings'])} non-proxied siblings found){partial}")
    else:
        print(f"[*] {a.target} does not appear Cloudflare-proxied — no origin hunt needed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

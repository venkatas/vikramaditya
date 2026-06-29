"""authz_audit_run — live runner for the authz/disclosure detectors.

Drives authz_audit against an authenticated target and writes
``findings/<target>/authz/findings.json`` in the schema reporter.py Method 1f ingests
(the same contract burp_scanner uses). This is what hunt.py / scanner.sh invoke during an
authenticated scan so the BFLA/IDOR/PII findings fold into the report.

`run()` takes an injected fetcher so it is unit-testable without network; `cookie_fetcher`
builds a live authenticated fetcher from a session cookie.
"""
import http.client
import os
import ssl
import urllib.parse

import authz_audit


def cookie_fetcher(base_url, cookie, ua="Mozilla/5.0", timeout=15, verify=False):
    """Return get(path) -> (status, body, location) for an authenticated cookie session."""
    pu = urllib.parse.urlsplit(base_url if "://" in base_url else "https://" + base_url)
    host, port = pu.hostname, (pu.port or 443)
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    def get(path):
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": ua, "Cookie": cookie, "Accept": "text/html"})
            r = conn.getresponse()
            body = r.read().decode("utf-8", "replace")
            loc = dict((k.lower(), v) for k, v in r.getheaders()).get("location", "")
            return (r.status, body, loc)
        finally:
            conn.close()

    return get


def run(base_url, get_fn, unauth_get=None, owner_get=None, other_get=None,
        object_refs=None, admin_paths=None, page_urls=None, out_root="findings"):
    """Run the authz audit and write findings/<target>/authz/findings.json.

    Returns (findings_json_path, findings_list).
    """
    findings = authz_audit.audit(
        get_fn, unauth_get=unauth_get, owner_get=owner_get, other_get=other_get,
        object_refs=object_refs, admin_paths=admin_paths, page_urls=page_urls)
    pu = urllib.parse.urlsplit(base_url if "://" in base_url else "https://" + base_url)
    target = pu.hostname or "target"
    out_dir = os.path.join(out_root, target, "authz")
    path = authz_audit.write_findings_json(findings, out_dir)
    return path, findings


def _expand_ids(spec):
    """'1-10' or '1,2,5' -> ['1','2',...]."""
    out = []
    for part in (spec or "").split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out += [str(i) for i in range(int(a), int(b) + 1)]
        elif part:
            out.append(part)
    return out


def _build_arg_parser():
    import argparse
    p = argparse.ArgumentParser(
        description="Vikramaditya authz audit — BFLA/IDOR/PII over an authenticated session "
                    "(writes findings/<target>/authz/findings.json for reporter.py)")
    p.add_argument("--base-url", required=True, help="e.g. https://app.example.com")
    p.add_argument("--cookie", required=True, help="authenticated session cookie header value")
    p.add_argument("--admin-paths", default=None, help="comma list to force-browse (default: built-in wordlist)")
    p.add_argument("--object-base", default=None, help="object-ref URL prefix, e.g. /RecordDetails?recordId=")
    p.add_argument("--ids", default=None, help="ids to enumerate against --object-base, e.g. 1-10 or 1,2,5")
    p.add_argument("--pages", default=None, help="comma list of authenticated pages to PII-scan")
    p.add_argument("--out", default="findings", help="findings root dir (default: findings)")
    return p


def main(argv=None):
    args = _build_arg_parser().parse_args(argv)
    get = cookie_fetcher(args.base_url, args.cookie)
    unauth = cookie_fetcher(args.base_url, "")  # no cookie -> unauthenticated baseline
    admin_paths = args.admin_paths.split(",") if args.admin_paths else None
    object_refs = None
    if args.object_base and args.ids:
        object_refs = [args.object_base + i for i in _expand_ids(args.ids)]
    page_urls = args.pages.split(",") if args.pages else None
    path, findings = run(args.base_url, get, unauth_get=unauth, object_refs=object_refs,
                         admin_paths=admin_paths, page_urls=page_urls, out_root=args.out)
    sev = {}
    for f in findings:
        sev[f.get("severity", "info")] = sev.get(f.get("severity", "info"), 0) + 1
    print(f"[authz_audit] {len(findings)} finding(s) {sev} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

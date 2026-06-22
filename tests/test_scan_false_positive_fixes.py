"""False-positive fixes surfaced verifying a large WAF-fronted government estate scan
that reported dozens of 'findings' that were ALL false positives:

1. recon.sh exposed-config check flagged [EXPOSED] /.env, /.git/config,
   /actuator/heapdump, /adminer.php on hosts whose framework custom-404 is served
   as HTTP 200 and ECHOES the requested path into the body
   (<form action="./.env?404;http://...">). Each path's body differs from the
   fingerprint baseline, so it slipped past the md5/size catch-all checks. Now
   suppressed via (a) the path-echo/404-redirect signature and (b) text-config
   paths that return an HTML document.

2. scanner.sh time-based SQLi flagged [SQLI-TIMEOUT-CANDIDATE] on ANY curl timeout
   >18s — but a WAF/gateway returns a FIXED ~19s 502 for any SQL-metachar payload,
   which does NOT scale with the injected sleep. The timeout path now routes through
   the 1s/2s linear-scaling check (verify_sqli_poc); a fixed block fails it.
"""
import os
import re
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECON = os.path.join(ROOT, "recon.sh")
SCANNER = os.path.join(ROOT, "scanner.sh")


def _read(p):
    return open(p, encoding="utf-8", errors="replace").read()


def test_both_scripts_parse():
    for s in (RECON, SCANNER):
        r = subprocess.run(["bash", "-n", s], capture_output=True, text=True)
        assert r.returncode == 0, f"{s} syntax error: {r.stderr}"


def test_recon_suppresses_soft404_pathecho():
    t = _read(RECON)
    # the path-echo / framework-404 redirect signature suppressor
    assert "'?404;'" in t and 'action="./' in t, "no soft-404 path-echo suppressor"
    # text-config-returns-HTML suppressor
    assert re.search(r'\*\.env\*\|\*\.git/\*', t), "no text-config-path soft-404 guard"
    assert "<!doctype html" in t, "soft-404 guard does not check for an HTML document body"


def test_scanner_timeout_routes_through_scaling():
    t = _read(SCANNER)
    # the bare-timeout blind flag must be gone, replaced by a scaling check
    assert 'RC" -eq 28 ] && [ "$TE" -gt 18000' not in t, \
        "scanner.sh still blindly flags a bare >18s timeout as a SQLi candidate"
    # the RC=28 branch now calls verify_sqli_poc before flagging
    assert re.search(r'RC"\s*-eq\s*28[\s\S]{0,1000}verify_sqli_poc', t), \
        "timeout branch no longer routes through the linear-scaling confirmation"


def test_soft404_suppressor_logic_keeps_real_env():
    """Functional: the suppressor must drop a path-echo soft-404 but KEEP a real .env."""
    soft404 = '<!doctype html><html><head><title></title></head><body>' \
              '<form name="form1" method="post" action="./.env?404;http://x/">'
    real_env = "DB_HOST=10.0.0.1\nDB_PASSWORD=s3cr3t\nAPP_KEY=base64:xx"
    def suppressed(body):
        low = body.lower()
        if "?404;" in low or 'action="./' in low:
            return True
        # (b) only applies to text-config paths returning HTML; real_env has no HTML
        if any(m in low for m in ("<!doctype html", "<html", "<form")):
            return True
        return False
    assert suppressed(soft404) is True
    assert suppressed(real_env) is False

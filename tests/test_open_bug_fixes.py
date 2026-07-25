"""Fixes for the open bugs found on a real engagement: vuln-scan batch too tight (B),
cve.py CVE-searches IP 'tech' tokens (C), reporter over-emits per-host dupes (E)."""
import sys
from pathlib import Path
REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


# ── B: vuln-scan batches must fit the timeout ────────────────────────────────
def test_scan_batch_size_and_timeout():
    h = (REPO / "hunt.py").read_text()
    assert "SCAN_TIMEOUT       = 5400" in h, "batch timeout not raised"
    assert "batch_size = 25" in h, "batch size not reduced"


# ── C: cve.py skips IP-address 'tech' tokens (no CVE keyword search on an IP) ──
def test_cve_skips_ip_tokens():
    import cve
    assert cve._is_searchable_tech("23.212.0.111") is False
    assert cve._is_searchable_tech("2600:140f:7200:49::17d4:71") is False
    assert cve._is_searchable_tech("52.172.195.80") is False
    assert cve._is_searchable_tech("nginx") is True          # real product still searched
    assert cve._is_searchable_tech("microsoft sharepoint") is True


# ── E: reporter consolidates many identical per-host findings ────────────────
def test_reporter_consolidates_repeated_misconfig(tmp_path):
    import reporter
    d = tmp_path / "findings"; mc = d / "misconfig"; mc.mkdir(parents=True)
    lines = "\n".join(
        f"[LOW] Missing Content-Security-Policy (CSP) response header — https://host{i}.example"
        for i in range(6))
    (mc / "csp_missing.txt").write_text(lines + "\n")
    findings = reporter.load_findings(str(d))
    mis = [f for f in findings if f.get("vtype") == "misconfig"]
    assert len(mis) == 1, f"6 identical CSP findings across hosts should collapse to 1, got {len(mis)}"
    assert mis[0].get("_consolidated_count") == 6
    assert len(mis[0].get("_affected_hosts", [])) == 6


def test_reporter_keeps_below_threshold(tmp_path):
    # a couple of the same issue (below threshold=4) must NOT be collapsed
    import reporter
    d = tmp_path / "findings"; mc = d / "misconfig"; mc.mkdir(parents=True)
    (mc / "csp.txt").write_text(
        "[LOW] Missing CSP header — https://h1.example\n"
        "[LOW] Missing CSP header — https://h2.example\n")
    findings = reporter.load_findings(str(d))
    assert len([f for f in findings if f.get("vtype") == "misconfig"]) == 2


# ── A: SAML/import endpoint checks skip blanket-response hosts + drop 301/403 ──
def test_saml_import_skip_catchall_and_drop_redirect_forbidden():
    sc = (REPO / "scanner.sh").read_text()
    # both loops skip catchall/WAF hosts
    assert sc.count('case ",$CATCHALL_HOSTS," in *"$_bh"*) continue ;; esac') >= 2
    # SAML no longer flags 301/403 as "endpoint found"
    assert "200|301|302|403)" not in sc, "SAML still flags 301/403 as endpoint-found"
    # import no longer flags the 301/403 flood
    assert "200|201|301|302|400|403|405|422)" not in sc, "IMPORT still flags 301/403 flood"
    assert "200|302)" in sc and "200|201|302|400|405|422)" in sc


# ── F: cred-file check must reject HTML soft-404s (SPA/CDN catch-all) ─────────
def test_cred_file_check_rejects_html_soft404():
    """2026-07-25 engagement: a fake HIGH '[CRED-FILE] .../Dockerfile' shipped from a SPA/CDN
    that serves 200 + index.html for ANY path. These cred/config files (Dockerfile, .npmrc,
    lockfiles, docker-compose.yml, settings.xml) are ALL plaintext — never HTML — so the check
    must drop an HTML body (soft-404) BEFORE the loose keyword filter ('auth'/'key' match
    ordinary markup) reaches the [CRED-FILE] emit."""
    import re
    sc = (REPO / "scanner.sh").read_text()
    i_loop = sc.index("for CRED_PATH in")
    i_echo = sc.index("[CRED-FILE]", i_loop)
    block = sc[i_loop:i_echo]                       # the cred-file loop, up to the emit
    assert re.search(r"grep -qiE\s+['\"]<!doctype html\|<html", block, re.I), \
        "cred-file check must skip HTML/soft-404 bodies before flagging [CRED-FILE]"
    assert "continue" in block, "HTML guard must skip the path (continue), not fall through"

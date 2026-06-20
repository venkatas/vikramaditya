#!/usr/bin/env python3
"""
CVE Hunter
Detects technologies on targets and searches for known CVEs.
Uses httpx tech detection + public CVE databases.

Usage:
    python3 cve_hunter.py <domain>
    python3 cve_hunter.py --recon-dir <recon_dir>
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")

# Exposed-config check: 0 = probe ALL live hosts (the uncapped CLAUDE.md contract).
# Set CVE_CONFIG_MAX_HOSTS=N to cap for runtime reasons; when a cap truncates the
# host list, a degradation marker is printed so a "clean" result is never mistaken
# for a complete one. (audit-fix: was a silent hardcoded [:20])
CVE_CONFIG_MAX_HOSTS = int(os.environ.get("CVE_CONFIG_MAX_HOSTS", "0") or "0")


def resolve_domain_from_recon_dir(recon_dir):
    recon_dir = os.path.abspath(recon_dir)
    parts = recon_dir.split(os.sep)
    if len(parts) >= 3 and parts[-2] == "sessions":
        return parts[-3]
    return os.path.basename(recon_dir)

NOISY_TECH_RE = [
    re.compile(r"^\d+$"),
    re.compile(r"^\d+\s+bytes?$"),
    re.compile(r"^\d{3}\b"),
]
NOISY_TECH_EXACT = {
    "", "ok", "found", "forbidden", "not found", "unauthorized",
    "bad request", "internal server error", "moved permanently",
    "301 moved permanently", "302 found", "403 forbidden", "404 not found",
}
TECH_ALIASES = {
    "apache http server": "apache",
    "apache httpd": "apache",
    "apache": "apache",
    "drupal cms": "drupal",
    "wordpress cms": "wordpress",
}


def run_cmd(cmd, timeout=30):
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode == 0, stdout.strip()
    except subprocess.TimeoutExpired:
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
        return False, f"timeout after {timeout}s"
    except Exception as e:
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
        return False, str(e)


def normalize_tech_name(raw):
    tech = (raw or "").strip().lower()
    tech = re.sub(r"\s+", " ", tech)
    tech = tech.strip("[]()")
    if tech.startswith("title[") or tech.startswith("country[") or tech.startswith("ip["):
        return ""
    if tech in NOISY_TECH_EXACT:
        return ""
    for pattern in NOISY_TECH_RE:
        if pattern.search(tech):
            return ""
    return TECH_ALIASES.get(tech, tech)


def add_tech(techs, raw, count=1):
    tech = normalize_tech_name(raw)
    if not tech or len(tech) < 2:
        return
    techs[tech] = techs.get(tech, 0) + count


# CMS-specific body markers — a fingerprint path is only real evidence of the CMS if the response
# body actually contains one of these (a status-200 alone is meaningless against an SPA catch-all).
_CMS_MARKERS = {
    "wordpress": ["wp-content", "wp-includes", 'content="wordpress'],
    "joomla":    ["joomla", "com_content", "joomla!", "/media/jui/"],
    "drupal":    ["drupal.settings", "/sites/default/", "x-generator: drupal", "drupal.js"],
    "typo3":     ["typo3conf", "typo3temp", "typo3"],
    "umbraco":   ["umbraco"],
    "sitecore":  ["sitecore"],
    "sitefinity": ["sitefinity", "telerik.web"],
}


def _norm_body(s: str) -> str:
    """Whitespace-normalize a body for catch-all equality comparison."""
    return " ".join((s or "").split())


def _cms_path_confirms(tech, status, body, baseline_status, baseline_body):
    """True only if a fingerprint-path response is REAL evidence of ``tech``.

    Gate order: (1) HTTP 200; (2) a CMS-specific body marker MUST be present (primary evidence —
    an SPA/React index has none); (3) reject an SPA/catch-all whose body is essentially IDENTICAL
    to the baseline random-path 200. Marker-primary + exact-duplicate (not a length heuristic) so a
    real CMS page that happens to be a similar length to the baseline is not false-negatived.
    """
    if str(status) != "200":
        return False
    low = body.lower()
    if not any(m in low for m in _CMS_MARKERS.get(tech, [tech])):
        return False
    if str(baseline_status) == "200" and _norm_body(body) == _norm_body(baseline_body):
        return False  # catch-all: the exact same page is served for the random baseline path
    return True


def _fetch_body_status(url, timeout=8):
    """Fetch (body, status) for a URL via curl; ('', '000') on failure."""
    ok, out = run_cmd(
        f'curl -sk -w "\\nHTTPSTATUS:%{{http_code}}" --max-time {timeout} "{url}"',
        timeout=timeout + 5)
    if not ok:
        return "", "000"
    if "HTTPSTATUS:" in out:
        body, _, status = out.rpartition("HTTPSTATUS:")
        return body, status.strip()
    return out, "000"


def detect_technologies(domain, recon_dir=None):
    """Detect technologies running on the target."""
    print(f"[*] Detecting technologies on {domain}...")
    techs = {}

    # Method 1: Check httpx output from recon
    if recon_dir:
        httpx_file = os.path.join(recon_dir, "live", "httpx_full.txt")
        if os.path.exists(httpx_file):
            with open(httpx_file) as f:
                for line in f:
                    # In httpx_full, the last bracket group is the tech-detect field.
                    tech_groups = re.findall(r'\[([^\]]+)\]', line)
                    if tech_groups:
                        for t in tech_groups[-1].split(","):
                            add_tech(techs, t)

        attack_surface_file = os.path.join(recon_dir, "priority", "attack_surface.json")
        if os.path.exists(attack_surface_file):
            try:
                attack_surface = json.load(open(attack_surface_file))
            except Exception:
                attack_surface = {}
            for item in attack_surface.get("tech_clusters", []):
                add_tech(techs, item.get("tech", ""))
            for item in attack_surface.get("detected_versions", []):
                version = (item.get("version", "") or "").lower().strip()
                if version.startswith("drupal "):
                    add_tech(techs, "drupal")
                    add_tech(techs, version.replace(" ", "/", 1))

    # Method 2: Direct httpx probe
    if not techs:
        success, output = run_cmd(
            f'echo "{domain}" | httpx -silent -tech-detect -status-code 2>/dev/null',
            timeout=30
        )
        if success and output:
            tech_groups = re.findall(r'\[([^\]]+)\]', output)
            if tech_groups:
                for t in tech_groups[-1].split(","):
                    add_tech(techs, t)

    # Method 3: Manual header analysis
    success, output = run_cmd(
        f'curl -sI "https://{domain}" --max-time 10 2>/dev/null',
        timeout=15
    )
    if success and output:
        headers = output.lower()

        # Server header
        server_match = re.search(r'server:\s*(.+)', headers)
        if server_match:
            server = server_match.group(1).strip()
            add_tech(techs, server)
            # Extract version
            ver_match = re.search(r'(nginx|apache|iis|lighttpd|caddy|tomcat|jetty)[/ ]*([0-9.]+)', server)
            if ver_match:
                add_tech(techs, f"{ver_match.group(1)}/{ver_match.group(2)}")

        # X-Powered-By
        powered_match = re.search(r'x-powered-by:\s*(.+)', headers)
        if powered_match:
            powered = powered_match.group(1).strip()
            add_tech(techs, powered)

        # Common headers indicating tech
        if "x-aspnet-version" in headers:
            add_tech(techs, "asp.net")
        if "x-drupal" in headers:
            add_tech(techs, "drupal")
        if "x-wordpress" in headers or "wp-" in headers:
            add_tech(techs, "wordpress")
        if "x-shopify" in headers:
            add_tech(techs, "shopify")
        if "x-amz" in headers:
            add_tech(techs, "aws")
        if "cf-ray" in headers:
            add_tech(techs, "cloudflare")

    # Method 4: Check common CMS/framework fingerprints
    print("    [>] Checking CMS/framework fingerprints...")
    fingerprints = {
        "/wp-login.php": "wordpress",
        "/wp-admin/": "wordpress",
        "/wp-includes/": "wordpress",
        "/administrator/": "joomla",
        "/user/login": "drupal",
        "/misc/drupal.js": "drupal",
        "/typo3/": "typo3",
        "/umbraco/": "umbraco",
        "/sitecore/": "sitecore",
        "/sitefinity/": "sitefinity",
    }

    # v10.4.1 — body-evidence gating. A status-200-only probe (the old `-o /dev/null` check)
    # mis-detected six CMS on React/Vite SPAs (client-spa.example): an SPA serves index.html with
    # 200 for EVERY unmatched path. Baseline a random nonexistent path, then require 200 + a body
    # that differs from that baseline (rejects catch-alls) + a CMS-specific body marker.
    import random as _random
    import string as _string
    _rand = "/vikramaditya-baseline-" + "".join(
        _random.choice(_string.ascii_lowercase + _string.digits) for _ in range(12))
    base_body, base_status = _fetch_body_status(f"https://{domain}{_rand}")
    for path, tech in fingerprints.items():
        body, status = _fetch_body_status(f"https://{domain}{path}")
        if _cms_path_confirms(tech, status, body, base_status, base_body):
            add_tech(techs, tech)

    if techs:
        print(f"    [+] Detected technologies:")
        for tech, count in sorted(techs.items(), key=lambda x: -x[1]):
            print(f"        - {tech}")
    else:
        print("    [!] No technologies detected")

    return techs


# v9.23 — tokens that are protocols, transport features, or HTTP *headers* rather
# than software products. Searching them as CVE keywords yields nonsense: "hsts"
# (a response header) returned Firefox/Chrome HSTS CVEs that the report then listed
# as if the site ran a product called HSTS. Never CVE-search these.
NON_PRODUCT_TECHS = {
    "hsts", "https", "http", "http/1.1", "http/2", "http/3", "h2", "h3",
    "ssl", "tls", "tls1.2", "tls1.3", "preload", "hsts preload",
    "gzip", "deflate", "br", "chunked", "keep-alive", "cors", "csp",
    "x-frame-options", "x-content-type-options", "referrer-policy",
    "permissions-policy", "set-cookie", "cookie", "etag", "cache-control",
    "strict-transport-security",
}

# v9.23 — generic framework/library tokens whose bare-keyword NVD search collides
# with unrelated products ("bootstrap" -> Cisco UCCX / BitTorrent bootstrap-dht,
# "jquery" -> jQuery-in-TYPO3). Only worth searching when a version is attached
# (e.g. "jquery/3.4.1"); the version-less token is pure noise.
AMBIGUOUS_BARE_TECHS = {
    "bootstrap", "jquery", "parsley.js", "parsley", "modernizr", "lodash",
    "underscore", "moment", "select2",
}


def _is_searchable_tech(tech_name: str) -> bool:
    """Gate which detected tech tokens are worth a CVE-database keyword search."""
    tl = (tech_name or "").lower().strip()
    if not tl or len(tl) < 2:
        return False
    if tl in NON_PRODUCT_TECHS:
        return False
    # Ambiguous framework name with no attached version -> skip (keyword noise).
    base = tl.split('/', 1)[0]
    if base in AMBIGUOUS_BARE_TECHS and '/' not in tl:
        return False
    return True


def search_cves(tech_name, max_results=10):
    """Search for CVEs related to a technology using public APIs."""
    cves = []

    # Clean up tech name for search
    search_term = re.sub(r'[/.]', ' ', tech_name).strip()

    # Method 1: NVD API (NIST)
    print(f"    [>] Searching CVEs for: {tech_name}...")
    try:
        success, output = run_cmd(
            f'curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&resultsPerPage={max_results}" --max-time 15',
            timeout=20
        )
        if success and output:
            data = json.loads(output)
            # NVD returns a non-object payload (e.g. [], null, an error string)
            # on rate-limit / maintenance — guard like the circl.lu block below
            # so a non-dict response can't raise an uncaught AttributeError.
            vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                descriptions = cve_data.get("descriptions", [])
                desc = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                # Get CVSS score
                metrics = cve_data.get("metrics", {})
                cvss_score = 0
                severity = "unknown"
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(metric_key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN").lower()
                        break

                if cve_id:
                    cves.append({
                        "id": cve_id,
                        "description": desc[:200],
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "technology": tech_name
                    })
    except (json.JSONDecodeError, ValueError, KeyError, TypeError, AttributeError, IndexError) as e:
        print(f"    [!] CVE search parse error for {tech_name}: {e}")

    # Method 2: cve.circl.lu API (fallback)
    if not cves:
        try:
            success, output = run_cmd(
                f'curl -s "https://cve.circl.lu/api/search/{search_term}" --max-time 15',
                timeout=20
            )
            if success and output:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = data.get("results", data.get("data", []))
                if isinstance(data, list):
                    for item in data[:max_results]:
                        cve_id = item.get("id", item.get("cve_id", ""))
                        if cve_id:
                            try:
                                cvss_val = float(item.get("cvss", 0) or 0)
                            except (TypeError, ValueError):
                                cvss_val = 0.0
                            cves.append({
                                "id": cve_id,
                                "description": item.get("summary", "")[:200],
                                "cvss_score": item.get("cvss", 0),
                                "severity": "high" if cvss_val >= 7 else "medium",
                                "technology": tech_name
                            })
        except (json.JSONDecodeError, ValueError, KeyError, TypeError, AttributeError, IndexError) as e:
            print(f"    [!] CVE search parse error for {tech_name}: {e}")

    return cves


def _write_nuclei_status(out_file, status, error=None, findings=0):
    """Persist a degraded/ok status sidecar next to ``out_file``.

    The sidecar lets the caller distinguish "nuclei ran clean, 0 findings"
    from "nuclei failed/missing (result unknown)" — a clean 0-finding run is a
    real negative, a failed run is NOT and must not be reported as such.

    Returns the sidecar path on success, or ``None`` if it could not be written
    (best-effort; never raises). The path is ``<out_file>.status.json``.
    """
    if not out_file:
        return None
    status_file = out_file + ".status.json"
    payload = {
        "status": status,            # "ok" | "degraded" | "failed"
        "tool": "nuclei",
        "error": error,
        "findings": findings,
        "timestamp": datetime.now().isoformat(),
    }
    try:
        with open(status_file, "w") as f:
            json.dump(payload, f, indent=2)
        return status_file
    except OSError:
        return None


def run_nuclei_cve_scan(domain, recon_dir=None, out_file=None):
    """Run nuclei with CVE templates against the target.

    nuclei streams findings to ``out_file`` via ``-o`` instead of buffering them
    in the subprocess stdout pipe. That makes results land on disk incrementally
    and — critically — survive the 300s timeout cap: ``run_cmd`` kills the
    process and discards its buffered stdout on timeout, so any CVE found in the
    last seconds before the cap used to be lost. Reading the ``-o`` file recovers
    those partial results. Coverage is unchanged (same tags/severity/rate-limit/
    timeout); only the result-capture path is hardened.

    Failure handling: a non-timeout, non-zero exit (nuclei missing, template
    download failure, panic before writing ``-o`` …) is a *degraded/failed*
    run, NOT a clean "no CVEs detected" result. Such failures are surfaced as a
    WARN with captured stderr and recorded in a ``<out_file>.status.json``
    sidecar so the caller can mark the engagement's CVE coverage as incomplete
    rather than silently treating a tool failure as a vulnerability-free target.

    Returns the (de-duplicated) list of nuclei finding lines. The list is empty
    both on a clean 0-finding run and on a tool failure — read the status
    sidecar (or ``nuclei_scan_status`` on this function) to tell them apart.
    """
    print(f"\n[*] Running nuclei CVE scan on {domain}...")

    targets_file = None
    if recon_dir:
        live_file = os.path.join(recon_dir, "live", "urls.txt")
        if os.path.exists(live_file):
            targets_file = live_file

    # Stream findings to a file so partial results survive the timeout cap.
    cleanup_out = False
    if not out_file:
        out_file = os.path.join(
            tempfile.gettempdir(), f"nuclei_cve_{domain}_{os.getpid()}.txt"
        )
        cleanup_out = True
    try:
        out_dir = os.path.dirname(out_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        # Start clean so we never read a previous run's findings.
        open(out_file, "w").close()
    except OSError:
        pass

    # Capture nuclei's stderr to a file so a tool failure (missing binary,
    # template error, panic) is no longer silently swallowed by 2>/dev/null.
    err_file = out_file + ".stderr" if out_file else None
    if err_file:
        try:
            open(err_file, "w").close()
        except OSError:
            err_file = None
    stderr_redirect = f'2>"{err_file}"' if err_file else "2>/dev/null"

    nuclei_opts = (
        f'nuclei -tags cve -severity medium,high,critical -silent '
        f'-rate-limit 30 -o "{out_file}"'
    )
    if targets_file:
        cmd = f'cat "{targets_file}" | {nuclei_opts} {stderr_redirect}'
    else:
        cmd = f'echo "https://{domain}" | {nuclei_opts} {stderr_redirect}'

    success, output = run_cmd(cmd, timeout=300)
    timed_out = (
        not success and isinstance(output, str) and output.startswith("timeout after")
    )
    if timed_out:
        print(f"    [!] nuclei hit the {output.split()[-1]} cap — reading partial results")

    # Read whatever nuclei wrote to stderr (if anything) for diagnostics.
    stderr_text = ""
    if err_file:
        try:
            with open(err_file) as f:
                stderr_text = f.read().strip()
        except OSError:
            stderr_text = ""

    # Prefer the -o file (complete on clean exit, partial on timeout); fall back
    # to whatever made it into stdout if the file is unreadable.
    findings = []
    seen = set()
    raw_lines = []
    try:
        with open(out_file) as f:
            raw_lines = f.read().splitlines()
    except OSError:
        if isinstance(output, str):
            raw_lines = output.splitlines()
    for line in raw_lines:
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            findings.append(line)
            print(f"    [VULN] {line}")

    # Classify the run BEFORE cleaning up temp artifacts.
    #   - timeout (partial recovery): degraded, but findings recovered are real.
    #   - non-timeout non-zero exit:  tool failed/missing — result UNKNOWN, do
    #     NOT report "no CVEs"; emit a WARN with stderr and a degraded signal.
    #   - clean exit:                 ok (0 findings is a real negative).
    error_detail = None
    if timed_out:
        status = "degraded"
        error_detail = output  # "timeout after 300s"
    elif not success:
        status = "failed"
        # run_cmd surfaces an exception string (not a returncode) in `output`
        # when Popen itself blew up; nuclei's own diagnostics go to stderr.
        detail = stderr_text or (output if isinstance(output, str) else "")
        error_detail = detail.strip() or "nuclei exited non-zero (no stderr captured)"
        # First stderr line is the most useful (e.g. "nuclei: command not found").
        first_line = error_detail.splitlines()[0] if error_detail else error_detail
        print(
            f"    [WARN] nuclei CVE scan FAILED (tool missing or errored before "
            f"writing results) — CVE coverage is INCOMPLETE, not clean. "
            f"Detail: {first_line}"
        )
    else:
        status = "ok"

    # Record the status sidecar before cleaning up so the caller can read it.
    # (On the default-temp path the sidecar is cleaned up with the rest; the
    # caller-supplied `out_file` path keeps the sidecar for inspection.)
    status_file = _write_nuclei_status(
        out_file, status, error=error_detail, findings=len(findings)
    )
    # Expose the last run's outcome for callers that prefer not to read a file.
    run_nuclei_cve_scan.last_status = {
        "status": status,
        "error": error_detail,
        "findings": len(findings),
        "status_file": status_file,
    }

    if cleanup_out:
        for path in (out_file, err_file, status_file):
            if not path:
                continue
            try:
                os.remove(path)
            except OSError:
                pass
    elif err_file:
        # Keep the caller's out_file + status sidecar; drop the raw stderr scratch.
        try:
            os.remove(err_file)
        except OSError:
            pass

    if findings:
        pass
    elif status == "ok":
        print("    [+] No CVEs detected by nuclei")
    # On a failed/degraded-with-no-findings run we deliberately do NOT print
    # "No CVEs detected" — the WARN/timeout message above already explained the
    # incomplete coverage.

    return findings


# Initialise the introspectable status attribute so callers can rely on it
# existing even before the first invocation.
run_nuclei_cve_scan.last_status = None


def check_exposed_configs(domain, recon_dir=None):
    """Check for exposed config files (env.js, app_env.js, etc.)."""
    print(f"\n[*] Checking for exposed config files on {domain}...")
    exposed = []
    findings_root = os.environ.get("FINDINGS_OUT_DIR", "").strip()
    if findings_root:
        temp_dir = os.path.join(findings_root, "cves", ".tmp")
    else:
        temp_dir = os.path.join(FINDINGS_DIR, domain, "cves", ".tmp")
    os.makedirs(temp_dir, exist_ok=True)
    temp_file = os.path.join(temp_dir, "cfg_check.txt")

    config_paths = [
        "/env.js", "/app_env.js", "/config.js", "/settings.js",
        "/.env", "/.env.local", "/.env.production",
        "/static/env.js", "/assets/env.js", "/config/env.js",
    ]

    hosts = [f"https://{domain}"]
    if recon_dir:
        # Prefer priority-ranked order (highest-risk first) so that if a cap is
        # ever applied, the most important hosts survive the truncation. The
        # live/urls.txt file is `sort -u` (alphabetical), so capping it would
        # silently drop hosts by name rather than by risk.
        ranked_file = os.path.join(recon_dir, "priority", "prioritized_hosts.txt")
        live_file = os.path.join(recon_dir, "live", "urls.txt")
        src_file = ranked_file if os.path.exists(ranked_file) else live_file
        if os.path.exists(src_file):
            with open(src_file) as f:
                all_hosts = [line.strip() for line in f if line.strip()]
            if all_hosts:
                hosts = all_hosts
                # Honor the uncapped contract unless an explicit cap is set.
                if CVE_CONFIG_MAX_HOSTS > 0 and len(all_hosts) > CVE_CONFIG_MAX_HOSTS:
                    hosts = all_hosts[:CVE_CONFIG_MAX_HOSTS]
                    print(
                        f"    [!] Coverage degraded: probing {CVE_CONFIG_MAX_HOSTS} "
                        f"of {len(all_hosts)} live hosts for exposed configs "
                        f"(capped via CVE_CONFIG_MAX_HOSTS)"
                    )

    for host in hosts:
        for path in config_paths:
            url = f"{host}{path}"
            success, output = run_cmd(
                f'curl -s -o "{temp_file}" -w "%{{http_code}}" --max-time 5 "{url}"',
                timeout=10
            )
            if success and output.strip() == "200":
                # Verify it's not an HTML error page
                _, content = run_cmd(f'file "{temp_file}"', timeout=5)
                _, head = run_cmd(f'head -1 "{temp_file}"', timeout=5)
                if 'HTML' not in content and '<!DOCTYPE' not in head and '<html' not in head.lower():
                    exposed.append(url)
                    print(f"    [VULN] Config exposed: {url}")

    if not exposed:
        print("    [+] No exposed config files found")

    return exposed


def hunt_cves(domain, recon_dir=None, findings_root=None):
    """Full CVE hunting pipeline."""
    print("=" * 50)
    print(f"  CVE Hunter — {domain}")
    print("=" * 50)

    findings_root = findings_root or os.environ.get("FINDINGS_OUT_DIR", "").strip()
    if findings_root:
        findings_dir = os.path.join(findings_root, "cves")
    else:
        findings_dir = os.path.join(FINDINGS_DIR, domain, "cves")
    os.makedirs(findings_dir, exist_ok=True)

    # Step 0: Check for exposed config files
    exposed_configs = check_exposed_configs(domain, recon_dir)
    if exposed_configs:
        config_file = os.path.join(findings_dir, "exposed_configs.txt")
        with open(config_file, "w") as f:
            f.write("\n".join(exposed_configs))
        print(f"    [+] Saved {len(exposed_configs)} exposed config URLs to {config_file}")

    # Step 1: Detect technologies
    techs = detect_technologies(domain, recon_dir)

    # Step 2: Search CVE databases for each technology
    all_cves = []
    if techs:
        searchable = [t for t in techs if _is_searchable_tech(t)]
        skipped = [t for t in techs if t not in searchable]
        if skipped:
            print(f"    [>] Skipping non-product/ambiguous tokens (no CVE keyword search): "
                  f"{', '.join(skipped)}")
        print(f"\n[*] Searching CVE databases for {len(searchable)} technologies...")
        for tech in searchable:
            cves = search_cves(tech, max_results=5)
            if cves:
                all_cves.extend(cves)
                for cve in cves:
                    severity_str = f"[{cve['severity'].upper()}]" if cve['severity'] != 'unknown' else ""
                    print(f"    {cve['id']} {severity_str} CVSS:{cve['cvss_score']} — {cve['description'][:80]}...")

        # Save CVE search results
        if all_cves:
            cve_file = os.path.join(findings_dir, "cve_database_matches.json")
            with open(cve_file, "w") as f:
                json.dump({
                    "target": domain,
                    "scan_date": datetime.now().isoformat(),
                    "technologies_detected": list(techs.keys()),
                    "cves_found": all_cves
                }, f, indent=2)
            print(f"\n    [+] Saved {len(all_cves)} CVE matches to {cve_file}")

    # Step 3: Run nuclei CVE detection. Stream straight into the findings dir so
    # results persist incrementally and survive the timeout cap (partial findings
    # used to be discarded when run_cmd killed nuclei at 300s).
    nuclei_file = os.path.join(findings_dir, "nuclei_cve_confirmed.txt")
    nuclei_findings = run_nuclei_cve_scan(domain, recon_dir, out_file=nuclei_file)
    nuclei_status = (getattr(run_nuclei_cve_scan, "last_status", None) or {})
    nuclei_ok = nuclei_status.get("status", "ok") == "ok"
    if nuclei_findings:
        with open(nuclei_file, "w") as f:
            f.write("\n".join(nuclei_findings))
        print(f"    [+] Saved {len(nuclei_findings)} nuclei CVE findings")
    if not nuclei_ok:
        # Do not let a tool failure masquerade as "no CVEs": flag the run so
        # the report/operator knows nuclei coverage is incomplete.
        print(
            f"    [WARN] nuclei CVE coverage is {nuclei_status.get('status', 'degraded').upper()}"
            f" — results are NOT a confirmed-clean signal"
            f"{' (' + str(nuclei_status.get('error')) + ')' if nuclei_status.get('error') else ''}"
        )

    # Summary
    print(f"\n{'=' * 50}")
    print(f"  CVE Hunt Summary — {domain}")
    print(f"{'=' * 50}")
    print(f"  Technologies detected: {len(techs)}")
    print(f"  CVEs from databases: {len(all_cves)}")
    if nuclei_ok:
        print(f"  Confirmed by nuclei: {len(nuclei_findings)}")
    else:
        print(
            f"  Confirmed by nuclei: {len(nuclei_findings)} "
            f"(nuclei {nuclei_status.get('status', 'degraded').upper()} — coverage INCOMPLETE)"
        )

    high_cves = [c for c in all_cves if c.get("cvss_score", 0) >= 7.0]
    if high_cves:
        print(f"\n  HIGH/CRITICAL CVEs ({len(high_cves)}):")
        for cve in sorted(high_cves, key=lambda x: -x.get("cvss_score", 0)):
            print(f"    - {cve['id']} (CVSS {cve['cvss_score']}) [{cve['technology']}]")
            print(f"      {cve['description'][:100]}")

    print(f"\n  Results: {findings_dir}/")
    print(f"{'=' * 50}")

    return all_cves, nuclei_findings


def main():
    parser = argparse.ArgumentParser(description="CVE Hunter — Find known vulnerabilities")
    parser.add_argument("domain", nargs="?", help="Target domain")
    parser.add_argument("--recon-dir", type=str, help="Path to recon results directory")
    parser.add_argument("--findings-dir", type=str, help="Base findings directory for this run")
    args = parser.parse_args()

    if not args.domain and not args.recon_dir:
        parser.print_help()
        sys.exit(1)

    domain = args.domain
    recon_dir = args.recon_dir

    if recon_dir and not domain:
        domain = resolve_domain_from_recon_dir(recon_dir)

    if not recon_dir and domain:
        potential = os.path.join(BASE_DIR, "recon", domain)
        if os.path.isdir(potential):
            recon_dir = potential

    hunt_cves(domain, recon_dir, findings_root=args.findings_dir)


if __name__ == "__main__":
    main()

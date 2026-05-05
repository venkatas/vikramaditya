#!/usr/bin/env python3
"""
Vikramaditya — One command to rule them all.

v9.0.1 — Dual-track VAPT orchestrator. Blackbox engine (recon, fuzz, scan,
HAR auth replay) and whitebox engine (AWS audit via Prowler + PMapper +
secrets scanner) feed the same correlator and report. Give it a target,
it figures out the rest.

Accepts URLs, domains, IPs, CIDRs, and HAR files (browser session exports).
For whitebox cloud audit see `python3 -m whitebox.cloud_hunt --help`.

Usage:
    python3 vikramaditya.py
    python3 vikramaditya.py <target>
    python3 vikramaditya.py <session.har>
"""
from __future__ import annotations

import getpass
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

# ── Colors ────────────────────────────────────────────────────────────────────
O = "\033[38;5;208m"   # Orange
W = "\033[1;37m"       # White bold
D = "\033[0;90m"       # Dim
G = "\033[0;32m"       # Green
R = "\033[0;31m"       # Red
Y = "\033[1;33m"       # Yellow
C = "\033[0;36m"       # Cyan
B = "\033[0;34m"       # Blue
N = "\033[0m"          # Reset

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# v9.5.0 — single-source-of-truth for the orchestrator version. Bumped from
# v9.4.0 for the ProjectDiscovery tool integration bundle (cvemap, cdncheck,
# fingerprintx, asnmap, mapcidr, shuffledns, notify, cloudlist all wired).
# See CHANGELOG.md v9.5.0.
__version__ = "9.5.0"


# ── Run-bookkeeping (v9.2.0 — P3-11) ──────────────────────────────────────────

def _append_run_log(target: str, started_at: float, exit_code: int) -> None:
    """Append one CSV row per vikramaditya invocation to logs/vikram_runs.csv.

    Cheap session bookkeeping for multi-target sweeps so we can answer
    "how long did adfactorspr take last week" without re-parsing per-domain
    log files. Created on first run; never rotated (operator's responsibility).
    """
    try:
        log_dir = os.path.join(SCRIPT_DIR, "logs")
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, "vikram_runs.csv")
        write_header = not os.path.exists(path)
        ended_at = time.time()
        duration_s = int(ended_at - started_at)
        with open(path, "a") as fh:
            if write_header:
                fh.write("started_iso,ended_iso,duration_s,target,exit_code,version\n")
            fh.write(
                f"{datetime.fromtimestamp(started_at).isoformat(timespec='seconds')},"
                f"{datetime.fromtimestamp(ended_at).isoformat(timespec='seconds')},"
                f"{duration_s},{target},{exit_code},{__version__}\n"
            )
    except Exception:
        # Bookkeeping is best-effort; never break the run.
        pass


# ── Whitebox integration (Task 22) ────────────────────────────────────────────

def _maybe_run_whitebox_for_target(target: str, session_dir, autonomous: bool = False) -> None:
    """If whitebox_config.yaml maps the target to any AWS profiles, offer
    to run the cloud whitebox audit alongside the blackbox flow.
    Silent no-op when no config exists or no profile matches.

    session_dir should be the TARGET-LEVEL recon directory (recon/<domain>/)
    so the cloud audit lives at recon/<domain>/cloud/ — session-agnostic and
    readable by hunt.py enrichment and reporter.py regardless of session timing.

    In autonomous mode the prompt is skipped; the audit runs only when
    config.whitebox.autonomous_default is true, otherwise we skip silently.
    """
    try:
        from pathlib import Path as _Path
        from urllib.parse import urlparse as _urlparse
        config_path = _Path("whitebox_config.yaml")
        if not config_path.exists():
            return
        try:
            import yaml as _yaml
        except ImportError:
            return
        cfg = _yaml.safe_load(config_path.read_text()) or {}
        profiles_map = (cfg.get("profiles") or {})
        # Normalize target: hostname only, lowercase, no trailing dot, no port
        _parsed = _urlparse(target if "://" in target else f"http://{target}")
        host = (_parsed.hostname or target).lower().rstrip(".")
        matched = []
        for name, meta in profiles_map.items():
            for d in (meta.get("domains") or []):
                d_norm = d.lower().rstrip(".")
                if host == d_norm or host.endswith("." + d_norm):
                    matched.append(name)
                    break
        if not matched:
            return
        if autonomous:
            # Autonomous mode: skip prompt; run only when explicitly opted in via config
            if not (cfg.get("whitebox", {}).get("autonomous_default", False)):
                print(f"[whitebox] target {host} matched profiles {matched} but autonomous_default not set — skipping cloud audit.")
                return
            ans = "y"
        else:
            print(f"[whitebox] target {host} matched profiles: {matched}")
            try:
                ans = input("Run cloud whitebox audit alongside blackbox? [Y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = "n"
        if ans in ("", "y", "yes"):
            from whitebox.cloud_hunt import main as _cloud_main
            argv = []
            for p in matched:
                argv += ["--profile", p]
            # Use target-level dir so cloud/ is session-agnostic
            argv += ["--session-dir", str(session_dir), "--allowlist", host]
            _cloud_main(argv)
            # v9.2.0 (P0-1) — when the same AWS profile maps to multiple
            # targets in one sweep (e.g. adfactorspr.com + adfactorsadvertising.com
            # both → adf-erp), cloud_hunt's per-account phase cache short-
            # circuits the SECOND target's run because the manifest from the
            # first run is still fresh. The previous behaviour created the
            # second target's recon/<domain>/cloud/<acct>/ directory but
            # left it empty (no findings JSON, no manifest), which broke
            # reporter.py's "Cloud Posture" chapter. Symlink the existing
            # cached account_dir into the second target's cloud/ subtree so
            # the report can still find it.
            try:
                from pathlib import Path as _P
                this_cloud = _P(session_dir) / "cloud"
                for p in matched:
                    acct_id = (cfg.get("profiles", {}).get(p, {}) or {}).get("account_id")
                    if not acct_id:
                        continue
                    dst = this_cloud / acct_id
                    if dst.exists() and any(dst.iterdir()):
                        continue  # cloud_hunt populated this already
                    # Hunt for a sibling target that has a populated cloud/<acct>/
                    repo_recon = _P(SCRIPT_DIR) / "recon"
                    src_dir = None
                    for sibling in repo_recon.iterdir():
                        if not sibling.is_dir() or sibling.name == _P(session_dir).name:
                            continue
                        cand = sibling / "cloud" / acct_id
                        if cand.exists() and (cand / "manifest.json").exists():
                            src_dir = cand
                            break
                    if src_dir is None:
                        continue
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    if dst.exists() and dst.is_symlink():
                        dst.unlink()
                    elif dst.exists():
                        # Empty real dir from cloud_hunt's account_dir.mkdir;
                        # remove and re-create as symlink.
                        try:
                            dst.rmdir()
                        except OSError:
                            continue
                    dst.symlink_to(src_dir.resolve())
                    print(f"[whitebox] linked cached audit: {dst} -> {src_dir}", flush=True)
            except Exception as _link_e:
                print(f"[whitebox] cache-link skipped: {_link_e}", flush=True)
    except Exception as _e:
        # Whitebox is optional — never break the blackbox flow
        print(f"[whitebox] integration skipped: {_e}")


def banner():
    # Indian flag: saffron (top), white (middle), green (bottom)
    # Ashoka Chakra blue for the tagline
    SF = "\033[38;5;208m"  # Saffron
    WH = "\033[1;37m"      # White
    GR = "\033[0;32m"      # Green (India green)
    BL = "\033[38;5;19m"   # Navy blue (Ashoka Chakra)
    RS = "\033[0m"         # Reset
    print(f"""
{SF} ██╗   ██╗██╗██╗  ██╗██████╗  █████╗ ███╗   ███╗ █████╗ ██████╗ ██╗████████╗██╗   ██╗ █████╗{RS}
{SF} ██║   ██║██║██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝██╔══██╗{RS}
{WH} ██║   ██║██║█████╔╝ ██████╔╝███████║██╔████╔██║███████║██║  ██║██║   ██║    ╚████╔╝ ███████║{RS}
{WH} ╚██╗ ██╔╝██║██╔═██╗ ██╔══██╗██╔══██║██║╚██╔╝██║██╔══██║██║  ██║██║   ██║     ╚██╔╝  ██╔══██║{RS}
{GR}  ╚████╔╝ ██║██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║██████╔╝██║   ██║      ██║   ██║  ██║{RS}
{GR}   ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝{RS}
{BL}              Autonomous VAPT Platform — One Target, Full Assessment{RS}
""")


def prompt(text: str, default: str = "") -> str:
    """Prompt user for input with optional default.

    v7.1.9 — when stdin isn't a TTY (background run, CI, piped input)
    ``input()`` raises EOFError the moment it sees EOF. Swallow that and
    return the default so a 3-hour autonomous scan doesn't crash at the
    final report prompt.
    """
    try:
        if default:
            raw = input(f"{C}  {text} [{default}]: {N}").strip()
            return raw or default
        return input(f"{C}  {text}: {N}").strip()
    except EOFError:
        return default


def confirm(text: str, default_yes: bool = True) -> bool:
    """Yes/no confirmation. Returns the configured default when stdin is closed."""
    hint = "Y/n" if default_yes else "y/N"
    try:
        raw = input(f"{C}  {text} [{hint}]: {N}").strip().lower()
    except EOFError:
        return default_yes
    if not raw:
        return default_yes
    return raw in ("y", "yes")


def log(level: str, msg: str):
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    colors = {"ok": G, "err": R, "warn": Y, "info": C}
    sym = symbols.get(level, "*")
    col = colors.get(level, "")
    print(f"  {col}[{sym}]{N} {msg}", flush=True)


# ── Target Classification ─────────────────────────────────────────────────────

def classify_target(target: str) -> dict:
    """Classify target as har, cidr, ip, domain, or url."""
    target = target.strip()

    # HAR file (browser session export)
    if target.lower().endswith(".har") and os.path.isfile(target):
        return {"type": "har", "value": target, "original": target}

    # v9.5.0 — ASN target. Operator passes "AS123456" or "asn:123456";
    # asnmap expands to a CIDR list which we then expand to individual
    # IPs (or pass through as a CIDR-list batch to hunt.py).
    asn_match = re.match(r"^(?:asn:|AS)(\d+)$", target.strip(), re.IGNORECASE)
    if asn_match:
        asn = "AS" + asn_match.group(1)
        cidrs = _expand_asn_to_cidrs(asn)
        if cidrs:
            return {"type": "asn", "value": asn, "cidrs": cidrs, "original": target}

    # CIDR
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return {"type": "cidr", "value": str(net), "original": target}
        except ValueError:
            pass

    # URL with scheme
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return {"type": "url", "value": target, "host": parsed.netloc,
                "scheme": parsed.scheme, "original": target}

    # Single IP
    try:
        ipaddress.ip_address(target)
        return {"type": "ip", "value": target, "original": target}
    except ValueError:
        pass

    # Bare domain — check if it looks like a URL someone forgot the scheme for
    if "." in target and not target.startswith("/"):
        return {"type": "domain", "value": target, "original": target}

    return {"type": "unknown", "value": target, "original": target}


# ── Web App Fingerprinting ────────────────────────────────────────────────────

def fingerprint_webapp(url: str) -> dict:
    """Quick fingerprint: tech stack, login detection, API detection, JS analysis."""
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    result = {
        "url": url,
        "tech": [],
        "login_detected": False,
        "login_paths": [],
        "api_detected": False,
        "api_base": None,
        "js_chunks": 0,
        "js_endpoints": 0,
        "openapi_found": False,
        "server": "",
        "status": 0,
        "error": None,
    }

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Fetch the main page
    try:
        resp = requests.get(url, verify=False, timeout=15, allow_redirects=True)
        result["status"] = resp.status_code
        result["server"] = resp.headers.get("Server", "")
    except Exception as e:
        result["error"] = str(e)
        return result

    html = resp.text

    # ── Tech stack detection ──────────────────────────────────────────────
    tech_signals = {
        "Vite":     [r'/assets/[^"]+\.js', r'modulepreload'],
        "React":    [r'react', r'__NEXT_DATA__', r'_reactRoot'],
        "Next.js":  [r'/_next/static', r'__NEXT_DATA__'],
        "Vue":      [r'vue', r'__vue__', r'/js/app\.[a-f0-9]+\.js'],
        "Angular":  [r'ng-version', r'angular', r'/main\.[a-f0-9]+\.js'],
        "Django":   [r'csrfmiddlewaretoken', r'django'],
        "Laravel":  [r'laravel', r'XSRF-TOKEN'],
        "Rails":    [r'csrf-token', r'rails'],
        "Express":  [r'X-Powered-By.*Express'],
        "WordPress":[r'wp-content', r'wp-json'],
        "Drupal":   [r'drupal', r'/sites/default/'],
        "PHP":      [r'\.php[\?"\'>\s]', r'PHPSESSID', r'\.phtml'],
        "CGI":      [r'/cgi-bin/', r'\.cgi[\?"\'>\s]'],
        "JSP":      [r'\.jsp[\?"\'>\s]', r'JSESSIONID'],
        "ASP.NET":  [r'\.aspx?[\?"\'>\s]', r'ASP\.NET_SessionId', r'__VIEWSTATE'],
    }
    for tech, patterns in tech_signals.items():
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                if tech not in result["tech"]:
                    result["tech"].append(tech)
                break

    # Server header tech
    server = result["server"].lower()
    if "nginx" in server:
        result["tech"].append(f"nginx ({result['server']})")
    elif "apache" in server:
        result["tech"].append(f"Apache ({result['server']})")

    # ── JS chunk counting ─────────────────────────────────────────────────
    js_patterns = [
        r'src="(/static/js/[^"]+\.js)"',
        r'src="(/assets/[^"]+\.js)"',
        r'src="(/_next/static/[^"]+\.js)"',
        r'href="(/assets/[^"]+\.js)"',
        r'<link[^>]+(?:rel="modulepreload"|as="script")[^>]+href="([^"]+\.js)"',
    ]
    js_files = set()
    for pat in js_patterns:
        js_files.update(re.findall(pat, html))
    result["js_chunks"] = len(js_files)

    # Quick endpoint count from main bundle (don't fetch all chunks — that's for the scan)
    if js_files:
        try:
            first_js = list(js_files)[0]
            if not first_js.startswith("http"):
                first_js = base + first_js
            js_resp = requests.get(first_js, verify=False, timeout=15)
            js_text = js_resp.text

            # Count API-like paths
            api_paths = set()
            for pat in [r'\.(get|post|put|patch|delete)\("[^"]*"',
                        r'fetch\(["`\'][^"`\']+["`\']']:
                api_paths.update(re.findall(pat, js_text))
            result["js_endpoints"] = len(api_paths)

            # Login detection from JS
            login_patterns = re.findall(r'"(/(?:auth/)?(?:login|sign-in|signin)[^"]*)"', js_text)
            if login_patterns:
                result["login_detected"] = True
                result["login_paths"] = list(set(login_patterns))

            # Cross-origin API base detection from JS (baseURL, apiUrl, etc.)
            # Catches: baseURL:"https://api.example.com/v1/"
            cross_origin_apis = re.findall(
                r'(?:baseURL|apiUrl|API_URL|apiBase|api_base)["\s:=]+["\']?(https?://[^"\'\s,;]+)',
                js_text, re.IGNORECASE)
            for api_url in cross_origin_apis:
                api_url = api_url.rstrip("/")
                if api_url and parsed.netloc not in api_url:
                    # Cross-origin API found
                    result["api_detected"] = True
                    result["api_base"] = api_url
                    log("info", f"Cross-origin API found in JS: {api_url}")
                    # Check if this API has a login endpoint
                    for lp in ["login-view/", "login/", "auth/login/"]:
                        try:
                            lp_resp = requests.post(f"{api_url}/{lp}",
                                                     data={"email": "", "password": ""},
                                                     verify=False, timeout=8)
                            if lp_resp.status_code not in (404, 405, 0):
                                result["login_detected"] = True
                                result["login_paths"].append(f"{api_url}/{lp}")
                                break
                        except Exception:
                            continue
                    break

            # Also detect login-view in JS fetch/post calls
            if not result["login_detected"]:
                login_js = re.findall(r'["\']([^"\']*login-view[^"\']*)["\']', js_text)
                if login_js:
                    result["login_detected"] = True
                    result["login_paths"].extend(login_js[:3])
        except Exception:
            pass

    # ── Login detection from HTML ─────────────────────────────────────────
    if not result["login_detected"]:
        login_html_signals = [
            r'type="password"', r'name="password"',
            r'login', r'sign.?in', r'authenticate',
        ]
        for sig in login_html_signals:
            if re.search(sig, html, re.IGNORECASE):
                result["login_detected"] = True
                break

    # ── Login detection: probe common login URLs directly ─────────────────
    if not result["login_detected"]:
        login_probes = ["auth/login", "login", "login-view/", "api/auth/login",
                        "v1/auth/login", "api/login"]
        for lp in login_probes:
            try:
                lp_resp = requests.post(f"{base}/{lp}", json={"email": "", "password": ""},
                                         verify=False, timeout=8)
                # If we get anything other than 404/405, a login endpoint exists
                if lp_resp.status_code not in (404, 405, 0):
                    result["login_detected"] = True
                    result["login_paths"].append(f"/{lp}")
                    break
            except Exception:
                continue

    # ── API base detection ────────────────────────────────────────────────
    api_probes = ["/api/", "/api/v1/", "/v1/", "/v2/", "/graphql"]
    for probe_path in api_probes:
        try:
            probe_resp = requests.get(base + probe_path, verify=False, timeout=8,
                                       allow_redirects=False)
            ct = probe_resp.headers.get("Content-Type", "")
            if "application/json" in ct:
                result["api_detected"] = True
                result["api_base"] = base + probe_path.rstrip("/")
                break
        except Exception:
            continue

    # Also check subdomain api.*
    host_parts = parsed.netloc.split(".")
    if host_parts[0] != "api" and len(host_parts) >= 2:
        api_host = "api." + ".".join(
            host_parts[1:] if host_parts[0] in ("app", "www") else host_parts)
        try:
            probe_resp = requests.get(f"{parsed.scheme}://{api_host}/",
                                       verify=False, timeout=8)
            if probe_resp.status_code not in (0, 502, 503):
                ct = probe_resp.headers.get("Content-Type", "")
                if "application/json" in ct or probe_resp.status_code == 200:
                    result["api_detected"] = True
                    result["api_base"] = f"{parsed.scheme}://{api_host}"
        except Exception:
            pass

    # If no explicit API base but JS has endpoints, API is same-origin
    if not result["api_detected"] and result["js_endpoints"] > 3:
        result["api_detected"] = True
        result["api_base"] = base

    # ── OpenAPI / Swagger ─────────────────────────────────────────────────
    openapi_paths = ["docs", "swagger.json", "openapi.json", "api-docs",
                     "api/docs", "api/swagger.json"]
    for doc_path in openapi_paths:
        try:
            doc_resp = requests.get(f"{base}/{doc_path}", verify=False, timeout=8)
            if doc_resp.status_code == 200:
                try:
                    spec = doc_resp.json()
                    if "paths" in spec or "openapi" in spec or "swagger" in spec:
                        result["openapi_found"] = True
                        break
                except Exception:
                    if "swagger" in doc_resp.text.lower() or "openapi" in doc_resp.text.lower():
                        result["openapi_found"] = True
                        break
        except Exception:
            continue

    return result


def show_summary(target_info: dict, fingerprint: dict = None):
    """Display fingerprint summary in a formatted box."""
    print(f"\n  {W}{'─' * 56}{N}")
    print(f"  {W}  TARGET SUMMARY{N}")
    print(f"  {W}{'─' * 56}{N}")

    if target_info["type"] in ("cidr", "ip"):
        print(f"  {C}  Target  :{N} {target_info['value']}")
        print(f"  {C}  Type    :{N} {target_info['type'].upper()}")
        print(f"  {C}  Action  :{N} Recon + Vulnerability Scan")
        print(f"  {W}{'─' * 56}{N}\n")
        return

    if target_info["type"] == "domain":
        print(f"  {C}  Target  :{N} {target_info['value']}")
        print(f"  {C}  Type    :{N} Domain")
        print(f"  {C}  Action  :{N} Subdomain Enum + Recon + Vulnerability Scan")
        print(f"  {W}{'─' * 56}{N}\n")
        return

    if not fingerprint:
        return

    fp = fingerprint
    print(f"  {C}  Target  :{N} {fp['url']}")
    print(f"  {C}  Status  :{N} HTTP {fp['status']}")

    if fp["tech"]:
        print(f"  {C}  Tech    :{N} {', '.join(fp['tech'])}")
    if fp["server"]:
        print(f"  {C}  Server  :{N} {fp['server']}")

    # Login
    if fp["login_detected"]:
        paths_str = ", ".join(fp["login_paths"][:3]) if fp["login_paths"] else "detected"
        print(f"  {G}  Login   :{N} {paths_str}")
    else:
        print(f"  {D}  Login   :{N} not detected")

    # API
    if fp["api_detected"]:
        print(f"  {G}  API     :{N} {fp['api_base'] or 'same-origin'}")
    else:
        print(f"  {D}  API     :{N} not detected")

    # JS
    if fp["js_chunks"]:
        print(f"  {C}  JS      :{N} {fp['js_chunks']} bundles, ~{fp['js_endpoints']}+ API calls found")

    # OpenAPI
    if fp["openapi_found"]:
        print(f"  {G}  OpenAPI :{N} found")

    # Recommendation
    print()
    if fp["login_detected"] and fp["api_detected"]:
        print(f"  {O}  Recommended: Authenticated API VAPT{N}")
    elif fp["api_detected"]:
        print(f"  {O}  Recommended: API VAPT (unauthenticated + authenticated if creds available){N}")
    elif fp["login_detected"]:
        print(f"  {O}  Recommended: Web App VAPT{N}")
    else:
        print(f"  {O}  Recommended: Recon + Vulnerability Scan{N}")

    print(f"  {W}{'─' * 56}{N}\n")


# ── HAR File Processing ───────────────────────────────────────────────────────

def process_har_file(har_file: str) -> dict:
    """Analyze a HAR file and return the analysis dict. Returns None on failure."""
    try:
        from har_analyzer import HARAnalyzer
    except ImportError as e:
        log("err", f"har_analyzer module not available: {e}")
        return None

    log("info", f"Analyzing HAR file: {har_file}")
    try:
        analysis = HARAnalyzer(har_file).analyze()
    except Exception as e:
        log("err", f"HAR analysis failed: {e}")
        return None

    if isinstance(analysis, dict) and analysis.get("error"):
        log("err", f"HAR analysis failed: {analysis['error']}")
        return None
    return analysis


def show_har_summary(analysis: dict):
    """Display HAR analysis summary (endpoints, auth, tech stack, recommendations)."""
    config = analysis.get("config", {})

    print(f"\n  {W}{'─' * 70}{N}")
    print(f"  {W}  HAR FILE ANALYSIS{N}")
    print(f"  {W}{'─' * 70}{N}")

    print(f"  {C}  Target Domain  :{N} {config.get('target_domain', 'unknown')}")
    print(f"  {C}  Total Endpoints:{N} {config.get('total_endpoints', 0)}")
    print(f"  {C}  Admin Endpoints:{N} {config.get('admin_endpoints', 0)}")
    print(f"  {C}  API Endpoints  :{N} {config.get('api_endpoints', 0)}")
    print(f"  {C}  File Uploads   :{N} {config.get('file_upload_endpoints', 0)}")

    auth = config.get("authentication", {})
    auth_type = auth.get("type", "unknown")
    print(f"  {C}  Auth Method    :{N} {auth_type}")
    if auth_type == "bearer_token":
        token = auth.get("token", "")
        token_disp = (token[:20] + "...") if len(token) > 20 else token
        print(f"  {C}  Bearer Token   :{N} {token_disp}")
    elif auth_type == "cookies":
        print(f"  {C}  Cookies        :{N} {len(auth.get('data', {}))} cookies extracted")

    tech = config.get("technology_stack", [])
    if tech:
        print(f"  {C}  Technology     :{N} {', '.join(tech)}")

    high_value = config.get("high_value_endpoints", 0)
    if high_value:
        print(f"  {G}  High-Value     :{N} {high_value} critical endpoints identified")

    tests = config.get("recommended_tests", [])
    if tests:
        shown = ", ".join(tests[:5])
        print(f"  {O}  Recommended    :{N} {shown}")
        if len(tests) > 5:
            print(f"  {D}                    + {len(tests) - 5} more tests{N}")

    print(f"  {W}{'─' * 70}{N}\n")


def run_har_vapt(analysis: dict, output_dir: str) -> str:
    """Run HAR-based authenticated VAPT. Returns path to results JSON, or None."""
    try:
        from har_vapt_engine import HARVAPTEngine
    except ImportError as e:
        log("err", f"har_vapt_engine module not available: {e}")
        return None

    log("info", "Starting HAR-based authenticated VAPT...")

    target_domain = analysis.get("config", {}).get("target_domain", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = os.path.join(output_dir, f"har_vapt_{target_domain}_{ts}.json")

    try:
        results = HARVAPTEngine(analysis).run_comprehensive_scan()
    except Exception as e:
        log("err", f"HAR VAPT engine failed: {e}")
        return None

    try:
        with open(result_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
    except Exception as e:
        log("err", f"Failed to save HAR VAPT results: {e}")
        return None

    log("ok", f"Results: {result_file}")

    vs = results.get("vulnerability_summary", {})
    print(f"\n  {W}{'─' * 56}{N}")
    print(f"  {W}  HAR VAPT RESULTS{N}")
    print(f"  {W}{'─' * 56}{N}")
    print(f"  {C}  Total   :{N} {vs.get('total_vulnerabilities', 0)}")
    print(f"  {R}  Critical:{N} {vs.get('critical', 0)}")
    print(f"  {Y}  High    :{N} {vs.get('high', 0)}")
    print(f"  {O}  Medium  :{N} {vs.get('medium', 0)}")
    print(f"  {D}  Low     :{N} {vs.get('low', 0)}")
    print(f"  {W}{'─' * 56}{N}\n")

    return result_file


# ── Ollama Detection ──────────────────────────────────────────────────────────

def ollama_available() -> bool:
    """Check if Ollama is installed and has at least one model."""
    try:
        import ollama
        models = ollama.list()
        return bool(models.get("models"))
    except Exception:
        return False


# ── Engine Routing ────────────────────────────────────────────────────────────

def run_hunt(target: str, full: bool = False, scope_lock: bool = False):
    """Route to hunt.py for domain/IP/CIDR recon + scan.

    v9.2.0 — pass PYTHONUNBUFFERED=1 to subprocess so phase markers flush in
    real time when the parent is being tee'd or run under nohup. Without this,
    long phases (cloud audit, sqlmap) appear stuck on the prior line for
    minutes because Python line-buffers stdout when it's not a TTY.
    """
    cmd = [sys.executable, "-u", os.path.join(SCRIPT_DIR, "hunt.py"),
           "--target", target]
    if full:
        cmd.append("--full")
    if scope_lock:
        cmd.append("--scope-lock")
    print(f"\n  {B}[»]{N} Launching hunt.py → {target}\n", flush=True)
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    subprocess.run(cmd, cwd=SCRIPT_DIR, env=env)


def run_legacy_crawl(target_url: str, creds: str, creds_b: str = None,
                     output_dir: str = None) -> dict:
    """Route to legacy_crawler.py for PHP/CGI/JSP app crawling + fuzzing."""
    sys.path.insert(0, SCRIPT_DIR)
    from legacy_crawler import LegacyCrawler
    crawler = LegacyCrawler(
        target_url=target_url, creds=creds, creds_b=creds_b,
        output_dir=output_dir,
    )
    results = crawler.run_comprehensive_scan()

    # Save results
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    from urllib.parse import urlparse as _up
    domain = _up(target_url).netloc.replace(":", "_")
    out_file = os.path.join(output_dir or ".", f"legacy_vapt_{domain}_{ts}.json")
    try:
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        log("ok", f"Results: {out_file}")
    except Exception as e:
        log("warn", f"Could not save results: {e}")

    vs = results.get("vulnerability_summary", {})
    print(f"\n  {W}{'─' * 56}{N}")
    print(f"  {W}  LEGACY CRAWLER RESULTS{N}")
    print(f"  {W}{'─' * 56}{N}")
    print(f"  {C}  Pages   :{N} {results.get('scan_info', {}).get('pages_crawled', 0)}")
    print(f"  {C}  Forms   :{N} {results.get('scan_info', {}).get('forms_discovered', 0)}")
    print(f"  {C}  Payloads:{N} {results.get('scan_info', {}).get('payloads_tested', 0)}")
    print(f"  {R}  Critical:{N} {vs.get('critical', 0)}")
    print(f"  {Y}  High    :{N} {vs.get('high', 0)}")
    print(f"  {O}  Medium  :{N} {vs.get('medium', 0)}")
    print(f"  {D}  Low     :{N} {vs.get('low', 0)}")
    print(f"  {W}{'─' * 56}{N}\n")

    return results


def run_api_vapt(base_url: str, creds: str, creds_b: str = None,
                 with_brain: bool = True, output_dir: str = None):
    """Route to autopilot_api_hunt.run_autopilot() for authenticated API VAPT."""
    # Import and call directly for tighter integration
    sys.path.insert(0, SCRIPT_DIR)
    from autopilot_api_hunt import run_autopilot

    result = run_autopilot(
        base_url=base_url,
        auth_creds=creds,
        auth_creds_b=creds_b,
        with_brain=with_brain,
        output_dir=output_dir,
    )
    return result


def run_brain_scan(target: str, cookies: str = "", briefing: str = "",
                   mode: str = "scan", fix_claim: str = "",
                   code_url: str = "", output_dir: str = None):
    """Route to brain_scanner.py for LLM-driven active testing."""
    sys.path.insert(0, SCRIPT_DIR)
    from brain_scanner import run_brain_scanner
    return run_brain_scanner(
        target=target, briefing=briefing, cookies=cookies,
        output_dir=output_dir, mode=mode, fix_claim=fix_claim,
        code_url=code_url,
    )


def run_report(findings_dir: str, client: str = "", consultant: str = ""):
    """Route to reporter.py for report generation."""
    cmd = [sys.executable, os.path.join(SCRIPT_DIR, "reporter.py"), findings_dir]
    if client:
        cmd.extend(["--client", client])
    if consultant:
        cmd.extend(["--consultant", consultant])
    print(f"\n  {B}[»]{N} Generating report...\n")
    subprocess.run(cmd, cwd=SCRIPT_DIR)


# ── Output Directory ──────────────────────────────────────────────────────────

def make_output_dir(target: str) -> str:
    """Create a timestamped session output directory."""
    safe_target = re.sub(r'[^a-zA-Z0-9._-]', '_', target)[:50]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(SCRIPT_DIR, "recon", safe_target, "sessions", f"{ts}_autopilot")
    os.makedirs(out_dir, exist_ok=True)
    # P1-FIX-3 — drop a per-session config.lock.json. Captures vikramaditya
    # version, external tool versions, wordlist hashes, scope-control env
    # vars and CLI args so two runs are diffable for config drift.
    try:
        sys.path.insert(0, SCRIPT_DIR)
        from whitebox.config_lock import write_session_lock
        write_session_lock(out_dir, args={"target": target, "argv": sys.argv})
    except Exception:
        pass
    return out_dir


# ── CLI Argument Parsing ──────────────────────────────────────────────────────

CLI_USAGE = """Usage:
  python3 vikramaditya.py [target] [options]

Targets:
  domain, URL, IP, CIDR, or .har file

Options:
  -h, --help              Show this help message and exit
  --creds USER:PASS       Primary test credentials
  --creds-b USER:PASS     Secondary test credentials for access-control checks
  --verify-fix PATH       Verify a deployed fix or source path
  --code-url URL          Source repository or code URL for audit context
  --legacy                Route through the legacy hunt.py flow
  --passive-only          v9.3.0 — generate Google dork catalogue and exit
                          (no active scanning; emits HTML+JSON to
                          recon/<target>/sessions/<id>/passive/).
  --skip-passive          v9.3.0 — skip the Phase-0 dork catalogue when
                          running a full scan (default: passive runs once
                          per session before active phases).
  --skip-mindmap          v9.4.0 — skip the tech-stack mind map artifact
                          (default: emitted to recon/<target>/mindmap.md
                          before active scanning).
  --intel                 v9.4.0 — fetch GHSA + NVD CVE feed for the
                          detected tech stack into recon/<target>/intel.md.
                          Auto-runs when --autonomous; explicit flag in
                          interactive mode.
  --oauth-audit URL       v9.4.0 — run oauth_tester.py (state CSRF,
                          redirect_uri bypass, password-reset host header
                          injection, etc.) against the given OAuth login
                          URL, then exit.
  --race-test URL         v9.4.0 — fire N parallel requests at URL via
                          race_audit.py to surface coupon/wallet/OTP race
                          conditions. Use --race-threads, --race-method,
                          --race-body, --header.
  --race-threads N        v9.4.0 — parallel-request count for --race-test
                          (default 30).
  --race-method M         v9.4.0 — HTTP method for --race-test (GET/POST/...)
  --race-body JSON        v9.4.0 — JSON body for --race-test.
  --header "K: V"         v9.4.0 — extra HTTP header for --race-test
                          (repeatable; e.g. Authorization).
  --cicd-audit OWNER/REPO v9.4.0 — wrap cicd_scanner.sh (sisakulint) for
                          GitHub Actions audit on the given owner/repo or
                          'org:name', then exit.
  --cloudlist             v9.5.0 — list multi-cloud assets via PD cloudlist
                          (reads ~/.config/cloudlist/config.yaml). Useful
                          for non-AWS engagements not covered by our
                          whitebox audit.
  AS<num> | asn:<num>     v9.5.0 — ASN target. asnmap expands to CIDR list,
                          each CIDR is then scanned with hunt.py. Saves
                          the full CIDR list to recon/AS<num>/cidrs.txt.
"""


def print_cli_usage() -> None:
    print(CLI_USAGE.strip())


def parse_cli_args() -> dict:
    """Parse command-line arguments. Minimal — most decisions are automatic."""
    args = {
        "target": "",
        "creds": "",
        "creds_b": "",
        "verify_fix": "",
        "code_url": "",
        "legacy": False,
        "help": False,
        # v9.3.0 — passive recon controls
        "passive_only": False,
        "skip_passive": False,
        # v9.4.0 — power-up flags
        "skip_mindmap": False,
        "intel": False,
        "oauth_audit": "",
        "race_test": "",
        "race_threads": 30,
        "race_method": "GET",
        "race_body": "",
        "extra_headers": [],
        "cicd_audit": "",
        # v9.5.0 — PD tool flags
        "cloudlist": False,
    }
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        if argv[i] in ("-h", "--help"):
            args["help"] = True; i += 1
        elif argv[i] == "--creds" and i + 1 < len(argv):
            args["creds"] = argv[i + 1]; i += 2
        elif argv[i] == "--creds-b" and i + 1 < len(argv):
            args["creds_b"] = argv[i + 1]; i += 2
        elif argv[i] == "--verify-fix" and i + 1 < len(argv):
            args["verify_fix"] = argv[i + 1]; i += 2
        elif argv[i] == "--code-url" and i + 1 < len(argv):
            args["code_url"] = argv[i + 1]; i += 2
        elif argv[i] == "--legacy":
            args["legacy"] = True; i += 1
        elif argv[i] == "--passive-only":
            args["passive_only"] = True; i += 1
        elif argv[i] == "--skip-passive":
            args["skip_passive"] = True; i += 1
        elif argv[i] == "--skip-mindmap":
            args["skip_mindmap"] = True; i += 1
        elif argv[i] == "--intel":
            args["intel"] = True; i += 1
        elif argv[i] == "--oauth-audit" and i + 1 < len(argv):
            args["oauth_audit"] = argv[i + 1]; i += 2
        elif argv[i] == "--race-test" and i + 1 < len(argv):
            args["race_test"] = argv[i + 1]; i += 2
        elif argv[i] == "--race-threads" and i + 1 < len(argv):
            try:
                args["race_threads"] = int(argv[i + 1])
            except ValueError:
                pass
            i += 2
        elif argv[i] == "--race-method" and i + 1 < len(argv):
            args["race_method"] = argv[i + 1]; i += 2
        elif argv[i] == "--race-body" and i + 1 < len(argv):
            args["race_body"] = argv[i + 1]; i += 2
        elif argv[i] == "--header" and i + 1 < len(argv):
            args["extra_headers"].append(argv[i + 1]); i += 2
        elif argv[i] == "--cicd-audit" and i + 1 < len(argv):
            args["cicd_audit"] = argv[i + 1]; i += 2
        elif argv[i] == "--cloudlist":
            args["cloudlist"] = True; i += 1
        elif not argv[i].startswith("--"):
            args["target"] = argv[i]; i += 1
        else:
            i += 1
    return args


# ── v9.5.0 — ProjectDiscovery tool wrappers ───────────────────────────────────

def _expand_asn_to_cidrs(asn: str) -> list[str]:
    """asnmap CLI: AS123456 → list of CIDR blocks. Empty list if asnmap
    is unavailable or returns nothing."""
    import shutil as _sh
    if not _sh.which("asnmap"):
        return []
    try:
        proc = subprocess.run(
            ["asnmap", "-a", asn, "-silent"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return []
    return [
        line.strip() for line in proc.stdout.splitlines()
        if line.strip() and "/" in line.strip()
    ]


def expand_cidrs(cidrs: list[str], max_hosts: int = 65536) -> list[str]:
    """mapcidr CLI: expand a list of CIDR blocks into individual IPs.

    Falls back to ipaddress stdlib when mapcidr isn't on PATH.
    Caps total at `max_hosts` to prevent expanding /8 by accident.
    """
    import shutil as _sh
    if not cidrs:
        return []
    if _sh.which("mapcidr"):
        try:
            proc = subprocess.run(
                ["mapcidr", "-cl", ",".join(cidrs), "-silent"],
                capture_output=True, text=True, timeout=60,
            )
            ips = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            return ips[:max_hosts]
        except Exception:
            pass
    # Fallback
    out: list[str] = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            for ip in net.hosts():
                out.append(str(ip))
                if len(out) >= max_hosts:
                    return out
        except ValueError:
            continue
    return out


def notify_finding(message: str, severity: str = "info") -> None:
    """Send a single-line notification via PD `notify` if configured.

    Reads $HOME/.config/notify/provider-config.yaml; silently no-ops if
    `notify` isn't installed or no provider is configured. Used to ping
    the engagement Slack/Discord/Telegram channel when a Critical finding
    lands during a long autonomous run.
    """
    import shutil as _sh
    if not _sh.which("notify"):
        return
    try:
        proc = subprocess.Popen(
            ["notify", "-bulk", "-silent", "-id", f"vikramaditya-{severity}"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc.communicate(input=message.encode(), timeout=15)
    except Exception:
        pass


def run_cloudlist(out_dir: str | None = None) -> str | None:
    """PD cloudlist — multi-provider asset listing (AWS/Azure/GCP/DO/etc.)
    using ~/.config/cloudlist/config.yaml. Useful for non-AWS engagements
    where our `whitebox/` audit doesn't apply.
    """
    import shutil as _sh
    if not _sh.which("cloudlist"):
        log("warn", "cloudlist not installed (go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest)")
        return None
    out = out_dir or os.path.join(SCRIPT_DIR, "recon", "cloudlist", "assets.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    try:
        subprocess.run(
            ["cloudlist", "-json", "-silent", "-o", out],
            cwd=SCRIPT_DIR, check=False, timeout=600,
        )
        log("ok", f"cloudlist → {out}")
        return out
    except Exception as e:
        log("warn", f"cloudlist skipped: {e}")
        return None


# ── v9.4.0 — Tier-1 power-up wrappers ─────────────────────────────────────────
# Each helper lazy-imports its module so a malformed sub-tool never breaks
# the active scanning flow. All five are best-effort: log a warning and
# continue.

def run_mindmap(target: str, target_type: str, techs: list[str]) -> str | None:
    """Generate the tech-stack mind map → recon/<target>/mindmap.md."""
    try:
        sys.path.insert(0, SCRIPT_DIR)
        import mindmap as _mm
        body = _mm.generate(target, target_type, techs) if hasattr(_mm, "generate") else None
        if body is None:
            # Older mindmap.py without generate() — fall back to a subprocess call.
            cmd = [sys.executable, "-u", os.path.join(SCRIPT_DIR, "mindmap.py"),
                   "--target", target, "--type", target_type]
            if techs:
                cmd += ["--tech", ",".join(techs)]
            subprocess.run(cmd, cwd=SCRIPT_DIR, check=False)
            return os.path.join(SCRIPT_DIR, "recon", target, "mindmap.md")
        out = os.path.join(SCRIPT_DIR, "recon", target, "mindmap.md")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as fh:
            fh.write(body)
        log("ok", f"mind map → {out}")
        return out
    except Exception as e:
        log("warn", f"mindmap skipped: {e}")
        return None


def run_intel(target: str, techs: list[str]) -> str | None:
    """Fetch GHSA + NVD CVE feed for `techs` → recon/<target>/intel.md.

    Best-effort; never breaks if the data sources are unreachable. Used
    after recon detects the live tech stack so the brain can ground its
    scan plan in fresh CVE context.
    """
    if not techs:
        return None
    try:
        sys.path.insert(0, SCRIPT_DIR)
        cmd = [sys.executable, "-u", os.path.join(SCRIPT_DIR, "intel.py"),
               "--tech", ",".join(techs), "--target", target]
        out = os.path.join(SCRIPT_DIR, "recon", target, "intel.md")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        cmd += ["--output", out]
        subprocess.run(cmd, cwd=SCRIPT_DIR, check=False, timeout=120)
        if os.path.exists(out):
            log("ok", f"CVE intel → {out}")
            return out
    except Exception as e:
        log("warn", f"intel skipped: {e}")
    return None


def run_oauth_audit(target_url: str) -> str | None:
    """Run oauth_tester.py against `target_url` → findings/<host>/oauth_audit/.

    Probes: state CSRF, redirect_uri bypass, PKCE enforcement, CORS on
    auth endpoints, password-reset host header injection, token reuse
    after logout. Generic — works against any OAuth/OIDC implementation
    (the upstream H1-specific oauth.py is intentionally NOT used).
    """
    if not target_url:
        return None
    try:
        sys.path.insert(0, SCRIPT_DIR)
        host = urlparse(target_url).netloc or target_url
        out_dir = os.path.join(SCRIPT_DIR, "findings", host, "oauth_audit")
        os.makedirs(out_dir, exist_ok=True)
        cmd = [sys.executable, "-u", os.path.join(SCRIPT_DIR, "oauth_tester.py"),
               target_url, "--output-dir", out_dir]
        subprocess.run(cmd, cwd=SCRIPT_DIR, check=False, timeout=180)
        log("ok", f"oauth_tester → {out_dir}")
        return out_dir
    except Exception as e:
        log("warn", f"oauth_audit skipped: {e}")
        return None


def run_race_audit(target_url: str, threads: int = 20,
                   method: str = "GET", body: str | None = None,
                   headers: list[str] | None = None) -> str | None:
    """Generic threaded race-condition test against `target_url`.

    Intended for explicit operator invocation via --race-test (not auto-run)
    because firing N parallel requests at a client endpoint is louder than
    the rest of the pipeline and may be blocked by WAFs.
    """
    if not target_url:
        return None
    try:
        host = urlparse(target_url).netloc or target_url.replace("/", "_")
        out = os.path.join(SCRIPT_DIR, "findings", host, "race_audit.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        cmd = [sys.executable, "-u", os.path.join(SCRIPT_DIR, "race_audit.py"),
               "--url", target_url, "--method", method, "--threads", str(threads),
               "--output", out]
        if body:
            cmd += ["--json", body]
        for h in (headers or []):
            cmd += ["--header", h]
        subprocess.run(cmd, cwd=SCRIPT_DIR, check=False, timeout=120)
        log("ok", f"race_audit → {out}")
        return out
    except Exception as e:
        log("warn", f"race_audit skipped: {e}")
        return None


def run_cicd_audit(repo_or_org: str) -> str | None:
    """Wrap cicd_scanner.sh (sisakulint) for GitHub Actions security audit.

    Accepts `owner/repo` or `org:orgname` per upstream CLI. Output lands in
    findings/<repo-or-org>/cicd/. Useful when the engagement scope includes
    the client's public GitHub org or selected repos.
    """
    if not repo_or_org:
        return None
    try:
        safe = repo_or_org.replace("/", "_").replace(":", "_")
        out_dir = os.path.join(SCRIPT_DIR, "findings", safe, "cicd")
        os.makedirs(out_dir, exist_ok=True)
        cmd = ["bash", os.path.join(SCRIPT_DIR, "cicd_scanner.sh"),
               repo_or_org, "--output-dir", out_dir]
        subprocess.run(cmd, cwd=SCRIPT_DIR, check=False, timeout=600)
        log("ok", f"cicd_audit → {out_dir}")
        return out_dir
    except Exception as e:
        log("warn", f"cicd_audit skipped: {e}")
        return None


# ── Passive recon (v9.3.0 — Google dork catalogue) ────────────────────────────

def run_passive_dorks(target: str, out_dir: str | None = None) -> str | None:
    """Generate the passive dork catalogue for `target` before active scanning.

    No requests are issued — outputs HTML/JSON/TXT under the session's
    `passive/` subdir. Imports `dorks` lazily so a malformed dorks.py does
    not break the active flow. Returns the HTML report path (for the report
    chapter) or None on failure.
    """
    try:
        sys.path.insert(0, SCRIPT_DIR)
        import dorks as _dorks
    except Exception as e:
        print(f"  {Y}[!]{N} dorks module unavailable: {e} — skipping passive phase", flush=True)
        return None
    try:
        results = _dorks.generate(target, "all")
        if out_dir is None:
            out_dir = os.path.join(SCRIPT_DIR, "recon", target, "passive")
        paths = _dorks.write_outputs(target, "all", results, out_dir)
        log("ok", f"Passive dork catalogue: {len(results)} queries → {paths['html']}")
        return paths.get("html")
    except Exception as e:
        log("warn", f"passive recon skipped: {e}")
        return None


# ── Main Flow ─────────────────────────────────────────────────────────────────

def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cli = parse_cli_args()
    if cli["help"]:
        print_cli_usage()
        return

    banner()

    # ── v9.4.0 standalone tools — run and exit before anything else ─────
    # These are operator-driven point tools, not part of the autonomous
    # pipeline. They produce findings/<host>/ artifacts and then return.
    if cli["cicd_audit"]:
        log("info", f"--cicd-audit: scanning {cli['cicd_audit']}")
        run_cicd_audit(cli["cicd_audit"])
        print(f"\n  {D}Done.{N}\n"); return
    if cli["oauth_audit"]:
        log("info", f"--oauth-audit: probing {cli['oauth_audit']}")
        run_oauth_audit(cli["oauth_audit"])
        print(f"\n  {D}Done.{N}\n"); return
    if cli["race_test"]:
        log("info", f"--race-test: {cli['race_threads']} parallel reqs → {cli['race_test']}")
        run_race_audit(
            cli["race_test"],
            threads=cli["race_threads"],
            method=cli["race_method"],
            body=cli["race_body"] or None,
            headers=cli["extra_headers"],
        )
        print(f"\n  {D}Done.{N}\n"); return
    if cli["cloudlist"]:
        log("info", "--cloudlist: enumerating multi-cloud assets")
        run_cloudlist()
        print(f"\n  {D}Done.{N}\n"); return

    has_ollama = ollama_available()

    # Autonomous mode: LLM present → no prompts, brain makes all decisions
    # Interactive mode: no LLM → ask user for every decision
    autonomous = has_ollama
    if autonomous:
        log("ok", "Autonomous mode — brain will drive all decisions")

    # ── Step 1: Get target ────────────────────────────────────────────────
    target_raw = cli["target"]
    if not target_raw:
        target_raw = prompt("Enter target (URL, domain, IP, CIDR, or .har file)")
    else:
        log("info", f"Target: {target_raw}")
    if not target_raw:
        print(f"  {R}No target provided. Exiting.{N}")
        return

    target_info = classify_target(target_raw)

    if target_info["type"] == "unknown":
        print(f"  {R}Could not parse target: {target_raw}{N}")
        return

    # ── v9.3.0 — Phase 0: passive dork catalogue ─────────────────────────
    # Runs before any active scanning so the operator has a clickable HTML
    # of search-engine queries to skim while recon spins up. No requests
    # are issued from this host. Skipped for IP / CIDR / HAR targets (no
    # apex domain to dork) and when --skip-passive is set.
    if not cli["skip_passive"] and target_info["type"] in ("domain", "url"):
        passive_target = (
            target_info["value"]
            if target_info["type"] == "domain"
            else urlparse(
                target_info["value"]
                if "://" in target_info["value"]
                else f"http://{target_info['value']}"
            ).netloc or target_info["value"]
        )
        run_passive_dorks(passive_target)

    if cli["passive_only"]:
        log("ok", "--passive-only set; exiting before active phases")
        print(f"\n  {D}Done.{N}\n")
        return

    # ── v9.4.0 — Phase 0b: tech-stack mind map artifact ──────────────────
    # Generated from the fingerprint we'll do anyway in Step 3 below; emit
    # an early stub now so the operator has a Methodology checklist while
    # active scanning runs. Refreshed later if --skip-mindmap is not set.
    if not cli["skip_mindmap"] and target_info["type"] in ("domain", "url"):
        mm_target = (
            target_info["value"]
            if target_info["type"] == "domain"
            else urlparse(
                target_info["value"]
                if "://" in target_info["value"]
                else f"http://{target_info['value']}"
            ).netloc or target_info["value"]
        )
        run_mindmap(mm_target, "website", techs=[])

    # ── Step 2: Route based on target type ────────────────────────────────

    # --- HAR file → authenticated VAPT using captured browser session ---
    if target_info["type"] == "har":
        analysis = process_har_file(target_info["value"])
        if not analysis:
            return
        show_har_summary(analysis)

        if not autonomous and not confirm("Proceed with HAR-based VAPT?"):
            print(f"  {D}Aborted.{N}")
            return

        target_domain = analysis.get("config", {}).get("target_domain", "har_target")
        output_dir = make_output_dir(target_domain)
        log("info", f"Output: {output_dir}")

        # Persist the analysis alongside the results
        try:
            with open(os.path.join(output_dir, "har_analysis.json"), "w") as f:
                json.dump(analysis, f, indent=2, default=str)
        except Exception as e:
            log("warn", f"Could not save analysis: {e}")

        result_file = run_har_vapt(analysis, output_dir)
        if result_file:
            want_report = autonomous or confirm("Generate HTML report?", default_yes=False)
            if want_report:
                try:
                    cmd = [sys.executable, os.path.join(SCRIPT_DIR, "reporter.py"), result_file]
                    subprocess.run(cmd, cwd=SCRIPT_DIR)
                except Exception as e:
                    log("warn", f"Report generation failed: {e}")
        print(f"\n  {D}Done.{N}\n")
        return

    # --- ASN → expand to CIDRs, then iterate ---
    if target_info["type"] == "asn":
        cidrs = target_info.get("cidrs", [])
        log("info", f"ASN {target_info['value']} → {len(cidrs)} CIDR blocks")
        for c in cidrs[:25]:  # safety cap; full list saved to recon/<asn>/cidrs.txt
            log("info", f"  {c}")
        # Persist the CIDR list for the report
        asn_dir = os.path.join(SCRIPT_DIR, "recon", target_info["value"])
        os.makedirs(asn_dir, exist_ok=True)
        with open(os.path.join(asn_dir, "cidrs.txt"), "w") as fh:
            fh.write("\n".join(cidrs) + "\n")
        if not autonomous and not confirm(f"Proceed with hunt against {len(cidrs)} CIDR(s)?"):
            print(f"  {D}Aborted.{N}")
            return
        for c in cidrs:
            run_hunt(c, full=True)
        return

    # --- CIDR / IP → hunt.py directly ---
    if target_info["type"] in ("cidr", "ip"):
        show_summary(target_info)
        if not autonomous and not confirm("Proceed with scan?"):
            print(f"  {D}Aborted.{N}")
            return
        run_hunt(target_info["value"])
        return

    # --- Bare domain → hunt.py ---
    if target_info["type"] == "domain":
        url_to_check = f"https://{target_info['value']}"
        log("info", f"Checking {url_to_check} ...")
        fp = fingerprint_webapp(url_to_check)

        if fp["error"] or fp["status"] == 0:
            show_summary(target_info)
            if not autonomous and not confirm("Proceed with recon + vulnerability scan?"):
                print(f"  {D}Aborted.{N}")
                return
            # v9.2.0 (P0-1) — previously the whitebox audit was only invoked
            # in the URL-fingerprint-success branch below, which meant
            # autonomous runs against bare domains whose HTTPS apex returned
            # 0 (or errored) silently skipped cloud audit even when the
            # profile mapped. Fire it here too.
            _maybe_run_whitebox_for_target(
                target_info["value"],
                os.path.join(SCRIPT_DIR, "recon", target_info["value"]),
                autonomous=autonomous,
            )
            run_hunt(target_info["value"], full=True)
            return
        else:
            target_info = classify_target(url_to_check)

    # --- URL → fingerprint and decide ---
    url = target_info["value"]
    if not url.startswith("http"):
        url = f"https://{url}"

    log("info", "Fingerprinting target...")
    fp = fingerprint_webapp(url)

    if fp["error"]:
        print(f"  {R}Error reaching target: {fp['error']}{N}")
        if cli["creds"]:
            # Creds provided — try autopilot anyway (server may respond to API calls)
            log("info", "Credentials provided — will attempt autopilot despite fingerprint failure")
        else:
            if not autonomous and not confirm("Try recon-only scan anyway?"):
                return
            run_hunt(urlparse(url).netloc)
            return

    show_summary(target_info, fp)

    if not autonomous and not confirm("Proceed?"):
        print(f"  {D}Aborted.{N}")
        return

    # ── v9.4.0 — refresh mind map with detected tech, fetch CVE intel ────
    # show_summary populates fp["tech"] with the techs we just detected.
    # Refresh the early-stub mindmap.md with that real list so the
    # operator's Methodology checklist is accurate. Auto-fetch CVE intel
    # from GHSA + NVD when --intel is set or autonomous mode is on.
    detected_techs = [t.lower() for t in (fp.get("tech") or [])]
    detected_host = urlparse(url).netloc or url
    if not cli["skip_mindmap"] and detected_techs:
        run_mindmap(detected_host, "website", detected_techs)
    if (cli["intel"] or autonomous) and detected_techs:
        run_intel(detected_host, detected_techs)

    # ── Whitebox: offer cloud audit if target matches a configured profile ─
    _maybe_run_whitebox_for_target(urlparse(url).netloc, os.path.join(SCRIPT_DIR, "recon", urlparse(url).netloc), autonomous=autonomous)

    # ── Step 3: Credentials ───────────────────────────────────────────────
    creds = cli["creds"] or None
    creds_b = cli["creds_b"] or None
    api_base = fp.get("api_base") or url

    # Only ask for credentials if login detected and not provided via CLI
    if not creds and (fp["login_detected"] or fp["api_detected"]):
        if autonomous:
            log("info", "Login detected but no --creds provided. Running unauthenticated scan.")
            log("info", "  Tip: python3 vikramaditya.py TARGET --creds user:pass")
        else:
            if confirm("Do you have credentials?"):
                username = prompt("Username / email")
                password = getpass.getpass(f"  {C}Password: {N}")
                if username and password:
                    creds = f"{username}:{password}"

                    if confirm("Second account for IDOR / privilege escalation testing?", default_yes=False):
                        username_b = prompt("Second account username / email")
                        password_b = getpass.getpass(f"  {C}Second account password: {N}")
                        if username_b and password_b:
                            creds_b = f"{username_b}:{password_b}"

    # ── Step 4: Brain — auto-enabled in autonomous mode ───────────────────
    with_brain = has_ollama
    use_brain_scanner = has_ollama  # Brain scanner auto-enabled when LLM present

    if not autonomous and has_ollama:
        if not confirm("AI brain supervisor: enabled. Keep enabled?"):
            with_brain = False
        if not confirm("Run brain active scanner?", default_yes=False):
            use_brain_scanner = False

    if with_brain:
        log("ok", "Brain supervisor: enabled")
    if use_brain_scanner:
        log("ok", "Brain active scanner: enabled")
    if not has_ollama:
        log("info", "Ollama not installed — running without AI brain")

    # ── Step 4b: Fix verification mode ────────────────────────────────────
    verify_fix_mode = False
    fix_claim = cli["verify_fix"]
    code_url = cli["code_url"]
    if fix_claim:
        verify_fix_mode = True
    elif not autonomous and has_ollama:
        if confirm("Verify a developer's fix claim?", default_yes=False):
            verify_fix_mode = True
            fix_claim = prompt("What does the developer claim they fixed?")
            code_url = prompt("URL to the fixed code (leave blank to auto-discover)", "")

    # ── Step 5: Route to engine ───────────────────────────────────────────

    # --- Fix verification mode → brain_scanner --verify-fix ---
    if verify_fix_mode and fix_claim:
        output_dir = make_output_dir(urlparse(url).netloc)
        cookie_str = ""
        if creds:
            cookie_str = f"(creds available: {creds.split(':')[0]})"
        log("info", f"Output: {output_dir}")
        print()
        run_brain_scan(
            target=url,
            mode="verify-fix",
            fix_claim=fix_claim,
            code_url=code_url,
            cookies=cookie_str,
            output_dir=os.path.join(output_dir, "brain_verify"),
        )
        print(f"\n  {D}Done.{N}\n")
        return

    if creds:
        output_dir = make_output_dir(urlparse(url).netloc)
        log("info", f"Output: {output_dir}")
        print()

        # Detect legacy app: no JS bundles, no API, PHP/CGI/JSP indicators
        is_legacy = cli.get("legacy", False)
        if not is_legacy and fp:
            legacy_tech = any(t in str(fp.get("tech", [])).lower()
                             for t in ["php", "cgi", "jsp", "asp", "coldfusion"])
            no_spa = fp.get("js_chunks", 0) == 0
            no_api = not fp.get("api_detected", False)
            has_login = fp.get("login_detected", False)
            is_legacy = legacy_tech or (no_spa and no_api and has_login)

        if is_legacy:
            log("ok", "Legacy app detected — using browser-based crawler + fuzzer")
            try:
                result = run_legacy_crawl(
                    target_url=url,
                    creds=creds,
                    creds_b=creds_b,
                    output_dir=output_dir,
                )
                findings_dir = output_dir
                if result and result.get("vulnerabilities"):
                    print(f"\n  {G}Legacy crawler complete.{N} {len(result['vulnerabilities'])} finding(s).\n")
                else:
                    print(f"\n  {D}Legacy crawler complete. No findings.{N}")
                    findings_dir = None
            except ImportError:
                log("warn", "playwright not installed — falling back to API autopilot")
                log("info", "  Install: pip install playwright && playwright install chromium")
                is_legacy = False
            except Exception as e:
                log("err", f"Legacy crawler failed: {e}")
                log("info", "Falling back to API autopilot...")
                is_legacy = False

        if not is_legacy:
            # Authenticated API VAPT (modern SPA/REST apps)
            result = run_api_vapt(
                base_url=api_base,
                creds=creds,
                creds_b=creds_b,
                with_brain=with_brain,
                output_dir=output_dir,
            )

        # ── Step 6: Post-scan ─────────────────────────────────────────────
        if result and result.get("findings"):
            findings = result["findings"]
            print(f"\n  {G}Autopilot complete.{N} {len(findings)} finding(s).\n")
            findings_dir = os.path.join(output_dir, "autopilot")
        else:
            print(f"\n  {D}Autopilot complete. No findings.{N}")
            findings_dir = None
            # Fallback: run tools directly on target when autopilot finds nothing
            # (legacy apps where REST endpoint patterns don't match)
            if autonomous:
                log("info", "Running direct tool scan (sqlmap + nuclei) on base URL...")
                try:
                    import subprocess as _sp
                    # sqlmap on the login form
                    log("info", "  sqlmap on login form...")
                    _sp.run(["sqlmap", "-u", api_base,
                             "--forms", "--batch", "--level=3", "--risk=2",
                             "--random-agent", "--current-db",
                             "--output-dir", os.path.join(output_dir, "sqlmap")],
                            timeout=180, capture_output=True)
                except Exception as e:
                    log("warn", f"  sqlmap: {e}")
                try:
                    # nuclei on base URL
                    log("info", "  nuclei CVE scan...")
                    _sp.run(["nuclei", "-u", api_base,
                             "-severity", "critical,high,medium", "-silent",
                             "-o", os.path.join(output_dir, "nuclei_results.txt")],
                            timeout=120, capture_output=True)
                except Exception as e:
                    log("warn", f"  nuclei: {e}")

    elif not creds:
        # No creds — run hunt.py for unauthenticated scan
        domain = urlparse(url).netloc
        scope_lock = autonomous or (not autonomous and confirm("Scope lock? (scan this exact host only, no subdomain expansion)", default_yes=False))
        log("info", "No credentials — running unauthenticated recon + vulnerability scan")
        print()
        run_hunt(domain, full=True, scope_lock=scope_lock)

        # Post-scan: check if there are findings to report
        # hunt.py stores findings in findings/<domain>/sessions/<id>/ (not recon/)
        print()
        if confirm("Generate report from scan results?", default_yes=False):
            # Try both findings/ and recon/ paths (hunt.py uses findings/)
            found_dir = None
            for base_name in ["findings", "recon"]:
                sessions_base = os.path.join(SCRIPT_DIR, base_name, domain, "sessions")
                if os.path.isdir(sessions_base):
                    sessions = sorted(os.listdir(sessions_base), reverse=True)
                    for sess in sessions:
                        candidate = os.path.join(sessions_base, sess)
                        # Check for findings in the session root or a findings/ subdirectory
                        if os.path.isdir(os.path.join(candidate, "findings")):
                            found_dir = os.path.join(candidate, "findings")
                            break
                        # Also check for finding_*.json or subdirs with .txt files directly in session
                        has_data = any(
                            f.endswith('.json') or f.endswith('.txt')
                            for f in os.listdir(candidate)
                            if os.path.isfile(os.path.join(candidate, f))
                        ) or any(
                            os.path.isdir(os.path.join(candidate, d))
                            for d in os.listdir(candidate)
                            if d in ('exploits', 'sqli', 'xss', 'cors', 'secrets', 'cves', 'sqlmap')
                        )
                        if has_data:
                            found_dir = candidate
                            break
                if found_dir:
                    break

            if found_dir:
                client = prompt("Client name", "")
                consultant = prompt("Consultant name", "")
                run_report(found_dir, client, consultant)
            else:
                print(f"  {Y}No findings directory found for {domain}{N}")
                print(f"  {D}Searched: findings/{domain}/sessions/ and recon/{domain}/sessions/{N}")

    # ── Brain active scanner follow-up ───────────────────────────────────
    if use_brain_scanner and has_ollama:
        # Use the API base if detected (not the SPA frontend)
        brain_target = url
        try:
            if fp and fp.get("api_base"):
                brain_target = fp["api_base"]
            elif api_base and api_base != url:
                brain_target = api_base
        except NameError:
            pass
        log("info", f"Launching brain active scanner on {brain_target}...")
        brain_out = make_output_dir(urlparse(url).netloc)
        run_brain_scan(
            target=brain_target,
            mode="scan",
            output_dir=os.path.join(brain_out, "brain_active"),
        )

    # ── Report generation (after ALL testing is complete) ─────────────────
    try:
        if findings_dir and os.path.isdir(findings_dir):
            print()
            if autonomous:
                # Auto-generate report in autonomous mode
                log("info", "Auto-generating report...")
                run_report(findings_dir)
            elif confirm("Generate report?", default_yes=False):
                client = prompt("Client name", "")
                consultant = prompt("Consultant name", "")
                run_report(findings_dir, client, consultant)
    except NameError:
        pass  # findings_dir not set (e.g., hunt.py path handles its own report)

    print(f"\n  {D}Done.{N}\n")


if __name__ == "__main__":
    # v9.2.0 (P3-11) — record per-run wall-time and exit status to
    # logs/vikram_runs.csv. Used to answer "how long did $domain take?" without
    # re-parsing the per-domain log file.
    _started = time.time()
    _target_for_log = sys.argv[1] if len(sys.argv) > 1 else "(interactive)"
    _exit_code = 0
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Y}Interrupted.{N}\n")
        _exit_code = 130
    except SystemExit as _se:
        _exit_code = int(_se.code) if isinstance(_se.code, int) else 1
        raise
    except Exception:
        _exit_code = 1
        raise
    finally:
        _append_run_log(_target_for_log, _started, _exit_code)
    if _exit_code:
        sys.exit(_exit_code)

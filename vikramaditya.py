#!/usr/bin/env python3
"""
Vikramaditya — One command to rule them all.

v8.0.0 — Dual-track VAPT orchestrator. Blackbox engine (recon, fuzz, scan,
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
    """Route to hunt.py for domain/IP/CIDR recon + scan."""
    cmd = [sys.executable, os.path.join(SCRIPT_DIR, "hunt.py"),
           "--target", target]
    if full:
        cmd.append("--full")
    if scope_lock:
        cmd.append("--scope-lock")
    print(f"\n  {B}[»]{N} Launching hunt.py → {target}\n")
    subprocess.run(cmd, cwd=SCRIPT_DIR)


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
        elif not argv[i].startswith("--"):
            args["target"] = argv[i]; i += 1
        else:
            i += 1
    return args


# ── Main Flow ─────────────────────────────────────────────────────────────────

def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cli = parse_cli_args()
    if cli["help"]:
        print_cli_usage()
        return

    banner()

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
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Y}Interrupted.{N}\n")
        sys.exit(130)

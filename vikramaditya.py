#!/usr/bin/env python3
"""
Vikramaditya — One command to rule them all.

Interactive VAPT orchestrator. Give it a target, it figures out the rest.

Usage:
    python3 vikramaditya.py
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
    """Prompt user for input with optional default."""
    if default:
        raw = input(f"{C}  {text} [{default}]: {N}").strip()
        return raw or default
    return input(f"{C}  {text}: {N}").strip()


def confirm(text: str, default_yes: bool = True) -> bool:
    """Yes/no confirmation."""
    hint = "Y/n" if default_yes else "y/N"
    raw = input(f"{C}  {text} [{hint}]: {N}").strip().lower()
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
    """Classify target as cidr, ip, domain, or url."""
    target = target.strip()

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
            # Count API-like paths
            api_paths = set()
            for pat in [r'\.(get|post|put|patch|delete)\("[^"]*"',
                        r'fetch\(["`\'][^"`\']+["`\']']:
                api_paths.update(re.findall(pat, js_resp.text))
            result["js_endpoints"] = len(api_paths)

            # Login detection from JS
            login_patterns = re.findall(r'"(/(?:auth/)?(?:login|sign-in|signin)[^"]*)"', js_resp.text)
            if login_patterns:
                result["login_detected"] = True
                result["login_paths"] = list(set(login_patterns))
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


# ── Main Interactive Flow ─────────────────────────────────────────────────────

def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    banner()

    # ── Step 1: Get target ────────────────────────────────────────────────
    # Accept target from command line args OR interactive prompt
    target_raw = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""
    if not target_raw:
        target_raw = prompt("Enter target (URL, domain, IP, or CIDR)")
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

    # --- CIDR / IP → hunt.py directly ---
    if target_info["type"] in ("cidr", "ip"):
        show_summary(target_info)
        if not confirm("Proceed with scan?"):
            print(f"  {D}Aborted.{N}")
            return
        run_hunt(target_info["value"])
        return

    # --- Bare domain → hunt.py ---
    if target_info["type"] == "domain":
        # Quick check: is there a web app at https://domain?
        url_to_check = f"https://{target_info['value']}"
        log("info", f"Checking {url_to_check} ...")
        fp = fingerprint_webapp(url_to_check)

        if fp["error"] or fp["status"] == 0:
            # No web app responding — pure domain recon
            show_summary(target_info)
            if not confirm("Proceed with recon + vulnerability scan?"):
                print(f"  {D}Aborted.{N}")
                return
            scope_lock = confirm("Scope lock? (scan this exact domain only, no subdomain expansion)", default_yes=False)
            run_hunt(target_info["value"], full=True, scope_lock=scope_lock)
            return
        else:
            # Web app found — treat it as a URL
            target_info = classify_target(url_to_check)
            # Fall through to URL handling below

    # --- URL → fingerprint and decide ---
    url = target_info["value"]
    if not url.startswith("http"):
        url = f"https://{url}"

    log("info", "Fingerprinting target...")
    fp = fingerprint_webapp(url)

    if fp["error"]:
        print(f"  {R}Error reaching target: {fp['error']}{N}")
        if not confirm("Try recon-only scan anyway?"):
            return
        run_hunt(urlparse(url).netloc)
        return

    show_summary(target_info, fp)

    if not confirm("Proceed?"):
        print(f"  {D}Aborted.{N}")
        return

    # ── Step 3: Collect credentials if login detected ─────────────────────
    creds = None
    creds_b = None
    api_base = fp.get("api_base") or url

    if fp["login_detected"] or fp["api_detected"]:
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

    # ── Step 4: Brain options ─────────────────────────────────────────────
    has_ollama = ollama_available()
    with_brain = False
    use_brain_scanner = False
    if has_ollama:
        with_brain = True
        if not confirm("AI brain supervisor: enabled. Keep enabled?"):
            with_brain = False
            log("info", "Brain disabled")
        else:
            log("ok", "Brain supervisor enabled")

        # Offer brain scanner for deeper testing
        if confirm("Run brain active scanner? (LLM writes + executes exploit code)", default_yes=False):
            use_brain_scanner = True
    else:
        log("info", "Ollama not installed — running without AI brain")

    # ── Step 4b: Fix verification mode ────────────────────────────────────
    verify_fix_mode = False
    fix_claim = ""
    code_url = ""
    if has_ollama and confirm("Verify a developer's fix claim?", default_yes=False):
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

    if creds and fp["api_detected"]:
        # Authenticated API VAPT
        output_dir = make_output_dir(urlparse(url).netloc)
        log("info", f"Output: {output_dir}")
        print()

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
            print(f"\n  {G}Scan complete.{N} {len(findings)} finding(s).\n")

            # Findings directory for reporter
            findings_dir = os.path.join(output_dir, "autopilot")

            if confirm("Generate report?", default_yes=False):
                client = prompt("Client name", "")
                consultant = prompt("Consultant name", "")
                run_report(findings_dir, client, consultant)
        else:
            print(f"\n  {D}Scan complete. No findings.{N}\n")

    elif creds:
        # Has creds but no clear API — try API VAPT on the URL itself
        output_dir = make_output_dir(urlparse(url).netloc)
        log("info", f"Output: {output_dir}")
        print()

        result = run_api_vapt(
            base_url=url.rstrip("/"),
            creds=creds,
            creds_b=creds_b,
            with_brain=with_brain,
            output_dir=output_dir,
        )

        if result and result.get("findings"):
            findings = result["findings"]
            print(f"\n  {G}Scan complete.{N} {len(findings)} finding(s).\n")
            findings_dir = os.path.join(output_dir, "autopilot")

            if confirm("Generate report?", default_yes=False):
                client = prompt("Client name", "")
                consultant = prompt("Consultant name", "")
                run_report(findings_dir, client, consultant)
        else:
            print(f"\n  {D}Scan complete. No findings.{N}\n")

    elif not creds:
        # No creds — run hunt.py for unauthenticated scan
        domain = urlparse(url).netloc
        scope_lock = confirm("Scope lock? (scan this exact host only, no subdomain expansion)", default_yes=False)
        log("info", "No credentials — running unauthenticated recon + vulnerability scan")
        print()
        run_hunt(domain, full=True, scope_lock=scope_lock)

        # Post-scan: check if there are findings to report
        # hunt.py manages its own output, so just offer the report prompt
        print()
        if confirm("Generate report from scan results?", default_yes=False):
            # Find the latest session dir
            sessions_base = os.path.join(SCRIPT_DIR, "recon", domain, "sessions")
            if os.path.isdir(sessions_base):
                sessions = sorted(os.listdir(sessions_base), reverse=True)
                if sessions:
                    findings_dir = os.path.join(sessions_base, sessions[0], "findings")
                    if os.path.isdir(findings_dir):
                        client = prompt("Client name", "")
                        consultant = prompt("Consultant name", "")
                        run_report(findings_dir, client, consultant)
                    else:
                        print(f"  {Y}No findings directory found at {findings_dir}{N}")
            else:
                print(f"  {Y}No scan sessions found for {domain}{N}")

    # ── Brain active scanner follow-up ───────────────────────────────────
    if use_brain_scanner and has_ollama:
        log("info", "Launching brain active scanner — LLM writes + executes exploit code...")
        brain_out = make_output_dir(urlparse(url).netloc)
        run_brain_scan(
            target=url,
            mode="scan",
            output_dir=os.path.join(brain_out, "brain_active"),
        )

    print(f"\n  {D}Done.{N}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Y}Interrupted.{N}\n")
        sys.exit(130)

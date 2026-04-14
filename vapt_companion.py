#!/usr/bin/env python3
"""
VAPT Companion - Integration tool for combining Vikramaditya with HAR-based testing
Provides unified workflow without modifying original vikramaditya.py

Usage:
    python3 vapt_companion.py <target>           # Auto-detect and route
    python3 vapt_companion.py --full <domain>    # Complete assessment (infra + web)
    python3 vapt_companion.py --har <har_file>   # HAR-based testing only
"""

import argparse
import os
import subprocess
import sys
from urllib.parse import urlparse

# Colors
O = "\033[38;5;208m"   # Orange
W = "\033[1;37m"       # White bold
G = "\033[0;32m"       # Green
R = "\033[0;31m"       # Red
Y = "\033[1;33m"       # Yellow
C = "\033[0;36m"       # Cyan
N = "\033[0m"          # Reset

def banner():
    print(f"""
{O} ██╗   ██╗ █████╗ ██████╗ ████████╗     ██████╗ ██████╗ ███╗   ███╗██████╗ ███╗   ███╗{N}
{O} ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔═══██╗████╗ ████║██╔══██╗████╗ ████║{N}
{W} ██║   ██║███████║██████╔╝   ██║       ██║     ██║   ██║██╔████╔██║██████╔╝██╔████╔██║{N}
{W} ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║       ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║╚██╔╝██║{N}
{G}  ╚████╔╝ ██║  ██║██║        ██║       ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ██║ ╚═╝ ██║{N}
{G}   ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝        ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝     ╚═╝{N}
{C}            Unified VAPT Platform - Infrastructure + Authenticated Testing{N}
""")

def log(level: str, msg: str):
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    colors = {"ok": G, "err": R, "warn": Y, "info": C}
    sym = symbols.get(level, "*")
    col = colors.get(level, "")
    print(f"  {col}[{sym}]{N} {msg}", flush=True)

def classify_target(target: str) -> dict:
    """Classify target type"""
    target = target.strip()

    # HAR file
    if target.endswith('.har') and os.path.isfile(target):
        return {"type": "har", "value": target, "original": target}

    # URL with scheme
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return {"type": "url", "value": target, "host": parsed.netloc, "original": target}

    # Domain
    if "." in target and not "/" in target:
        return {"type": "domain", "value": target, "original": target}

    # IP or CIDR
    return {"type": "unknown", "value": target, "original": target}

def run_infrastructure_vapt(target: str) -> bool:
    """Run infrastructure VAPT using original vikramaditya.py"""
    log("info", f"Running infrastructure VAPT: {target}")

    if not os.path.exists("vikramaditya.py"):
        log("err", "vikramaditya.py not found in current directory")
        return False

    try:
        cmd = [sys.executable, "vikramaditya.py", target]
        result = subprocess.run(cmd, capture_output=False, text=True)
        return result.returncode == 0
    except Exception as e:
        log("err", f"Infrastructure VAPT failed: {e}")
        return False

def run_har_vapt(har_file: str) -> bool:
    """Run HAR-based VAPT testing"""
    log("info", f"Running HAR-based VAPT: {har_file}")

    if not os.path.exists("har_vapt.py"):
        log("err", "har_vapt.py not found in current directory")
        return False

    try:
        cmd = [sys.executable, "har_vapt.py", har_file]
        result = subprocess.run(cmd, capture_output=False, text=True)
        return result.returncode == 0
    except Exception as e:
        log("err", f"HAR VAPT failed: {e}")
        return False

def run_combined_assessment(domain: str) -> dict:
    """Run combined infrastructure + web application assessment"""
    log("info", f"Starting comprehensive assessment: {domain}")

    results = {
        "infrastructure": False,
        "web_app": False,
        "har_files_processed": []
    }

    # Step 1: Infrastructure VAPT
    print(f"\n{C}Phase 1: Infrastructure Assessment{N}")
    print("─" * 50)
    results["infrastructure"] = run_infrastructure_vapt(domain)

    if results["infrastructure"]:
        log("ok", "Infrastructure assessment completed")
    else:
        log("warn", "Infrastructure assessment had issues")

    # Step 2: Look for HAR files to process
    print(f"\n{C}Phase 2: Authenticated Web Application Testing{N}")
    print("─" * 50)

    # Search for HAR files
    search_dirs = [
        ".",
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Downloads")
    ]

    har_files = []
    for search_dir in search_dirs:
        try:
            for file in os.listdir(search_dir):
                if file.endswith('.har'):
                    full_path = os.path.join(search_dir, file)
                    # Basic check if HAR contains target domain
                    try:
                        with open(full_path, 'r') as f:
                            content = f.read(1000)  # Read first 1KB
                            if domain in content:
                                har_files.append(full_path)
                    except:
                        continue
        except:
            continue

    if har_files:
        log("info", f"Found {len(har_files)} HAR files containing target domain")
        for har_file in har_files:
            log("info", f"Processing: {os.path.basename(har_file)}")
            if run_har_vapt(har_file):
                results["har_files_processed"].append(har_file)
                results["web_app"] = True

        if results["har_files_processed"]:
            log("ok", f"Processed {len(results['har_files_processed'])} HAR files successfully")
        else:
            log("warn", "No HAR files processed successfully")
    else:
        log("warn", f"No HAR files found containing domain: {domain}")
        print(f"\n{Y}Manual HAR capture recommended:{N}")
        print(f"  1. Open browser and navigate to https://{domain}")
        print(f"  2. Open Developer Tools (F12) → Network tab")
        print(f"  3. Perform authenticated actions (login, admin functions)")
        print(f"  4. Save as HAR file and run:")
        print(f"     python3 har_vapt.py session.har")

    return results

def interactive_workflow():
    """Interactive workflow for target selection"""
    print(f"\n{W}VAPT Companion - Interactive Mode{N}")
    print("─" * 40)

    print(f"\n{C}What would you like to assess?{N}")
    print(f"  1. Infrastructure only (domain/IP/CIDR)")
    print(f"  2. HAR-based authenticated testing")
    print(f"  3. Complete assessment (infrastructure + web app)")

    choice = input(f"\n{C}Select option [1-3]: {N}").strip()

    if choice == "1":
        target = input(f"{C}Enter target (domain, IP, or CIDR): {N}").strip()
        if target:
            run_infrastructure_vapt(target)

    elif choice == "2":
        # List available HAR files
        search_dirs = [".", os.path.expanduser("~/Documents"), os.path.expanduser("~/Downloads")]
        har_files = []

        for search_dir in search_dirs:
            try:
                for file in os.listdir(search_dir):
                    if file.endswith('.har'):
                        har_files.append(os.path.join(search_dir, file))
            except:
                continue

        if har_files:
            print(f"\n{C}Available HAR files:{N}")
            for i, har_file in enumerate(har_files[:10], 1):
                print(f"  {i}. {os.path.basename(har_file)}")

            try:
                selection = int(input(f"\n{C}Select HAR file [1-{min(10, len(har_files))}]: {N}"))
                if 1 <= selection <= min(10, len(har_files)):
                    run_har_vapt(har_files[selection - 1])
                else:
                    log("err", "Invalid selection")
            except ValueError:
                har_path = input(f"{C}Enter HAR file path: {N}").strip()
                if os.path.isfile(har_path):
                    run_har_vapt(har_path)
                else:
                    log("err", "HAR file not found")
        else:
            har_path = input(f"{C}Enter HAR file path: {N}").strip()
            if os.path.isfile(har_path):
                run_har_vapt(har_path)
            else:
                log("err", "HAR file not found")

    elif choice == "3":
        domain = input(f"{C}Enter domain: {N}").strip()
        if domain:
            results = run_combined_assessment(domain)

            print(f"\n{W}Assessment Summary:{N}")
            print(f"  Infrastructure VAPT: {'✅' if results['infrastructure'] else '❌'}")
            print(f"  Web App VAPT: {'✅' if results['web_app'] else '❌'}")
            print(f"  HAR files processed: {len(results['har_files_processed'])}")

    else:
        log("err", "Invalid choice")

def main():
    parser = argparse.ArgumentParser(
        description="VAPT Companion - Unified infrastructure and web application testing",
        epilog="Examples:\n"
               "  python3 vapt_companion.py example.com          # Auto-detect approach\n"
               "  python3 vapt_companion.py --full example.com   # Complete assessment\n"
               "  python3 vapt_companion.py --har session.har    # HAR testing only\n"
               "  python3 vapt_companion.py --interactive        # Interactive mode",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("target", nargs="?", help="Target domain, URL, IP, CIDR, or HAR file")
    parser.add_argument("--full", "-f", help="Run complete assessment (infrastructure + web app)")
    parser.add_argument("--har", help="Run HAR-based testing only")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")

    args = parser.parse_args()

    banner()

    if args.interactive:
        interactive_workflow()
        return

    if args.har:
        if os.path.isfile(args.har):
            run_har_vapt(args.har)
        else:
            log("err", f"HAR file not found: {args.har}")
        return

    if args.full:
        run_combined_assessment(args.full)
        return

    if args.target:
        target_info = classify_target(args.target)

        if target_info["type"] == "har":
            run_har_vapt(target_info["value"])

        elif target_info["type"] in ["domain", "url"]:
            domain = target_info["host"] if target_info["type"] == "url" else target_info["value"]

            print(f"\n{C}Assessment Options for {domain}:{N}")
            print(f"  1. Infrastructure only (subdomain enum + port scan + vuln scan)")
            print(f"  2. Complete assessment (infrastructure + authenticated web testing)")

            choice = input(f"\n{C}Select option [1-2]: {N}").strip()

            if choice == "2":
                run_combined_assessment(domain)
            else:
                run_infrastructure_vapt(target_info["value"])

        else:
            # Fallback to original vikramaditya for unknown targets
            run_infrastructure_vapt(target_info["value"])

    else:
        interactive_workflow()

if __name__ == "__main__":
    main()
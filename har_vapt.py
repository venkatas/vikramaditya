#!/usr/bin/env python3
"""
HAR VAPT - Standalone HAR-based Vulnerability Assessment Platform
Works alongside the original Vikramaditya platform without modification

Usage:
    python3 har_vapt.py <har_file>
    python3 har_vapt.py --analyze <har_file>
    python3 har_vapt.py --test <analysis_file>
"""

import argparse
import json
import os
import sys
from datetime import datetime
from har_analyzer import HARAnalyzer
from har_vapt_engine import HARVAPTEngine

# Colors
O = "\033[38;5;208m"   # Orange
W = "\033[1;37m"       # White bold
D = "\033[0;90m"       # Dim
G = "\033[0;32m"       # Green
R = "\033[0;31m"       # Red
Y = "\033[1;33m"       # Yellow
C = "\033[0;36m"       # Cyan
B = "\033[0;34m"       # Blue
N = "\033[0m"          # Reset

def banner():
    print(f"""
{O} ██╗  ██╗ █████╗ ██████╗     ██╗   ██╗ █████╗ ██████╗ ████████╗{N}
{O} ██║  ██║██╔══██╗██╔══██╗    ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝{N}
{W} ███████║███████║██████╔╝    ██║   ██║███████║██████╔╝   ██║   {N}
{W} ██╔══██║██╔══██║██╔══██╗    ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   {N}
{G} ██║  ██║██║  ██║██║  ██║     ╚████╔╝ ██║  ██║██║        ██║   {N}
{G} ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝      ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   {N}
{B}     Standalone HAR-based Vulnerability Assessment Platform{N}
{D}              Companion tool for Vikramaditya VAPT Suite{N}
""")

def log(level: str, msg: str):
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    colors = {"ok": G, "err": R, "warn": Y, "info": C}
    sym = symbols.get(level, "*")
    col = colors.get(level, "")
    print(f"  {col}[{sym}]{N} {msg}", flush=True)

def analyze_har_file(har_file: str) -> str:
    """Analyze HAR file and return analysis file path"""

    if not os.path.isfile(har_file):
        log("err", f"HAR file not found: {har_file}")
        return None

    log("info", f"Analyzing HAR file: {har_file}")

    analyzer = HARAnalyzer(har_file)
    analysis = analyzer.analyze()

    if 'error' in analysis:
        log("err", f"Analysis failed: {analysis['error']}")
        return None

    # Save analysis results
    analysis_file = har_file.replace('.har', '_analysis.json')
    analyzer.save_analysis(analysis_file, analysis)

    # Display summary
    config = analysis['config']
    print(f"\n  {W}{'─' * 60}{N}")
    print(f"  {W}  HAR ANALYSIS SUMMARY{N}")
    print(f"  {W}{'─' * 60}{N}")
    print(f"  {C}Target Domain     :{N} {config.get('target_domain', 'Unknown')}")
    print(f"  {C}Total Endpoints   :{N} {config.get('total_endpoints', 0)}")
    print(f"  {C}Admin Endpoints   :{N} {config.get('admin_endpoints', 0)}")
    print(f"  {C}API Endpoints     :{N} {config.get('api_endpoints', 0)}")
    print(f"  {C}File Uploads      :{N} {config.get('file_upload_endpoints', 0)}")
    print(f"  {C}High-Value Targets:{N} {config.get('high_value_endpoints', 0)}")

    auth = config.get('authentication', {})
    auth_type = auth.get('type', 'unknown')
    print(f"  {C}Authentication    :{N} {auth_type}")

    if auth_type == 'bearer_token':
        token_preview = auth.get('token', '')[:20] + '...' if len(auth.get('token', '')) > 20 else auth.get('token', '')
        print(f"  {C}Bearer Token      :{N} {token_preview}")
    elif auth_type == 'cookies':
        cookie_count = len(auth.get('data', {}))
        print(f"  {C}Session Cookies   :{N} {cookie_count} extracted")

    tests = config.get('recommended_tests', [])
    print(f"  {O}Recommended Tests :{N} {', '.join(tests[:5])}")
    if len(tests) > 5:
        print(f"  {D}                   + {len(tests) - 5} more{N}")

    print(f"  {W}{'─' * 60}{N}")

    log("ok", f"Analysis saved to: {analysis_file}")
    return analysis_file

def run_vapt_tests(analysis_file: str) -> str:
    """Run VAPT tests using analysis file"""

    if not os.path.isfile(analysis_file):
        log("err", f"Analysis file not found: {analysis_file}")
        return None

    log("info", f"Loading analysis: {analysis_file}")

    try:
        with open(analysis_file, 'r') as f:
            analysis = json.load(f)
    except Exception as e:
        log("err", f"Failed to load analysis: {e}")
        return None

    log("info", "Starting comprehensive VAPT testing...")

    engine = HARVAPTEngine(analysis)
    results = engine.run_comprehensive_scan()

    # Save results
    target_domain = analysis.get('config', {}).get('target_domain', 'unknown')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"har_vapt_{target_domain}_{timestamp}.json"

    try:
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        log("ok", f"Results saved to: {results_file}")

        # Display summary
        vuln_summary = results.get('vulnerability_summary', {})
        print(f"\n  {W}{'─' * 50}{N}")
        print(f"  {W}  VAPT RESULTS SUMMARY{N}")
        print(f"  {W}{'─' * 50}{N}")
        print(f"  {C}Total Vulnerabilities:{N} {vuln_summary.get('total_vulnerabilities', 0)}")
        print(f"  {R}Critical             :{N} {vuln_summary.get('critical', 0)}")
        print(f"  {Y}High                 :{N} {vuln_summary.get('high', 0)}")
        print(f"  {O}Medium               :{N} {vuln_summary.get('medium', 0)}")
        print(f"  {D}Low                  :{N} {vuln_summary.get('low', 0)}")

        if vuln_summary.get('critical', 0) > 0:
            print(f"\n  {R}🚨 CRITICAL VULNERABILITIES FOUND!{N}")
            print(f"  {R}   Immediate remediation required{N}")

        scan_info = results.get('scan_info', {})
        duration = scan_info.get('duration_seconds', 0)
        print(f"\n  {C}Scan Duration        :{N} {duration:.2f} seconds")
        print(f"  {C}Endpoints Tested     :{N} {scan_info.get('endpoints_tested', 0)}")
        print(f"  {W}{'─' * 50}{N}")

        return results_file

    except Exception as e:
        log("err", f"Failed to save results: {e}")
        return None

def full_workflow(har_file: str) -> str:
    """Complete HAR VAPT workflow: analyze + test"""

    log("info", "Starting complete HAR VAPT workflow...")

    # Step 1: Analyze HAR file
    print(f"\n{C}Step 1: HAR Analysis{N}")
    analysis_file = analyze_har_file(har_file)

    if not analysis_file:
        return None

    # Step 2: Run VAPT tests
    print(f"\n{C}Step 2: VAPT Testing{N}")
    results_file = run_vapt_tests(analysis_file)

    if results_file:
        print(f"\n{G}✅ Complete VAPT workflow finished successfully!{N}")
        print(f"  📁 Analysis: {analysis_file}")
        print(f"  📊 Results: {results_file}")

        # Optional: Generate HTML report
        try:
            import subprocess
            if os.path.exists("reporter.py"):
                print(f"\n{C}Generating HTML report...{N}")
                subprocess.run([sys.executable, "reporter.py", results_file], check=True)
                log("ok", "HTML report generated")
        except Exception:
            log("warn", "Could not generate HTML report (reporter.py not found or failed)")

    return results_file

def list_available_hars():
    """List available HAR files in current directory and Documents"""

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
                    har_files.append(os.path.join(search_dir, file))
        except:
            continue

    if har_files:
        print(f"\n  {W}Available HAR files:{N}")
        for i, har_file in enumerate(har_files[:10], 1):  # Show max 10
            print(f"  {C}{i:2d}.{N} {har_file}")
        if len(har_files) > 10:
            print(f"  {D}    ... and {len(har_files) - 10} more{N}")
    else:
        print(f"  {Y}No HAR files found in current directory or ~/Documents{N}")

def main():
    parser = argparse.ArgumentParser(
        description="HAR VAPT - Standalone HAR-based Vulnerability Assessment",
        epilog="Examples:\n"
               "  python3 har_vapt.py session.har                   # Complete workflow\n"
               "  python3 har_vapt.py --analyze session.har         # Analysis only\n"
               "  python3 har_vapt.py --test session_analysis.json  # Testing only\n"
               "  python3 har_vapt.py --list                        # List available HAR files",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("file", nargs="?", help="HAR file or analysis file")
    parser.add_argument("--analyze", "-a", help="Analyze HAR file only")
    parser.add_argument("--test", "-t", help="Run VAPT tests on analysis file")
    parser.add_argument("--list", "-l", action="store_true", help="List available HAR files")

    args = parser.parse_args()

    banner()

    if args.list:
        list_available_hars()
        return

    if args.analyze:
        analyze_har_file(args.analyze)
        return

    if args.test:
        run_vapt_tests(args.test)
        return

    if args.file:
        if args.file.endswith('.har'):
            full_workflow(args.file)
        elif args.file.endswith('.json'):
            run_vapt_tests(args.file)
        else:
            log("err", "File must be a .har or .json file")
            return
    else:
        # Interactive mode
        list_available_hars()
        print(f"\n{C}Interactive Mode{N}")

        while True:
            har_file = input(f"{C}Enter HAR file path (or 'quit'): {N}").strip()

            if har_file.lower() in ['quit', 'exit', 'q']:
                break

            if not har_file:
                continue

            if os.path.isfile(har_file) and har_file.endswith('.har'):
                full_workflow(har_file)
                break
            else:
                log("err", "Invalid HAR file. Please try again.")

if __name__ == "__main__":
    main()
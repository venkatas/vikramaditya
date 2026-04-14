#!/usr/bin/env python3
"""
VAPT Suite - Complete VAPT platform combining all tools
Provides unified interface for infrastructure and authenticated testing

Usage:
    python3 vapt_suite.py                    # Interactive menu
    python3 vapt_suite.py <target>           # Quick assessment
    python3 vapt_suite.py --help             # Show all options
"""

import argparse
import os
import sys
import subprocess
from datetime import datetime

# Colors
O = "\033[38;5;208m"   # Orange
W = "\033[1;37m"       # White bold
G = "\033[0;32m"       # Green
R = "\033[0;31m"       # Red
Y = "\033[1;33m"       # Yellow
C = "\033[0;36m"       # Cyan
B = "\033[0;34m"       # Blue
N = "\033[0m"          # Reset

def main_banner():
    print(f"""
{O}██╗   ██╗██╗██╗  ██╗██████╗  █████╗ ███╗   ███╗ █████╗ ██████╗ ██╗████████╗██╗   ██╗ █████╗{N}
{O}██║   ██║██║██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝██╔══██╗{N}
{W}██║   ██║██║█████╔╝ ██████╔╝███████║██╔████╔██║███████║██║  ██║██║   ██║    ╚████╔╝ ███████║{N}
{W}╚██╗ ██╔╝██║██╔═██╗ ██╔══██╗██╔══██║██║╚██╔╝██║██╔══██║██║  ██║██║   ██║     ╚██╔╝  ██╔══██║{N}
{G} ╚████╔╝ ██║██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║██████╔╝██║   ██║      ██║   ██║  ██║{N}
{G}  ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝{N}
{B}                    Complete VAPT Suite - All Tools in One Place{N}
{Y}           Infrastructure Testing • Authenticated Web Testing • HAR Analysis{N}
""")

def show_menu():
    """Display main menu"""
    print(f"\n{W}═══════════════════════════════════════════════════════════════════{N}")
    print(f"{W}                            VAPT SUITE MENU{N}")
    print(f"{W}═══════════════════════════════════════════════════════════════════{N}")

    print(f"\n{C}🏗️  INFRASTRUCTURE TESTING{N}")
    print(f"  {Y}1.{N} Single Target        - URL, domain, IP, or CIDR")
    print(f"  {Y}2.{N} Domain Recon         - Subdomain enum + port scan + vulns")
    print(f"  {Y}3.{N} Network Range        - CIDR range assessment")

    print(f"\n{C}🔐 AUTHENTICATED WEB TESTING{N}")
    print(f"  {Y}4.{N} HAR File Analysis    - Extract endpoints and session data")
    print(f"  {Y}5.{N} HAR-based VAPT       - Comprehensive authenticated testing")
    print(f"  {Y}6.{N} API VAPT             - Authenticated API vulnerability testing")

    print(f"\n{C}🎯 COMBINED ASSESSMENTS{N}")
    print(f"  {Y}7.{N} Complete VAPT        - Infrastructure + Web + HAR analysis")
    print(f"  {Y}8.{N} Multi-HAR Testing    - Process multiple HAR files")

    print(f"\n{C}📊 UTILITIES{N}")
    print(f"  {Y}9.{N} Generate Reports     - Create HTML/PDF reports from results")
    print(f"  {Y}10.{N} List HAR Files       - Show available HAR files")
    print(f"  {Y}11.{N} View Recent Results  - Display recent scan results")

    print(f"\n{C}❓ HELP & INFO{N}")
    print(f"  {Y}h.{N} Help & Examples      - Detailed usage examples")
    print(f"  {Y}q.{N} Quit")

    print(f"\n{W}═══════════════════════════════════════════════════════════════════{N}")

def run_tool(script_name: str, args: list, description: str = "") -> bool:
    """Run a VAPT tool with given arguments"""
    if description:
        print(f"\n{C}🚀 {description}{N}")
        print("─" * 60)

    if not os.path.exists(script_name):
        print(f"{R}❌ Error: {script_name} not found{N}")
        return False

    try:
        cmd = [sys.executable, script_name] + args
        print(f"{Y}Running: {' '.join(cmd)}{N}\n")
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except KeyboardInterrupt:
        print(f"\n{Y}⚠️  Interrupted by user{N}")
        return False
    except Exception as e:
        print(f"{R}❌ Error running {script_name}: {e}{N}")
        return False

def list_har_files():
    """List available HAR files"""
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
                    size = os.path.getsize(full_path)
                    har_files.append({
                        'path': full_path,
                        'name': file,
                        'size': size,
                        'dir': search_dir
                    })
        except:
            continue

    if har_files:
        print(f"\n{W}Available HAR Files:{N}")
        print(f"{'#':>3} {'Name':<30} {'Size':<10} {'Location'}")
        print("─" * 70)
        for i, har in enumerate(har_files, 1):
            size_str = f"{har['size']:,} bytes" if har['size'] < 1024*1024 else f"{har['size']/(1024*1024):.1f} MB"
            location = "Current" if har['dir'] == "." else os.path.basename(har['dir'])
            print(f"{i:>3} {har['name']:<30} {size_str:<10} {location}")
    else:
        print(f"\n{Y}No HAR files found in current directory, ~/Documents, or ~/Downloads{N}")

    return har_files

def list_recent_results():
    """List recent scan results"""
    result_files = []

    # Look for common result file patterns
    patterns = ['*vapt*.json', '*results*.json', '*scan*.json', '*findings*.json']

    try:
        import glob
        for pattern in patterns:
            result_files.extend(glob.glob(pattern))
    except:
        # Fallback to simple listing
        try:
            for file in os.listdir("."):
                if file.endswith('.json') and any(keyword in file.lower()
                    for keyword in ['vapt', 'results', 'scan', 'findings']):
                    result_files.append(file)
        except:
            pass

    if result_files:
        print(f"\n{W}Recent Result Files:{N}")
        result_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)

        for i, file in enumerate(result_files[:10], 1):
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(file))
                size = os.path.getsize(file)
                size_str = f"{size:,} bytes" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                print(f"  {i:>2}. {file:<40} {size_str:<12} {mtime.strftime('%Y-%m-%d %H:%M')}")
            except:
                print(f"  {i:>2}. {file}")
    else:
        print(f"\n{Y}No recent result files found{N}")

def show_help():
    """Show detailed help and examples"""
    print(f"\n{W}VAPT SUITE - HELP & EXAMPLES{N}")
    print("═" * 60)

    print(f"\n{C}🏗️  INFRASTRUCTURE TESTING EXAMPLES:{N}")
    print(f"  {Y}Domain Assessment:{N}")
    print(f"    python3 vapt_suite.py example.com")
    print(f"    python3 vikramaditya.py example.com")

    print(f"\n  {Y}Network Range:{N}")
    print(f"    python3 vapt_suite.py 192.168.1.0/24")
    print(f"    python3 vikramaditya.py 192.168.1.0/24")

    print(f"\n{C}🔐 AUTHENTICATED WEB TESTING:{N}")
    print(f"  {Y}HAR File Analysis:{N}")
    print(f"    python3 har_analyzer.py session.har")

    print(f"\n  {Y}HAR-based VAPT:{N}")
    print(f"    python3 har_vapt.py session.har")

    print(f"\n  {Y}API Testing:{N}")
    print(f"    python3 autopilot_api_hunt.py --base-url https://api.example.com")

    print(f"\n{C}🎯 COMBINED WORKFLOWS:{N}")
    print(f"  {Y}Complete Assessment:{N}")
    print(f"    python3 vapt_companion.py --full example.com")

    print(f"\n  {Y}Infrastructure + HAR:{N}")
    print(f"    python3 vikramaditya.py example.com")
    print(f"    python3 har_vapt.py admin_session.har")

    print(f"\n{C}📊 REPORTING:{N}")
    print(f"  {Y}Generate HTML Report:{N}")
    print(f"    python3 reporter.py results.json --client 'Client Name'")

    print(f"\n{C}💡 HAR FILE CAPTURE GUIDE:{N}")
    print(f"  1. Open browser and navigate to target application")
    print(f"  2. Open Developer Tools (F12) → Network tab")
    print(f"  3. Perform authenticated actions:")
    print(f"     • Login with valid credentials")
    print(f"     • Navigate through admin panels")
    print(f"     • Use file upload features")
    print(f"     • Access user management functions")
    print(f"  4. Right-click in Network tab → Save as HAR")
    print(f"  5. Run: python3 har_vapt.py captured_session.har")

def interactive_menu():
    """Run interactive menu"""
    while True:
        show_menu()
        choice = input(f"\n{C}Enter your choice: {N}").strip().lower()

        if choice == 'q' or choice == 'quit':
            print(f"\n{Y}Goodbye!{N}")
            break

        elif choice == 'h' or choice == 'help':
            show_help()
            input(f"\n{C}Press Enter to continue...{N}")

        elif choice == '1':
            target = input(f"{C}Enter target (URL, domain, IP, or CIDR): {N}").strip()
            if target:
                run_tool("vikramaditya.py", [target], "Single Target Assessment")

        elif choice == '2':
            domain = input(f"{C}Enter domain: {N}").strip()
            if domain:
                run_tool("vikramaditya.py", [domain], "Domain Reconnaissance")

        elif choice == '3':
            cidr = input(f"{C}Enter CIDR range (e.g., 192.168.1.0/24): {N}").strip()
            if cidr:
                run_tool("vikramaditya.py", [cidr], "Network Range Assessment")

        elif choice == '4':
            har_files = list_har_files()
            if har_files:
                try:
                    selection = int(input(f"\n{C}Select HAR file [1-{len(har_files)}]: {N}"))
                    if 1 <= selection <= len(har_files):
                        har_file = har_files[selection - 1]['path']
                        run_tool("har_analyzer.py", [har_file], "HAR File Analysis")
                except ValueError:
                    har_path = input(f"{C}Enter HAR file path: {N}").strip()
                    if os.path.isfile(har_path):
                        run_tool("har_analyzer.py", [har_path], "HAR File Analysis")

        elif choice == '5':
            har_files = list_har_files()
            if har_files:
                try:
                    selection = int(input(f"\n{C}Select HAR file [1-{len(har_files)}]: {N}"))
                    if 1 <= selection <= len(har_files):
                        har_file = har_files[selection - 1]['path']
                        run_tool("har_vapt.py", [har_file], "HAR-based VAPT Testing")
                except ValueError:
                    har_path = input(f"{C}Enter HAR file path: {N}").strip()
                    if os.path.isfile(har_path):
                        run_tool("har_vapt.py", [har_path], "HAR-based VAPT Testing")

        elif choice == '6':
            url = input(f"{C}Enter API base URL: {N}").strip()
            if url:
                creds = input(f"{C}Enter credentials (user:pass) [optional]: {N}").strip()
                args = ["--base-url", url]
                if creds:
                    args.extend(["--auth-creds", creds])
                run_tool("autopilot_api_hunt.py", args, "API VAPT Testing")

        elif choice == '7':
            domain = input(f"{C}Enter domain for complete assessment: {N}").strip()
            if domain:
                run_tool("vapt_companion.py", ["--full", domain], "Complete VAPT Assessment")

        elif choice == '8':
            print(f"\n{C}Processing all available HAR files...{N}")
            run_tool("demo_har_vapt.py", [], "Multi-HAR VAPT Testing")

        elif choice == '9':
            list_recent_results()
            result_file = input(f"\n{C}Enter result file name: {N}").strip()
            if result_file and os.path.isfile(result_file):
                client = input(f"{C}Enter client name [optional]: {N}").strip()
                args = [result_file]
                if client:
                    args.extend(["--client", client])
                run_tool("reporter.py", args, "Report Generation")

        elif choice == '10':
            list_har_files()
            input(f"\n{C}Press Enter to continue...{N}")

        elif choice == '11':
            list_recent_results()
            input(f"\n{C}Press Enter to continue...{N}")

        else:
            print(f"{R}Invalid choice. Please try again.{N}")

def main():
    parser = argparse.ArgumentParser(
        description="VAPT Suite - Complete vulnerability assessment platform",
        epilog="Run without arguments for interactive menu",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("target", nargs="?", help="Quick target assessment")
    parser.add_argument("--menu", "-m", action="store_true", help="Show interactive menu")

    args = parser.parse_args()

    main_banner()

    if args.target:
        # Quick assessment mode
        if args.target.endswith('.har'):
            run_tool("har_vapt.py", [args.target], f"HAR-based VAPT: {args.target}")
        else:
            run_tool("vikramaditya.py", [args.target], f"Infrastructure VAPT: {args.target}")
    else:
        # Interactive menu
        interactive_menu()

if __name__ == "__main__":
    main()
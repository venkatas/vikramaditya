#!/usr/bin/env python3
"""
ad_hunt.py — Active Directory / hybrid identity VAPT (v9.7.0)

Wraps NetExec (nxc), BloodHound CE / SharpHound, Impacket, and Certipy
into a single Vikramaditya-shaped engagement output. Hybrid (Entra ID +
on-prem AD) clients increasingly need this; our `whitebox/` covers cloud
only.

Output: findings/<domain>/ad/{nxc/, bloodhound/, impacket/, certipy/,
summary.json}

Usage:
    # Discovery against a DC IP
    python3 ad_hunt.py --dc 10.1.1.10 --domain corp.client.local \\
        --user audit_user --pass 'P@ss' --mode discover

    # Full BloodHound collection
    python3 ad_hunt.py --dc 10.1.1.10 --domain corp.client.local \\
        --user audit_user --pass 'P@ss' --mode bloodhound

    # ADCS enumeration (Certipy)
    python3 ad_hunt.py --dc 10.1.1.10 --domain corp.client.local \\
        --user audit_user --pass 'P@ss' --mode certipy

    # Kerberoast / ASREPRoast (Impacket)
    python3 ad_hunt.py --dc 10.1.1.10 --domain corp.client.local \\
        --user audit_user --pass 'P@ss' --mode kerberoast

Tool requirements:
    nxc       — pip install netexec
    bloodhound-python — pip install bloodhound  (Linux/macOS Python collector)
    Impacket  — pip install impacket  (GetUserSPNs.py, GetNPUsers.py, secretsdump.py)
    Certipy   — pip install certipy-ad
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list[str], log_path: Path, timeout: int = 300) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] $ {' '.join(cmd)}")
    try:
        with open(log_path, "w") as fh:
            fh.write(f"# {' '.join(cmd)}\n# {datetime.now().isoformat(timespec='seconds')}\n\n")
            fh.flush()
            proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, timeout=timeout)
        return proc.returncode
    except subprocess.TimeoutExpired:
        return 124
    except FileNotFoundError:
        return 127


def discover(args, out_dir: Path) -> None:
    """nxc smb / ldap discovery + null-session check + signing/SMBv1 posture."""
    if not _which("nxc"):
        print("[!] nxc (NetExec) not found — pip install netexec")
        return
    base = ["nxc", "smb", args.dc, "-d", args.domain, "-u", args.user, "-p", args.password]
    _run(base + ["--shares"], out_dir / "nxc" / "smb_shares.txt")
    _run(base + ["--users"], out_dir / "nxc" / "smb_users.txt")
    _run(base + ["--groups"], out_dir / "nxc" / "smb_groups.txt")
    _run(base + ["--pass-pol"], out_dir / "nxc" / "smb_passpol.txt")
    _run(["nxc", "ldap", args.dc, "-d", args.domain, "-u", args.user, "-p", args.password,
          "--asreproast", str(out_dir / "nxc" / "asrep.txt")],
         out_dir / "nxc" / "asreproast.log")
    _run(["nxc", "ldap", args.dc, "-d", args.domain, "-u", args.user, "-p", args.password,
          "--kerberoasting", str(out_dir / "nxc" / "kerberoast.txt")],
         out_dir / "nxc" / "kerberoast.log")


def bloodhound_collect(args, out_dir: Path) -> None:
    """bloodhound-python collector (Linux/macOS Python implementation of SharpHound)."""
    if not _which("bloodhound-python"):
        print("[!] bloodhound-python not found — pip install bloodhound")
        return
    bh_dir = out_dir / "bloodhound"
    bh_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["bloodhound-python", "-d", args.domain, "-u", args.user, "-p", args.password,
           "-ns", args.dc, "-c", "All", "--zip", "-op", str(bh_dir / "bh")]
    _run(cmd, bh_dir / "collect.log", timeout=600)
    print(f"[+] BloodHound zip → {bh_dir}/bh_<timestamp>.zip")
    print(f"    Import: in BloodHound CE UI → Upload → select the .zip")


def certipy_audit(args, out_dir: Path) -> None:
    """Certipy ADCS enumeration (ESC1-ESC15)."""
    if not _which("certipy"):
        print("[!] certipy not found — pip install certipy-ad")
        return
    cert_dir = out_dir / "certipy"
    cert_dir.mkdir(parents=True, exist_ok=True)
    _run(["certipy", "find", "-u", f"{args.user}@{args.domain}", "-p", args.password,
          "-dc-ip", args.dc, "-stdout", "-vulnerable",
          "-output", str(cert_dir / "certipy_find")],
         cert_dir / "find.log", timeout=600)


def kerberoast(args, out_dir: Path) -> None:
    """Impacket GetUserSPNs / GetNPUsers — Kerberoast + ASREPRoast."""
    imp_dir = out_dir / "impacket"
    imp_dir.mkdir(parents=True, exist_ok=True)
    if _which("GetUserSPNs.py"):
        _run(["GetUserSPNs.py", "-request", "-dc-ip", args.dc,
              f"{args.domain}/{args.user}:{args.password}",
              "-outputfile", str(imp_dir / "kerberoast_hashes.txt")],
             imp_dir / "kerberoast.log")
    if _which("GetNPUsers.py"):
        users_file = out_dir / "nxc" / "smb_users.txt"
        if users_file.exists():
            _run(["GetNPUsers.py", "-dc-ip", args.dc, "-no-pass",
                  "-usersfile", str(users_file),
                  f"{args.domain}/"],
                 imp_dir / "asreproast.log")
    if _which("secretsdump.py"):
        # Only run if the operator passed --domain-admin explicitly
        if args.domain_admin:
            _run(["secretsdump.py",
                  f"{args.domain}/{args.user}:{args.password}@{args.dc}"],
                 imp_dir / "secretsdump.log", timeout=900)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ad_hunt",
                                 description="Vikramaditya AD / hybrid identity VAPT")
    ap.add_argument("--dc", required=True, help="Domain Controller IP")
    ap.add_argument("--domain", required=True, help="AD domain (e.g. corp.client.local)")
    ap.add_argument("--user", required=True, help="Authenticated audit user")
    ap.add_argument("--pass", dest="password", required=True, help="User password")
    ap.add_argument("--mode", default="discover",
                    choices=["discover", "bloodhound", "certipy", "kerberoast", "all"],
                    help="Phase to run (default discover)")
    ap.add_argument("--domain-admin", action="store_true",
                    help="Operator confirms credentials are domain-admin → enable secretsdump")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    out_dir = Path(args.output_dir) if args.output_dir else (
        REPO / "findings" / args.domain.replace("/", "_") / "ad"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] AD VAPT — domain={args.domain} dc={args.dc} mode={args.mode}")
    print(f"[*] Output: {out_dir}")

    if args.mode in ("discover", "all"):
        discover(args, out_dir)
    if args.mode in ("bloodhound", "all"):
        bloodhound_collect(args, out_dir)
    if args.mode in ("certipy", "all"):
        certipy_audit(args, out_dir)
    if args.mode in ("kerberoast", "all"):
        kerberoast(args, out_dir)

    summary = {
        "tool": "vikramaditya.ad_hunt",
        "version": "9.7.0",
        "domain": args.domain,
        "dc": args.dc,
        "user": args.user,
        "mode": args.mode,
        "ran_at": datetime.now().isoformat(timespec="seconds"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[+] summary → {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

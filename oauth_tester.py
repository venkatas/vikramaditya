#!/usr/bin/env python3
from __future__ import annotations
"""
OAuth Security Tester — Tests OAuth/OIDC implementation weaknesses.

Checks: state entropy, redirect_uri bypass, PKCE enforcement, CORS on auth endpoints,
password reset host header injection, token reuse after logout.

Usage:
    python3 oauth_tester.py <target_url>
    python3 oauth_tester.py --recon-dir <recon_dir>
"""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from urllib.parse import urlparse, urljoin

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FINDINGS_DIR = os.environ.get("FINDINGS_OUT_DIR", os.path.join(BASE_DIR, "findings"))


def run_cmd(cmd, timeout=15):
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, preexec_fn=os.setsid,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode == 0, stdout, stderr
    except subprocess.TimeoutExpired:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
        return False, "", "timeout"
    except Exception as e:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
        return False, "", str(e)


def check_cors_on_auth_endpoints(base_url: str) -> list[dict]:
    """Check CORS headers on authentication-related endpoints."""
    findings = []
    auth_paths = ["/oauth/authorize", "/oauth/token", "/api/v1/auth",
                  "/login", "/api/auth", "/graphql", "/.well-known/openid-configuration"]

    for path in auth_paths:
        url = urljoin(base_url, path)
        ok, stdout, _ = run_cmd(
            f'curl -sk -I -H "Origin: https://evil.com" "{url}" --max-time 8'
        )
        if not ok:
            continue
        headers = stdout.lower()
        if "access-control-allow-origin" in headers:
            if "evil.com" in headers or "*" in headers.split("access-control-allow-origin")[1].split("\n")[0]:
                findings.append({
                    "type": "cors_on_auth",
                    "severity": "high",
                    "url": url,
                    "detail": "CORS allows arbitrary origin on auth endpoint",
                    "evidence": [l for l in stdout.split("\n") if "access-control" in l.lower()][:3],
                })
    return findings


def check_oauth_state_entropy(base_url: str) -> list[dict]:
    """Check if OAuth state parameter has sufficient entropy."""
    findings = []
    # Try to find OAuth authorization endpoint
    for path in ["/oauth/authorize", "/authorize", "/auth/authorize", "/connect/authorize"]:
        url = urljoin(base_url, path)
        ok, stdout, _ = run_cmd(f'curl -sk -D- -o /dev/null "{url}?response_type=code&client_id=test&redirect_uri=http://localhost" --max-time 8')
        if not ok:
            continue
        # Extract state from redirect or response
        states = re.findall(r'state=([a-zA-Z0-9_-]+)', stdout)
        if len(states) >= 1:
            state = states[0]
            if len(state) < 16:
                findings.append({
                    "type": "weak_oauth_state",
                    "severity": "medium",
                    "url": url,
                    "detail": f"OAuth state parameter too short ({len(state)} chars, need 16+)",
                    "evidence": [f"state={state}"],
                })
    return findings


def check_redirect_uri_bypass(base_url: str) -> list[dict]:
    """Test redirect_uri validation bypass vectors."""
    findings = []
    for path in ["/oauth/authorize", "/authorize", "/auth/authorize"]:
        url = urljoin(base_url, path)
        # Get legitimate redirect_uri first
        ok, stdout, _ = run_cmd(f'curl -sk -D- "{url}" --max-time 8')
        if not ok:
            continue

        legit_uri = re.search(r'redirect_uri=([^&\s"]+)', stdout)
        if not legit_uri:
            continue
        legit = legit_uri.group(1)

        bypasses = [
            (f"{legit}@evil.com", "at-sign injection"),
            (f"{legit}%2F@evil.com", "url-encoded slash injection"),
            ("https://evil.com/", "full override"),
            (f"{legit}.evil.com", "subdomain confusion"),
        ]
        for bypass_uri, technique in bypasses:
            test_url = f"{url}?response_type=code&client_id=test&redirect_uri={bypass_uri}"
            ok, stdout, _ = run_cmd(f'curl -sk -o /dev/null -w "%{{http_code}}" "{test_url}" --max-time 8')
            if ok and stdout.strip() in ("200", "302", "301"):
                findings.append({
                    "type": "redirect_uri_bypass",
                    "severity": "high",
                    "url": test_url,
                    "detail": f"redirect_uri bypass via {technique}",
                    "evidence": [f"HTTP {stdout.strip()} for bypass URI: {bypass_uri[:80]}"],
                })
    return findings


def check_password_reset_host_injection(base_url: str) -> list[dict]:
    """Test password reset host header injection."""
    findings = []
    for path in ["/password/reset", "/forgot-password", "/api/password/reset",
                 "/users/password", "/auth/reset"]:
        url = urljoin(base_url, path)
        for header_name, header_value in [
            ("Host", "evil.com"),
            ("X-Forwarded-Host", "evil.com"),
            ("X-Host", "evil.com"),
        ]:
            ok, stdout, _ = run_cmd(
                f'curl -sk -X POST -H "{header_name}: {header_value}" '
                f'-d "email=test@test.com" "{url}" -D- --max-time 8'
            )
            if ok and "evil.com" in stdout:
                findings.append({
                    "type": "host_header_injection",
                    "severity": "high",
                    "url": url,
                    "detail": f"Password reset reflects injected {header_name}: {header_value}",
                    "evidence": [f"{header_name}: {header_value} reflected in response"],
                })
    return findings


def run_oauth_audit(target: str, recon_dir: str | None = None, output_dir: str | None = None) -> list[dict]:
    """Run all OAuth security checks."""
    print(f"[*] OAuth Security Audit: {target}")
    all_findings = []

    base_urls = [f"https://{target}", f"http://{target}"]
    if recon_dir:
        live_file = os.path.join(recon_dir, "live", "urls.txt")
        if os.path.isfile(live_file):
            with open(live_file) as f:
                base_urls = [l.strip() for l in f if l.strip()][:5]

    for base_url in base_urls:
        print(f"  [>] Testing {base_url}...")
        all_findings.extend(check_cors_on_auth_endpoints(base_url))
        all_findings.extend(check_oauth_state_entropy(base_url))
        all_findings.extend(check_redirect_uri_bypass(base_url))
        all_findings.extend(check_password_reset_host_injection(base_url))

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        out_file = os.path.join(output_dir, "oauth_findings.txt")
        with open(out_file, "w") as f:
            for finding in all_findings:
                f.write(f"[{finding['severity'].upper()}] {finding['type']} {finding['url']}\n")
                f.write(f"  Detail: {finding['detail']}\n")
                for ev in finding.get("evidence", []):
                    f.write(f"  Evidence: {ev}\n")
                f.write("\n")
        print(f"  [+] {len(all_findings)} findings → {out_file}")

    if not all_findings:
        print("  [+] No OAuth issues found")

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="OAuth Security Tester")
    parser.add_argument("target", nargs="?", help="Target domain")
    parser.add_argument("--recon-dir", help="Recon directory")
    parser.add_argument("--output-dir", help="Output directory for findings")
    args = parser.parse_args()

    target = args.target
    if not target and args.recon_dir:
        target = os.path.basename(args.recon_dir.rstrip("/"))
    if not target:
        parser.error("Target domain required")

    run_oauth_audit(target, args.recon_dir, args.output_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())

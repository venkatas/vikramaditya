#!/usr/bin/env python3
from __future__ import annotations
"""
Authenticated API Tester — Broken Access Control Detection.

Tests every API endpoint with valid/no/expired/tampered tokens
to find endpoints accessible without proper authentication.

Usage:
    python3 auth_api_tester.py --base-url https://api.example.com --auth-token TOKEN --endpoints endpoints.json
    python3 auth_api_tester.py --base-url URL --auth-creds user:pass --login-url sign-in/
"""

import argparse
import json
import os
import sys

from auth_utils import RateLimiter, JWTHelper, AuthSession, FindingSaver


def load_endpoints(filepath: str) -> list[dict]:
    """Load endpoints from JSON file or plain text (one path per line)."""
    with open(filepath) as f:
        content = f.read().strip()
    if content.startswith("["):
        return json.loads(content)
    return [{"path": line.strip(), "method": "POST", "body": {}}
            for line in content.split("\n") if line.strip() and not line.startswith("#")]


def test_endpoint(session: AuthSession, endpoint: dict, valid_token: str) -> dict:
    """Test a single endpoint with multiple auth states."""
    path = endpoint.get("path", "")
    method = endpoint.get("method", "POST").upper()
    body = endpoint.get("body", {})

    result = {"path": path, "method": method, "tests": {}, "findings": []}

    # 1. Valid token (baseline)
    resp = session.request(method, path, token=valid_token, json_body=body)
    result["tests"]["valid"] = resp["status"]
    baseline = resp["status"]

    # 2. No token
    resp = session.request(method, path, token="", json_body=body)
    result["tests"]["no_auth"] = resp["status"]
    if resp["status"] in (200, 201, 204) and baseline in (200, 201, 204):
        result["findings"].append({
            "type": "broken_authentication",
            "severity": "critical",
            "detail": f"Endpoint accessible without auth token ({method} {path})",
            "url": resp["url"],
            "evidence": f"No-auth: HTTP {resp['status']}, Valid-auth: HTTP {baseline}",
        })

    # 3. Expired token
    expired = JWTHelper.expire_token(valid_token)
    resp = session.request(method, path, token=expired, json_body=body)
    result["tests"]["expired"] = resp["status"]
    if resp["status"] in (200, 201, 204):
        result["findings"].append({
            "type": "no_expiry_validation",
            "severity": "high",
            "detail": f"Expired JWT accepted ({method} {path})",
            "url": resp["url"],
            "evidence": f"Expired token: HTTP {resp['status']}",
        })

    # 4. Tampered signature
    tampered = JWTHelper.tamper_signature(valid_token)
    resp = session.request(method, path, token=tampered, json_body=body)
    result["tests"]["tampered"] = resp["status"]
    if resp["status"] in (200, 201, 204):
        result["findings"].append({
            "type": "no_signature_validation",
            "severity": "high",
            "detail": f"Tampered JWT signature accepted ({method} {path})",
            "url": resp["url"],
            "evidence": f"Tampered token: HTTP {resp['status']}",
        })

    # 5. alg=none
    alg_none = JWTHelper.set_alg_none(valid_token)
    resp = session.request(method, path, token=alg_none, json_body=body)
    result["tests"]["alg_none"] = resp["status"]
    if resp["status"] in (200, 201, 204):
        result["findings"].append({
            "type": "jwt_alg_none_bypass",
            "severity": "critical",
            "detail": f"JWT alg=none accepted ({method} {path})",
            "url": resp["url"],
            "evidence": f"alg=none token: HTTP {resp['status']}",
        })

    # 6. 500 errors = poor error handling
    for test_name, status in result["tests"].items():
        if status == 500:
            result["findings"].append({
                "type": "server_error_on_auth",
                "severity": "medium",
                "detail": f"Server 500 on {test_name} auth test ({method} {path})",
                "url": f"{session.base_url}/{path}",
                "evidence": f"{test_name}: HTTP 500",
            })
            break

    return result


def run_auth_api_test(base_url: str, auth_token: str = None,
                       endpoints_file: str = None, auth_creds: str = None,
                       login_url: str = "sign-in/", output_dir: str = None,
                       rate_limit: float = 10.0) -> list[dict]:
    """Run authenticated API testing on all endpoints."""
    print(f"[*] Authenticated API Tester: {base_url}")

    limiter = RateLimiter(rate_limit)
    session = AuthSession(base_url, limiter)

    # Get token
    token = auth_token
    if not token and auth_creds:
        parts = auth_creds.split(":", 1)
        if len(parts) == 2:
            print(f"  [>] Auto-login as {parts[0]}...")
            token = session.auto_login(login_url, parts[0], parts[1])
            if token:
                print(f"  [+] Login successful, token: {token[:20]}...")
            else:
                print(f"  [-] Login failed")
                return []
    if not token:
        print("  [-] No auth token available")
        return []

    session.set_token(token)
    payload = JWTHelper.decode_payload(token)
    print(f"  [*] JWT payload: {json.dumps(payload, indent=2)[:200]}")

    # Load endpoints
    if endpoints_file and os.path.isfile(endpoints_file):
        endpoints = load_endpoints(endpoints_file)
    else:
        print("  [!] No endpoints file — using default LMS endpoints")
        endpoints = [{"path": p, "method": "POST", "body": {}} for p in [
            "learner-list/", "instructor-list/", "course-list/", "list-package/",
            "app-setting/", "list-smtp/", "logs-list/", "otp-list/",
            "users-report/", "list-notification/", "ads-list/", "news-list/",
            "list-videos/", "list-live-tests/", "list-discussion/",
        ]]

    print(f"  [*] Testing {len(endpoints)} endpoints...")

    saver = None
    if output_dir:
        saver = FindingSaver(output_dir, "auth_bypass")

    all_findings = []
    for i, ep in enumerate(endpoints):
        result = test_endpoint(session, ep, token)
        status_str = " | ".join(f"{k}={v}" for k, v in result["tests"].items())
        marker = "[VULN]" if result["findings"] else "[OK]"
        print(f"  {marker} {ep.get('method', 'POST')} {ep['path']} → {status_str}")

        for finding in result["findings"]:
            all_findings.append(finding)
            if saver:
                saver.save(finding)
                saver.save_txt(finding)

    if saver:
        saver.save_summary()

    print(f"\n  [+] Done: {len(all_findings)} findings across {len(endpoints)} endpoints")
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Vikramaditya Authenticated API Tester")
    parser.add_argument("--base-url", required=True, help="API base URL")
    parser.add_argument("--auth-token", help="JWT Bearer token")
    parser.add_argument("--auth-creds", help="user:pass for auto-login")
    parser.add_argument("--login-url", default="sign-in/", help="Login endpoint path")
    parser.add_argument("--endpoints", help="Endpoints JSON file")
    parser.add_argument("--output", help="Output directory for findings")
    parser.add_argument("--rate-limit", type=float, default=10.0, help="Max requests/sec")
    args = parser.parse_args()

    run_auth_api_test(
        base_url=args.base_url,
        auth_token=args.auth_token,
        endpoints_file=args.endpoints,
        auth_creds=args.auth_creds,
        login_url=args.login_url,
        output_dir=args.output,
        rate_limit=args.rate_limit,
    )


if __name__ == "__main__":
    main()

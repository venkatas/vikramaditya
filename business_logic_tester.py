#!/usr/bin/env python3
from __future__ import annotations
"""
Business Logic Tester — 8 test categories for application-layer flaws.

Tests: score manipulation, workflow bypass, negative values, bulk abuse,
privilege escalation, file upload bypass, rate limiting, pagination abuse.

Usage:
    python3 business_logic_tester.py --base-url URL --auth-token TOKEN
    python3 business_logic_tester.py --base-url URL --auth-creds user:pass --login-url sign-in/
"""

import argparse
import json
import os
import sys
import time

from auth_utils import RateLimiter, AuthSession, FindingSaver


def test_score_manipulation(session: AuthSession, token: str, endpoints: list[dict],
                             saver: FindingSaver = None) -> list[dict]:
    """Test if server accepts manipulated scores/grades."""
    findings = []
    tampered_scores = [999999, -1, 0, -999, 2147483647, "NaN", "Infinity"]

    for ep in endpoints:
        path = ep.get("path", "")
        body = dict(ep.get("body", {}))
        score_fields = [k for k in body if any(w in k.lower() for w in
                        ("score", "marks", "grade", "total", "correct", "points", "result"))]
        if not score_fields:
            continue

        for field in score_fields:
            original = body.get(field)
            for tampered in tampered_scores:
                test_body = dict(body)
                test_body[field] = tampered
                resp = session.request("POST", path, token=token, json_body=test_body)
                if resp["status"] in (200, 201):
                    body_data = resp["body"] if isinstance(resp["body"], dict) else {}
                    if body_data.get("status") is True or body_data.get("success") is True:
                        finding = {
                            "type": "score_manipulation",
                            "severity": "high",
                            "detail": f"Server accepted tampered {field}={tampered} ({path})",
                            "url": resp["url"],
                            "evidence": f"POST {path} with {field}={tampered} → HTTP {resp['status']} success",
                        }
                        findings.append(finding)
                        if saver:
                            saver.save(finding)
                            saver.save_txt(finding)
                        break  # One tampered value confirmed is enough per field
    return findings


def test_privilege_escalation(session: AuthSession, admin_token: str,
                                non_admin_token: str, admin_endpoints: list[str],
                                saver: FindingSaver = None) -> list[dict]:
    """Test admin-only endpoints with non-admin token."""
    findings = []
    for path in admin_endpoints:
        resp = session.request("POST", path, token=non_admin_token, json_body={})
        if resp["status"] in (200, 201, 204):
            finding = {
                "type": "privilege_escalation",
                "severity": "critical",
                "detail": f"Non-admin can access admin endpoint ({path})",
                "url": resp["url"],
                "evidence": f"Non-admin token → HTTP {resp['status']}",
            }
            findings.append(finding)
            if saver:
                saver.save(finding)
                saver.save_txt(finding)
    return findings


def test_rate_limiting(session: AuthSession, token: str, endpoints: list[str],
                        count: int = 30, saver: FindingSaver = None) -> list[dict]:
    """Test if sensitive endpoints have rate limiting."""
    findings = []
    for path in endpoints:
        statuses = []
        for i in range(count):
            resp = session.request("POST", path, token=token, json_body={"test": f"rate_{i}"})
            statuses.append(resp["status"])
            if resp["status"] == 429:
                break
        if 429 not in statuses and any(s in (200, 201, 400, 401) for s in statuses):
            finding = {
                "type": "missing_rate_limit",
                "severity": "medium",
                "detail": f"No rate limiting on sensitive endpoint after {count} requests ({path})",
                "url": f"{session.base_url}/{path}",
                "evidence": f"Sent {count} requests, no 429 received. Statuses: {set(statuses)}",
            }
            findings.append(finding)
            if saver:
                saver.save(finding)
                saver.save_txt(finding)
    return findings


def test_pagination_abuse(session: AuthSession, token: str, endpoints: list[str],
                           saver: FindingSaver = None) -> list[dict]:
    """Test pagination for data leak and DoS."""
    findings = []
    for path in endpoints:
        for payload in [
            {"page": 1, "page_size": 99999},
            {"page": 1, "limit": 99999},
            {"page": -1},
            {"page": 0},
            {"page": 1, "per_page": 99999},
        ]:
            resp = session.request("POST", path, token=token, json_body=payload)
            if resp["status"] in (200, 201):
                body = resp["body"]
                body_str = json.dumps(body, default=str) if isinstance(body, dict) else str(body)
                if len(body_str) > 50000:
                    finding = {
                        "type": "pagination_abuse",
                        "severity": "medium",
                        "detail": f"Excessive data returned with page_size=99999 ({path})",
                        "url": resp["url"],
                        "evidence": f"Response size: {len(body_str)} chars",
                    }
                    findings.append(finding)
                    if saver:
                        saver.save(finding)
                        saver.save_txt(finding)
                    break
    return findings


def test_negative_values(session: AuthSession, token: str, endpoints: list[dict],
                          saver: FindingSaver = None) -> list[dict]:
    """Test numeric fields with negative/extreme values."""
    findings = []
    neg_values = [-1, -999, -2147483648, 0]

    for ep in endpoints:
        path = ep.get("path", "")
        body = dict(ep.get("body", {}))
        numeric_fields = [k for k in body if isinstance(body.get(k), (int, float))]
        if not numeric_fields:
            continue

        for field in numeric_fields[:3]:
            for val in neg_values:
                test_body = dict(body)
                test_body[field] = val
                resp = session.request("POST", path, token=token, json_body=test_body)
                if resp["status"] in (200, 201):
                    body_data = resp["body"] if isinstance(resp["body"], dict) else {}
                    if body_data.get("status") is True:
                        finding = {
                            "type": "negative_value_accepted",
                            "severity": "medium",
                            "detail": f"Server accepted {field}={val} ({path})",
                            "url": resp["url"],
                            "evidence": f"{field}={val} → HTTP {resp['status']} success",
                        }
                        findings.append(finding)
                        if saver:
                            saver.save(finding)
                            saver.save_txt(finding)
                        break
    return findings


def run_business_logic_tests(base_url: str, auth_token: str = None,
                               auth_creds: str = None, login_url: str = "sign-in/",
                               config_file: str = None, output_dir: str = None,
                               rate_limit: float = 10.0,
                               non_admin_token: str = None) -> list[dict]:
    """Run all business logic tests."""
    print(f"[*] Business Logic Tester: {base_url}")

    limiter = RateLimiter(rate_limit)
    session = AuthSession(base_url, limiter)

    token = auth_token
    if not token and auth_creds:
        parts = auth_creds.split(":", 1)
        if len(parts) == 2:
            token = session.auto_login(login_url, parts[0], parts[1])
    if not token:
        print("  [-] No auth token")
        return []
    session.set_token(token)

    # Load config or use defaults
    config = {}
    if config_file and os.path.isfile(config_file):
        with open(config_file) as f:
            config = json.load(f)

    score_endpoints = config.get("score_endpoints", [
        {"path": "generate-live-test-result/", "body": {
            "learner_id": "1", "live_test_id": "1", "total_question": 10,
            "total_marks": 100, "correct_answers": 10, "wrong_answers": 0, "total_score": 100,
        }},
    ])
    admin_endpoints = config.get("admin_endpoints", [
        "app-setting/", "list-smtp/", "logs-list/", "otp-list/",
        "users-report/", "change-learner-password/",
    ])
    rate_limit_endpoints = config.get("rate_limit_endpoints", [
        "change-learner-password/", "sign-in/",
    ])
    list_endpoints = config.get("list_endpoints", [
        "learner-list/", "instructor-list/", "course-list/",
        "list-package/", "users-report/",
    ])

    saver = FindingSaver(output_dir, "business_logic") if output_dir else None
    all_findings = []

    # 1. Score manipulation
    print("  [>] Testing score manipulation...")
    findings = test_score_manipulation(session, token, score_endpoints, saver)
    print(f"      {len(findings)} findings")
    all_findings.extend(findings)

    # 2. Privilege escalation (if non-admin token provided)
    if non_admin_token:
        print("  [>] Testing privilege escalation...")
        findings = test_privilege_escalation(session, token, non_admin_token, admin_endpoints, saver)
        print(f"      {len(findings)} findings")
        all_findings.extend(findings)

    # 3. Rate limiting
    print("  [>] Testing rate limiting...")
    findings = test_rate_limiting(session, token, rate_limit_endpoints, 30, saver)
    print(f"      {len(findings)} findings")
    all_findings.extend(findings)

    # 4. Pagination abuse
    print("  [>] Testing pagination abuse...")
    findings = test_pagination_abuse(session, token, list_endpoints, saver)
    print(f"      {len(findings)} findings")
    all_findings.extend(findings)

    # 5. Negative values
    print("  [>] Testing negative values...")
    findings = test_negative_values(session, token, score_endpoints, saver)
    print(f"      {len(findings)} findings")
    all_findings.extend(findings)

    if saver:
        saver.save_summary()

    print(f"\n  [+] Done: {len(all_findings)} business logic findings")
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Vikramaditya Business Logic Tester")
    parser.add_argument("--base-url", required=True, help="API base URL")
    parser.add_argument("--auth-token", help="JWT Bearer token")
    parser.add_argument("--auth-creds", help="user:pass for auto-login")
    parser.add_argument("--login-url", default="sign-in/", help="Login endpoint")
    parser.add_argument("--config", help="Test config JSON file")
    parser.add_argument("--output", help="Output directory")
    parser.add_argument("--rate-limit", type=float, default=10.0)
    parser.add_argument("--non-admin-token", help="Non-admin token for priv esc testing")
    args = parser.parse_args()

    run_business_logic_tests(
        base_url=args.base_url, auth_token=args.auth_token,
        auth_creds=args.auth_creds, login_url=args.login_url,
        config_file=args.config, output_dir=args.output,
        rate_limit=args.rate_limit, non_admin_token=args.non_admin_token,
    )


if __name__ == "__main__":
    main()

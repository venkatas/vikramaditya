#!/usr/bin/env python3
from __future__ import annotations
"""
Generic REST API IDOR Scanner — two-token cross-user access testing.

Tests if User B can access User A's resources by swapping IDs.
Supports sequential numeric IDs, Base64-encoded IDs, and UUID IDs.

Usage:
    python3 api_idor_scanner.py --base-url URL --token-a TOKEN1 --token-b TOKEN2 --endpoints endpoints.json
"""

import argparse
import base64
import json
import os
import re
import sys

from auth_utils import RateLimiter, AuthSession, FindingSaver

VOLATILE_FIELDS = {"created_at", "updated_at", "timestamp", "ts", "nonce",
                   "token", "csrf", "session_id", "request_id", "modified_at"}
PII_FIELDS = {"email", "phone", "name", "first_name", "last_name", "address",
              "dob", "date_of_birth", "ssn", "password", "contact_no", "mobile"}


def normalize_response(body: dict) -> dict:
    """Strip volatile fields for comparison."""
    if not isinstance(body, dict):
        return body
    return {k: normalize_response(v) if isinstance(v, dict) else v
            for k, v in body.items() if k.lower() not in VOLATILE_FIELDS}


def jaccard_keys(a: dict, b: dict) -> float:
    """Jaccard similarity on dict keys."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return 0.0
    ka, kb = set(a.keys()), set(b.keys())
    if not ka and not kb:
        return 1.0
    intersection = ka & kb
    union = ka | kb
    return len(intersection) / len(union) if union else 0.0


# v9.18.3 — Identity-bearing fields the IDOR verdict logic compares
# across the two tokens' responses. When *the same* identity value
# appears in both responses, token B is genuinely seeing token A's
# specific resource (real IDOR). When the keys match but the identity
# values differ, both users are reading their own private copy of a
# shared endpoint shape (e.g. ``GET /auth/me``) and that is benign.
ID_FIELDS = (
    "id", "uuid", "pk", "_id", "user_id", "userId", "owner_id", "ownerId",
    "email", "username", "name", "slug", "tenant_id", "tenantId",
    "company_id", "companyId", "project_id", "projectId",
)


def _flat_id_values(body: dict, depth: int = 0) -> dict:
    """Walk a JSON body and collect every value attached to an ID-like
    key. Used to decide whether two responses describe *the same*
    underlying resource (real IDOR) or merely the *same shape* of a
    per-user resource (benign).
    """
    out: dict = {}
    if depth > 4 or not isinstance(body, dict):
        return out
    for k, v in body.items():
        kl = k.lower()
        if any(idf == kl for idf in ID_FIELDS):
            if isinstance(v, (str, int, float)) and v not in ("", None):
                out[kl] = v
        if isinstance(v, dict):
            for sub_k, sub_v in _flat_id_values(v, depth + 1).items():
                out.setdefault(sub_k, sub_v)
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            # Common case: {"data": [{...}, {...}]}.  Pull the first row's
            # identifiers so two identical lists collapse to a hit.
            for sub_k, sub_v in _flat_id_values(v[0], depth + 1).items():
                out.setdefault(sub_k, sub_v)
    return out


def shared_resource_signal(body_a, body_b) -> tuple[bool, str]:
    """
    Returns ``(same_resource, reason)``.

    ``same_resource`` is True when token B's response describes *the
    same* resource as token A's — i.e. token B got token A's data.

    Detection ladder (cheapest first):
      1. Both bodies are byte-equal after normalisation.
      2. They share at least one non-empty ID-bearing field whose value
         is identical across A and B.
      3. Otherwise: shape may match but contents differ → benign.
    """
    if not isinstance(body_a, dict) or not isinstance(body_b, dict):
        return (False, "non-dict body")
    if body_a == body_b:
        return (True, "identical normalised body")
    ids_a = _flat_id_values(body_a)
    ids_b = _flat_id_values(body_b)
    overlap: list[str] = []
    for k, va in ids_a.items():
        vb = ids_b.get(k)
        if vb is not None and va == vb:
            overlap.append(k)
    if overlap:
        return (True, f"shared id field(s): {','.join(sorted(overlap)[:4])}")
    return (False, "same shape, different values per token (benign)")


def has_pii(body: dict) -> bool:
    """Check if response contains PII-like fields."""
    if not isinstance(body, dict):
        return False
    keys = {k.lower() for k in body.keys()}
    if isinstance(body.get("data"), dict):
        keys |= {k.lower() for k in body["data"].keys()}
    return bool(keys & PII_FIELDS)


def is_base64_numeric(value: str) -> bool:
    """Check if value is Base64-encoded numeric ID."""
    if not re.match(r'^[A-Za-z0-9+/]+=*$', str(value)):
        return False
    try:
        decoded = base64.b64decode(str(value)).decode()
        return decoded.isdigit()
    except Exception:
        return False


def mutate_id(id_value: str) -> list[str]:
    """Generate ID mutations for IDOR testing."""
    mutations = []
    # Check if Base64-encoded numeric
    if is_base64_numeric(str(id_value)):
        try:
            num = int(base64.b64decode(str(id_value)).decode())
            for offset in [1, -1, 2, -2, 10]:
                mutations.append(base64.b64encode(str(num + offset).encode()).decode().rstrip("="))
            mutations.append(base64.b64encode(b"0").decode().rstrip("="))
        except Exception:
            pass
    # Try as plain numeric
    try:
        num = int(id_value)
        for offset in [1, -1, 2, -2, 10, 100]:
            mutations.append(str(num + offset))
        mutations.append("0")
        mutations.append("-1")
    except ValueError:
        pass
    return mutations


def test_idor(session: AuthSession, endpoint: dict, token_a: str, token_b: str,
              saver: FindingSaver = None) -> list[dict]:
    """Test a single endpoint for IDOR."""
    path = endpoint.get("path", "")
    method = endpoint.get("method", "POST")
    body = endpoint.get("body", {})
    id_field = endpoint.get("id_field")
    findings = []

    # Phase 1: Get baseline with token_a
    resp_a = session.request(method, path, token=token_a, json_body=body)
    if resp_a["status"] not in (200, 201):
        return findings

    # Phase 2: Same request with token_b (cross-user access)
    resp_b = session.request(method, path, token=token_b, json_body=body)
    if resp_b["status"] in (200, 201):
        norm_a = normalize_response(resp_a["body"]) if isinstance(resp_a["body"], dict) else {}
        norm_b = normalize_response(resp_b["body"]) if isinstance(resp_b["body"], dict) else {}

        # v9.18.3 — Don't fire on shape similarity alone. Many endpoints
        # (`GET /auth/me`, `/dashboard`, `/audit-programs`, …) return the
        # same response *shape* for every authenticated caller while
        # serving each user's own data. Real IDOR requires that token B
        # actually receive token A's resource. We confirm that by either
        # byte-equality of normalised bodies, or by an ID-bearing field
        # carrying the same value across A and B.
        same_resource, reason = shared_resource_signal(norm_a, norm_b)
        similarity = jaccard_keys(norm_a, norm_b)

        if same_resource and has_pii(resp_b["body"] if isinstance(resp_b["body"], dict) else {}):
            finding = {
                "type": "idor_confirmed",
                "severity": "high",
                "detail": f"Cross-user IDOR: token_b accessed token_a's resource ({method} {path})",
                "url": resp_b["url"],
                "evidence": f"{reason}; PII exposed; similarity={similarity:.0%}; "
                            f"B got HTTP {resp_b['status']}",
            }
            findings.append(finding)
            if saver:
                saver.save(finding)
                saver.save_txt(finding)
        elif same_resource:
            finding = {
                "type": "idor_probable",
                "severity": "medium",
                "detail": f"Probable IDOR: token_b received token_a's identifying data "
                          f"({method} {path})",
                "url": resp_b["url"],
                "evidence": f"{reason}; similarity={similarity:.0%}; "
                            f"B got HTTP {resp_b['status']}",
            }
            findings.append(finding)
            if saver:
                saver.save(finding)
                saver.save_txt(finding)
        # else: same shape, different values across the two tokens —
        # benign per-user endpoint. Suppress to avoid the FP that
        # plagued earlier runs on `/auth/me`, `/dashboard`, etc.

    # Phase 3: ID mutation (if id_field specified in body)
    if id_field and id_field in body:
        original_id = str(body[id_field])
        for mutated_id in mutate_id(original_id)[:5]:
            mut_body = dict(body)
            mut_body[id_field] = mutated_id
            resp = session.request(method, path, token=token_b, json_body=mut_body)
            if resp["status"] in (200, 201) and isinstance(resp["body"], dict):
                if has_pii(resp["body"]):
                    finding = {
                        "type": "idor_id_mutation",
                        "severity": "high",
                        "detail": f"IDOR via ID mutation: {id_field}={original_id}→{mutated_id} ({method} {path})",
                        "url": resp["url"],
                        "evidence": f"Mutated {id_field}={mutated_id}, got HTTP {resp['status']} with PII",
                    }
                    findings.append(finding)
                    if saver:
                        saver.save(finding)
                        saver.save_txt(finding)
                    break  # One confirmed is enough

    return findings


def run_idor_scan(base_url: str, token_a: str, token_b: str,
                   endpoints_file: str = None, output_dir: str = None,
                   rate_limit: float = 10.0) -> list[dict]:
    """Run IDOR scan across all endpoints."""
    print(f"[*] API IDOR Scanner: {base_url}")

    limiter = RateLimiter(rate_limit)
    session = AuthSession(base_url, limiter)

    if endpoints_file and os.path.isfile(endpoints_file):
        with open(endpoints_file) as f:
            endpoints = json.load(f)
    else:
        print("  [!] No endpoints file — using default LMS endpoints")
        endpoints = [{"path": p, "method": "POST", "body": {}} for p in [
            "learner-list/", "instructor-list/", "course-list/",
            "view-learner/", "view-instructor/", "view-course/",
            "learner-report/", "quiz-report/", "users-report/",
        ]]

    saver = FindingSaver(output_dir, "idor") if output_dir else None
    all_findings = []

    print(f"  [*] Testing {len(endpoints)} endpoints for IDOR...")
    for ep in endpoints:
        findings = test_idor(session, ep, token_a, token_b, saver)
        marker = f"[IDOR x{len(findings)}]" if findings else "[OK]"
        print(f"  {marker} {ep.get('method', 'POST')} {ep['path']}")
        all_findings.extend(findings)

    if saver:
        saver.save_summary()
    print(f"\n  [+] Done: {len(all_findings)} IDOR findings")
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Vikramaditya API IDOR Scanner")
    parser.add_argument("--base-url", required=True, help="API base URL")
    parser.add_argument("--token-a", required=True, help="Token for User A (resource owner)")
    parser.add_argument("--token-b", required=True, help="Token for User B (attacker)")
    parser.add_argument("--endpoints", help="Endpoints JSON file")
    parser.add_argument("--output", help="Output directory")
    parser.add_argument("--rate-limit", type=float, default=10.0)
    args = parser.parse_args()

    run_idor_scan(args.base_url, args.token_a, args.token_b,
                  args.endpoints, args.output, args.rate_limit)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
NoSQL operator-injection differential probe.

Trigger: api-maya / hrms-user-gateway engagement (2026-04). The blackbox
scanner reported "NoSQL injection" on every endpoint where sending
``{"$gt": ""}`` produced a 500. Codex review showed those were actually
generic type-confusion crashes — the same endpoints also 500'd on
``{"foo": "bar"}`` and on a bare array, so the finding was false-positive.
This module replaces the single-payload check with a six-probe differential
that distinguishes:

* NOT_VULNERABLE   — server handles all six probes the same as baseline.
* TYPE_CONFUSION   — server crashes on ANY non-string input (object, array,
                     operator) — a robustness bug, not a NoSQL injection.
* OPERATOR_INJECTION — server accepts ``$eq`` / ``$gt`` / ``$ne`` and the
                     response shape is materially different from a plain
                     object payload (e.g. baseline 200 / object 200 /
                     ``$ne`` returns extra rows or auth context).
* AUTH_BYPASS      — same as OPERATOR_INJECTION, but the operator probe
                     flips an unauthenticated request to a 200 with body
                     length matching an authenticated baseline.

Also reusable as a library by other modules (``autopilot_api_hunt.py``
phase 8a, future GraphQL adapter, etc.).

Usage as a library
------------------
    >>> from whitebox.nosql_probe import NoSQLProbe
    >>> probe = NoSQLProbe(
    ...     url="https://api.example.com/login",
    ...     headers={"Authorization": "Bearer abc"},
    ...     template={"email": "<INJECT>", "password": "x"},
    ... )
    >>> result = probe.run()
    >>> result["verdict"]
    'TYPE_CONFUSION'
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import requests
from requests import Response

# Strict TLS by default; opt out via VAPT_INSECURE_SSL=1 to match the rest
# of the toolchain (Semgrep ERROR fix, v9.x).
VERIFY_TLS = os.environ.get("VAPT_INSECURE_SSL", "0") != "1"

# Differential probe payloads. Order matters: indexes are referenced in
# the verdict logic below.
PROBES: list[tuple[str, Any]] = [
    ("baseline_str", "vapt-probe"),                  # 0 — the control
    ("number", 1337),                                # 1 — type confusion?
    ("array", ["vapt"]),                             # 2 — type confusion?
    ("object", {"foo": "bar"}),                      # 3 — type confusion?
    ("op_eq", {"$eq": "vapt-probe"}),                # 4 — true NoSQL op
    ("op_gt", {"$gt": ""}),                          # 5 — true NoSQL op
    ("op_ne", {"$ne": "__never_matches__"}),         # 6 — true NoSQL op
]

# Body fragments that imply the server choked on the input shape but
# never actually evaluated a query — i.e. type confusion, not injection.
TYPE_ERROR_HINTS = re.compile(
    r"(typeerror|valueerror|cannot read property|cast.*to.*string|"
    r"expected.*string|invalid input syntax|unsupported type)",
    re.IGNORECASE,
)


def _safe_status(resp: Response | None) -> int:
    return resp.status_code if resp is not None else 0


def _safe_len(resp: Response | None) -> int:
    return len(resp.content) if resp is not None else 0


def _error_signature(resp: Response | None) -> str:
    """Return a short, normalised signature of the response error body."""
    if resp is None:
        return "no_response"
    text = (resp.text or "")[:600]
    match = TYPE_ERROR_HINTS.search(text)
    return match.group(0).lower() if match else ""


class NoSQLProbe:
    """Differential NoSQL operator-injection probe for one parameter."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        template: dict | None = None,
        method: str = "POST",
        param: str | None = None,
        timeout: int = 8,
    ) -> None:
        self.url = url
        self.headers = headers or {}
        self.template = dict(template or {})
        self.method = method.upper()
        # Either pick the first <INJECT> sentinel from template or trust the
        # explicit ``param`` argument.
        self.param = param or self._auto_pick_param()
        self.timeout = timeout

    def _auto_pick_param(self) -> str:
        for k, v in self.template.items():
            if v == "<INJECT>":
                return k
        # Fallback: first key.
        return next(iter(self.template), "q")

    def _build_body(self, value: Any) -> dict:
        body = dict(self.template)
        body[self.param] = value
        return body

    def _send(self, value: Any) -> Response | None:
        try:
            return requests.request(
                self.method, self.url,
                json=self._build_body(value),
                headers=self.headers,
                timeout=self.timeout,
                verify=VERIFY_TLS,
                allow_redirects=False,
            )
        except requests.RequestException:
            return None

    def run(self) -> dict:
        """Send all probes and return a verdict dict."""
        results = []
        for name, value in PROBES:
            resp = self._send(value)
            results.append({
                "probe": name,
                "value": value,
                "status": _safe_status(resp),
                "length": _safe_len(resp),
                "err_sig": _error_signature(resp),
            })

        baseline, num, arr, obj, op_eq, op_gt, op_ne = results
        op_results = [op_eq, op_gt, op_ne]

        # Helper: did baseline succeed?
        baseline_ok = 200 <= baseline["status"] < 400

        # 1) Type-confusion: any non-string probe blew up the server in the
        # same way as the operator probes. This is the api-maya pattern —
        # ``{"foo":"bar"}`` and ``{"$gt":""}`` both 500. Not a NoSQL bug.
        non_str_5xx = [
            p for p in (num, arr, obj, *op_results) if p["status"] >= 500
        ]
        if obj["status"] >= 500 and any(p["status"] >= 500 for p in op_results):
            return self._verdict("TYPE_CONFUSION", baseline, results,
                                 reason="object payload and operator payload "
                                        "both 5xx — server can't handle "
                                        "non-string input, not NoSQL")

        # 2) Auth-bypass: baseline was 401/403 but operator probe returned
        # 200 with a body length consistent with success.
        if baseline["status"] in (401, 403):
            for op in op_results:
                if 200 <= op["status"] < 300 and op["length"] > baseline["length"] + 32:
                    return self._verdict("AUTH_BYPASS", baseline, results,
                                         reason=f"{op['probe']} flipped "
                                                f"{baseline['status']}→{op['status']}")

        # 3) Operator-injection: baseline succeeded with a real payload, the
        # plain-object probe returned a clean 4xx (validation rejection),
        # but ``$ne`` / ``$gt`` / ``$eq`` returned 200 with a body length
        # different from baseline (extra rows, different doc).
        obj_clean_reject = 400 <= obj["status"] < 500 and obj["status"] != 422
        if baseline_ok and obj_clean_reject:
            for op in op_results:
                if 200 <= op["status"] < 300 and abs(op["length"] - baseline["length"]) > 32:
                    return self._verdict("OPERATOR_INJECTION", baseline, results,
                                         reason=f"{op['probe']} accepted; "
                                                f"object payload rejected with "
                                                f"{obj['status']}")

        # 4) Otherwise: not vulnerable (or the server is so broken that no
        # signal is extractable — caller can re-test with another param).
        return self._verdict("NOT_VULNERABLE", baseline, results,
                             reason="no differential signal across 6 probes")

    @staticmethod
    def _verdict(verdict: str, baseline: dict, results: list[dict],
                 reason: str) -> dict:
        return {
            "verdict": verdict,
            "reason": reason,
            "baseline": baseline,
            "probes": results,
        }


def to_finding(probe_result: dict, url: str, param: str) -> dict | None:
    """Convert a probe result into the finding dict ``reporter.py`` expects.

    Returns ``None`` for NOT_VULNERABLE so callers can ``filter(None, ...)``.
    """
    verdict = probe_result.get("verdict")
    if verdict == "NOT_VULNERABLE":
        return None

    severity_map = {
        "TYPE_CONFUSION":     "low",
        "OPERATOR_INJECTION": "high",
        "AUTH_BYPASS":        "critical",
    }
    type_map = {
        "TYPE_CONFUSION":     "nosql_type_confusion",
        "OPERATOR_INJECTION": "nosql_operator_injection",
        "AUTH_BYPASS":        "nosql_auth_bypass",
    }
    return {
        "type": type_map.get(verdict, "nosql_unknown"),
        "severity": severity_map.get(verdict, "medium"),
        "detail": f"NoSQL probe: {verdict} on {param}",
        "url": url,
        "evidence": probe_result.get("reason", ""),
        "probes": probe_result.get("probes", []),
    }


__all__ = ["NoSQLProbe", "PROBES", "to_finding"]

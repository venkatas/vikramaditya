"""HAR-replay differential probe — authenticated NoSQL/operator-injection
discovery driven by a captured browser session.

The blackbox API hunter (``autopilot_api_hunt.py``) only sees endpoints it
discovers via Swagger / JS scraping / authenticated crawl. Real product
flows — multi-step wizards, role-gated admin pages, paginated bulk endpoints —
often only fire from the browser and are missed. A HAR file captured during
manual exploration covers exactly that gap.

For every in-scope JSON POST/PUT in the HAR, this module re-issues the
request six different ways (the same probe matrix as
``whitebox/nosql_probe.NoSQLProbe``) on each top-level JSON parameter and
classifies the result with the same TYPE_CONFUSION / OPERATOR_INJECTION /
AUTH_BYPASS rules.

Usage as a library
------------------
    >>> from whitebox.har_replay import HARReplayProbe
    >>> probe = HARReplayProbe(
    ...     har_path="captured.har",
    ...     scope_hosts=["api.example.com"],
    ...     output_dir="recon/example.com/sessions/<id>/findings/har_replay",
    ...     auth_cookies={"sessionid": "..."},
    ... )
    >>> results = probe.run()
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import requests

from whitebox.nosql_probe import (
    PROBES,
    TYPE_ERROR_HINTS,
    VERIFY_TLS,
    _safe_len,
    _safe_status,
    _error_signature,
)

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_name(s: str, max_len: int = 80) -> str:
    s = _SAFE_NAME_RE.sub("_", s).strip("._") or "unknown"
    return s[:max_len]


def _hash_body(resp) -> str:
    if resp is None:
        return ""
    return hashlib.sha256((resp.content or b"")).hexdigest()[:16]


class HARReplayProbe:
    """Replay every in-scope JSON POST/PUT in a HAR with the 6 differential probes."""

    def __init__(
        self,
        har_path: str | os.PathLike,
        scope_hosts: Iterable[str],
        output_dir: str | os.PathLike | None = None,
        auth_cookies: dict[str, str] | None = None,
        timeout: int = 8,
    ) -> None:
        self.har_path = Path(har_path)
        self.scope_hosts = {h.lower() for h in scope_hosts}
        self.output_dir = Path(output_dir) if output_dir else None
        self.auth_cookies = auth_cookies or {}
        self.timeout = timeout

    # ----- HAR parsing ------------------------------------------------------

    def _load_entries(self) -> list[dict]:
        try:
            data = json.loads(self.har_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return []
        return (data.get("log") or {}).get("entries", []) or []

    def _in_scope(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        host = host.lower()
        if not self.scope_hosts:
            return True
        return any(host == s or host.endswith("." + s) for s in self.scope_hosts)

    def _candidate_requests(self) -> list[dict]:
        """Yield {url, method, headers, json_body, params} for each in-scope JSON POST/PUT."""
        out: list[dict] = []
        for entry in self._load_entries():
            req = entry.get("request") or {}
            method = (req.get("method") or "").upper()
            if method not in ("POST", "PUT", "PATCH"):
                continue
            url = req.get("url") or ""
            if not url or not self._in_scope(url):
                continue
            post = req.get("postData") or {}
            mime = (post.get("mimeType") or "").lower()
            text = post.get("text") or ""
            if "json" not in mime and not text.strip().startswith("{"):
                continue
            try:
                body = json.loads(text)
            except Exception:
                continue
            if not isinstance(body, dict) or not body:
                continue
            headers = {h["name"]: h["value"] for h in req.get("headers", [])
                       if isinstance(h, dict) and h.get("name") and h.get("value")
                       and h["name"].lower() not in ("content-length", "host",
                                                    "connection", "accept-encoding")}
            out.append({
                "url": url,
                "method": method,
                "headers": headers,
                "json_body": body,
                "params": list(body.keys()),
            })
        return out

    # ----- probing ----------------------------------------------------------

    def _send(self, url: str, method: str, headers: dict, body: dict):
        try:
            return requests.request(
                method, url,
                json=body,
                headers=headers,
                cookies=self.auth_cookies or None,
                timeout=self.timeout,
                verify=VERIFY_TLS,
                allow_redirects=False,
            )
        except requests.RequestException:
            return None

    def _probe_param(self, req: dict, param: str) -> dict:
        """Run all six probes against one parameter and return per-probe records."""
        records: list[dict] = []
        for name, value in PROBES:
            body = dict(req["json_body"])
            body[param] = value
            resp = self._send(req["url"], req["method"], req["headers"], body)
            records.append({
                "probe": name,
                "value": value if not isinstance(value, (dict, list)) else json.dumps(value),
                "status": _safe_status(resp),
                "length": _safe_len(resp),
                "body_sha256_16": _hash_body(resp),
                "err_sig": _error_signature(resp),
            })
        return self._verdict_from_records(records)

    @staticmethod
    def _verdict_from_records(records: list[dict]) -> dict:
        """Apply the same TYPE_CONFUSION / OPERATOR_INJECTION / AUTH_BYPASS
        decision rules as ``NoSQLProbe._verdict`` — kept logic-equivalent so
        signal stays consistent between the live probe and HAR replay."""
        baseline, num, arr, obj, op_eq, op_gt, op_ne = records
        op_results = [op_eq, op_gt, op_ne]
        baseline_ok = 200 <= baseline["status"] < 400

        if obj["status"] >= 500 and any(p["status"] >= 500 for p in op_results):
            return {
                "verdict": "TYPE_CONFUSION",
                "cwe": "CWE-20",
                "severity": "MEDIUM",
                "reason": "object payload and operator payload both 5xx — "
                          "server can't handle non-string input, not NoSQL",
                "probes": records,
            }

        if baseline["status"] in (401, 403):
            for op in op_results:
                if 200 <= op["status"] < 300 and op["length"] > baseline["length"] + 32:
                    return {
                        "verdict": "AUTH_BYPASS",
                        "cwe": "CWE-287",
                        "severity": "CRITICAL",
                        "reason": f"{op['probe']} flipped {baseline['status']}→{op['status']}",
                        "probes": records,
                    }

        obj_clean_reject = 400 <= obj["status"] < 500 and obj["status"] != 422
        if baseline_ok and obj_clean_reject:
            for op in op_results:
                if 200 <= op["status"] < 300 and abs(op["length"] - baseline["length"]) > 32:
                    return {
                        "verdict": "OPERATOR_INJECTION",
                        "cwe": "CWE-943",
                        "severity": "HIGH",
                        "reason": (f"{op['probe']} accepted; object payload "
                                   f"rejected with {obj['status']}"),
                        "probes": records,
                    }

        return {
            "verdict": "NOT_VULNERABLE",
            "severity": "INFO",
            "reason": "no differential signal across 6 probes",
            "probes": records,
        }

    # ----- driver ----------------------------------------------------------

    def run(self) -> list[dict]:
        """Replay every candidate HAR request and write per-endpoint JSON."""
        all_results: list[dict] = []
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        for req in self._candidate_requests():
            host = urlparse(req["url"]).hostname or "unknown"
            endpoint = urlparse(req["url"]).path or "/"
            per_param: dict[str, dict] = {}
            for param in req["params"]:
                per_param[param] = self._probe_param(req, param)
            payload = {
                "url": req["url"],
                "method": req["method"],
                "host": host,
                "endpoint": endpoint,
                "params": req["params"],
                "results": per_param,
            }
            all_results.append(payload)
            if self.output_dir:
                fname = f"{_safe_name(host)}_{_safe_name(endpoint)}.json"
                (self.output_dir / fname).write_text(json.dumps(payload, indent=2))
        return all_results


__all__ = ["HARReplayProbe"]

#!/usr/bin/env python3
from __future__ import annotations
"""
Resolved-vector ledger — session-scoped JSON log of attack vectors already
attempted / confirmed / resolved / blocked.

Prevents blind retests of settled vectors. Pure stdlib.

Inspired by PentestCode resolved-vector tracking ideas (MIT) — clean-room Python.
"""

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


VALID_STATUSES = frozenset({"attempted", "confirmed", "resolved", "blocked"})


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _vector_id(target: str, vector: str) -> str:
    raw = f"{(target or '').strip().lower()}|{(vector or '').strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def default_ledger_path(session_dir: str | None = None) -> str | None:
    """Resolve ledger path from env or session_dir.

    Priority:
      1. VIK_RESOLVED_VECTORS env (explicit file path)
      2. <session_dir>/resolved_vectors.json
    """
    env = (os.environ.get("VIK_RESOLVED_VECTORS") or "").strip()
    if env:
        return env
    if session_dir:
        return os.path.join(session_dir, "resolved_vectors.json")
    return None


def load_ledger(path: str | None) -> list:
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("vectors"), list):
            return data["vectors"]
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return []
    return []


def save_ledger(path: str | None, vectors: list) -> None:
    if not path:
        return
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    payload = list(vectors or [])
    # Atomic replace
    fd, tmp = tempfile.mkstemp(prefix=".resolved_vectors_", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=False)
            f.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def upsert_vector(path: str | None, **fields: Any) -> dict:
    """Insert or update a vector entry. Requires target + vector (or id)."""
    vectors = load_ledger(path)
    target = str(fields.get("target") or "")
    vector = str(fields.get("vector") or "")
    vid = fields.get("id") or _vector_id(target, vector)

    existing = None
    for i, v in enumerate(vectors):
        if v.get("id") == vid or (
            (v.get("target") or "").lower() == target.lower()
            and (v.get("vector") or "").lower() == vector.lower()
        ):
            existing = i
            break

    if existing is None:
        entry = {
            "id": vid,
            "timestamp": fields.get("timestamp") or _utc_now(),
            "target": target,
            "vector": vector,
            "status": fields.get("status") or "attempted",
            "tested_by": fields.get("tested_by"),
            "attempts": int(fields.get("attempts") or 0),
            "evidence": fields.get("evidence"),
            "revisit_when": fields.get("revisit_when"),
            "attempt_log": list(fields.get("attempt_log") or []),
        }
        # Drop None optional keys for cleanliness but keep schema keys
        vectors.append(entry)
    else:
        entry = dict(vectors[existing])
        for k, v in fields.items():
            if k == "id":
                continue
            if k == "attempt_log" and v is not None:
                entry["attempt_log"] = list(v)
            elif v is not None:
                entry[k] = v
        if "timestamp" not in fields:
            entry["timestamp"] = _utc_now()
        entry["id"] = vid
        vectors[existing] = entry

    if entry.get("status") not in VALID_STATUSES:
        entry["status"] = "attempted"

    save_ledger(path, vectors)
    return entry


def record_attempt(
    path: str | None,
    target: str,
    vector: str,
    technique: str,
    outcome: str,
    detail: str | None = None,
) -> dict | None:
    """Append an attempt_log row and bump attempts. No-op if path missing."""
    if not path:
        return None
    vectors = load_ledger(path)
    vid = _vector_id(target, vector)
    entry = None
    for v in vectors:
        if v.get("id") == vid or (
            (v.get("target") or "").lower() == (target or "").lower()
            and (v.get("vector") or "").lower() == (vector or "").lower()
        ):
            entry = v
            break
    if entry is None:
        entry = {
            "id": vid,
            "timestamp": _utc_now(),
            "target": target,
            "vector": vector,
            "status": "attempted",
            "tested_by": None,
            "attempts": 0,
            "evidence": None,
            "revisit_when": None,
            "attempt_log": [],
        }
        vectors.append(entry)

    log = list(entry.get("attempt_log") or [])
    log.append({
        "technique": technique,
        "outcome": outcome,
        "detail": detail,
        "timestamp": _utc_now(),
    })
    entry["attempt_log"] = log
    entry["attempts"] = int(entry.get("attempts") or 0) + 1
    entry["timestamp"] = _utc_now()
    # Promote status lightly from outcome
    oc = (outcome or "").lower()
    if oc in ("confirmed", "resolved", "blocked"):
        entry["status"] = oc
    elif entry.get("status") not in ("confirmed", "resolved", "blocked"):
        entry["status"] = "attempted"

    save_ledger(path, vectors)
    return entry


def is_resolved(path: str | None, target: str, vector: str) -> bool:
    if not path:
        return False
    for v in load_ledger(path):
        if (v.get("target") or "").lower() == (target or "").lower() and (
            v.get("vector") or ""
        ).lower() == (vector or "").lower():
            return (v.get("status") or "") == "resolved"
        if v.get("id") == _vector_id(target, vector):
            return (v.get("status") or "") == "resolved"
    return False


def should_skip(path: str | None, target: str, vector: str) -> tuple[bool, str]:
    """Skip blind retest of resolved/confirmed; blocked only if revisit_when unmet."""
    if not path:
        return False, "no ledger"
    for v in load_ledger(path):
        match = (
            (v.get("target") or "").lower() == (target or "").lower()
            and (v.get("vector") or "").lower() == (vector or "").lower()
        ) or v.get("id") == _vector_id(target, vector)
        if not match:
            continue
        status = (v.get("status") or "").lower()
        if status == "resolved":
            return True, "vector marked resolved — do not retest blindly"
        if status == "confirmed":
            return True, "vector already confirmed — do not retest blindly"
        if status == "blocked":
            revisit = v.get("revisit_when")
            if not revisit:
                return True, "vector blocked with no revisit_when"
            # If revisit_when is a future ISO timestamp, skip until then
            try:
                # Accept date or datetime; compare as strings if parse fails softly
                now = _utc_now()
                if str(revisit) > now:
                    return True, f"vector blocked until revisit_when={revisit}"
                return False, "blocked but revisit_when elapsed — ok to retry"
            except Exception:
                return True, "vector blocked"
        return False, f"status={status}"
    return False, "not in ledger"


def format_context(path: str | None, max: int = 30) -> str:
    """Compact block for brain prompts: dead ends + failed techniques."""
    if not path:
        return ""
    vectors = load_ledger(path)
    if not vectors:
        return ""
    lines = ["RESOLVED-VECTOR LEDGER (do not blindly retry):"]
    shown = 0
    # Prefer resolved/confirmed/blocked and failed attempts first
    def _rank(v: dict) -> int:
        s = (v.get("status") or "").lower()
        return {"resolved": 0, "confirmed": 1, "blocked": 2, "attempted": 3}.get(s, 9)

    for v in sorted(vectors, key=_rank):
        if shown >= max:
            break
        status = v.get("status") or "?"
        target = v.get("target") or "?"
        vector = v.get("vector") or "?"
        fails = [
            a.get("technique")
            for a in (v.get("attempt_log") or [])
            if (a.get("outcome") or "").lower() in ("fail", "failed", "blocked", "error", "negative")
        ]
        fail_s = f" failed=[{', '.join(fails[:5])}]" if fails else ""
        lines.append(f"- [{status}] {target} :: {vector}{fail_s}")
        shown += 1
    if shown == 0:
        return ""
    return "\n".join(lines)


# ── Heuristics for brain_scanner wiring ───────────────────────────────────────

_TOOL_RE = re.compile(
    r"\b(sqlmap|nuclei|ffuf|curl|dalfox|gobuster|feroxbuster|nmap)\b", re.I
)
_URL_RE = re.compile(r"https?://[^\s\"']+", re.I)


def infer_vector_key(code: str) -> tuple[str, str] | None:
    """Best-effort (target, vector) from a bash/tool command.

    Returns None if the command does not look like a repeatable attack vector.
    """
    if not code or not _TOOL_RE.search(code):
        return None
    tool_m = _TOOL_RE.search(code)
    tool = tool_m.group(1).lower()
    url_m = _URL_RE.search(code)
    url = url_m.group(0) if url_m else ""
    host = ""
    path = ""
    if url:
        try:
            p = urlparse(url)
            host = p.netloc or ""
            path = p.path or "/"
        except Exception:
            host = url
    # Technique hints
    technique = tool
    cl = code.lower()
    if tool == "sqlmap":
        technique = "sqlmap"
        pm = re.search(r"-p\s+(\S+)", code)
        if pm:
            technique = f"sqlmap:{pm.group(1)}"
    elif tool == "nuclei":
        technique = "nuclei"
        tm = re.search(r"-t\s+(\S+)|-tags?\s+(\S+)|-id\s+(\S+)", code)
        if tm:
            technique = f"nuclei:{(tm.group(1) or tm.group(2) or tm.group(3))}"
    elif tool == "ffuf":
        technique = "ffuf"
    elif tool == "curl":
        # Only treat curl as a vector when it looks like a PoC (payload-ish)
        if not re.search(r"(union\s+select|<\s*script|\$\{|;\s*id\b|/etc/passwd|\.\./)", cl):
            return None
        technique = "curl-poc"
    target = host or url or "unknown"
    vector = f"{technique}:{path}" if path else technique
    return target, vector


def looks_like_technique_failure(stdout: str, stderr: str = "") -> bool:
    """Heuristic: grounded run clearly failed a specific technique."""
    blob = f"{stdout or ''}\n{stderr or ''}".lower()
    if not blob.strip():
        return False
    fail_markers = (
        "not vulnerable", "not injectable", "does not seem to be injectable",
        "0 hosts", "no results found", "nothing found", "all tested",
        "parameter(s) are not injectable", "not exploitable",
        "false positive", "connection refused", "could not find",
    )
    # Don't treat confirmed vulns as failure
    if re.search(r"\b(is vulnerable|injectable|confirmed|\[critical\]|\[high\])\b", blob):
        if "not vulnerable" not in blob and "not injectable" not in blob:
            return False
    return any(m in blob for m in fail_markers)

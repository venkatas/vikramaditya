"""Per-engagement phase manifest + coverage consolidation (P1 fail-closed reporting).

Three problems this fixes:

1. A phase that failed (tool missing, non-zero exit, signal, timeout) could still leave
   ``result["success"] = True`` and exit 0 — a broken run looked like a clean pass.
2. Coverage limitations were split across three never-merged artifacts:
   ``coverage.json`` (hunt.py degraded list), ``manual_review/coverage_gaps.txt``
   (scanner.sh), and ``coverage_degraded.json`` (vikramaditya). The reporter only read
   the first, only in HTML, only if it was a list.
3. No phase manifest existed — exit codes / signals / timeouts / artifact counts were
   never persisted, so a resume or an operator could not tell what actually ran.

``record_phase`` appends one record per executed phase to ``<findings_dir>/phase_manifest.json``
and folds a top-level ``{overall_status, success}`` from the worst phase seen. ``merge_coverage``
normalizes the three artifacts into the canonical ``coverage.json`` list of
``{source, tool_or_phase, reason, status}`` so both report renderers show one honest picture.
"""
from __future__ import annotations

import json
import hashlib
import os
import re

from storage import atomic_write_bytes, atomic_write_json

# Phase statuses (a superset compatible with hunt.py's PHASE_STATUS_* strings).
PHASE_OK = "ran"
PHASE_SKIPPED = "skipped"
PHASE_DEGRADED = "degraded"
PHASE_FAILED = "failed"
PHASE_ABORTED = "aborted"

# Severity rank — anything >= 2 means the run is NOT a clean success.
_STATUS_RANK = {
    PHASE_OK: 0,
    PHASE_SKIPPED: 1,
    PHASE_DEGRADED: 2,
    PHASE_FAILED: 3,
    PHASE_ABORTED: 3,
}
_NOT_SUCCESS_THRESHOLD = 2

MANIFEST_NAME = "phase_manifest.json"
COVERAGE_NAME = "coverage.json"
_MISSING = object()


def _manifest_path(findings_dir: str) -> str:
    return os.path.join(findings_dir, MANIFEST_NAME)


def _new_doc() -> dict:
    return {"phases": [], "overall_status": "success", "success": True}


def _read_json_artifact(path: str) -> tuple[object, str | None]:
    """Missing optional evidence is different from existing unreadable evidence."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), None
    except FileNotFoundError:
        if os.path.lexists(path):
            return None, "artifact exists but its destination could not be read"
        return _MISSING, None
    except (ValueError, UnicodeError):
        return None, "invalid JSON or text encoding"
    except OSError:
        return None, "artifact exists but could not be read"


def _integrity_row(path: str, issue: str) -> dict:
    return {"source": "coverage_integrity", "tool_or_phase": "coverage",
            "reason": f"cannot verify {path}: {issue}", "status": PHASE_FAILED}


def _manifest_data(path: str) -> tuple[dict, str | None]:
    data, issue = _read_json_artifact(path)
    if data is _MISSING and issue is None:
        return _new_doc(), None
    if issue is None and (not isinstance(data, dict)
                          or not isinstance(data.get("phases"), list)
                          or any(not isinstance(row, dict)
                                 or not isinstance(row.get("status"), str)
                                 or row.get("status") not in _STATUS_RANK
                                 for row in data["phases"])
                          or ("success" in data and not isinstance(data["success"], bool))
                          or ("overall_status" in data and data["overall_status"] not in ("success", "inconclusive"))):
        issue = "invalid phase manifest schema"
    if issue is None and "integrity_errors" in data and _coverage_issue(
            data["integrity_errors"], rich_allowed=False):
        issue = "invalid manifest integrity metadata"
    if issue is not None:
        row = _integrity_row(path, issue)
        return {"phases": [{"phase": "MANIFEST INTEGRITY", "status": PHASE_FAILED,
                            "outcome": "integrity_error", "reason": row["reason"]}],
                "overall_status": "inconclusive", "success": False,
                "integrity_errors": [row]}, issue
    # Derive the result from evidence rather than trusting stale success flags.
    previously_failed = data.get("success") is False or data.get("overall_status") == "inconclusive"
    _fold(data)
    if previously_failed:
        data["success"] = False
        data["overall_status"] = "inconclusive"
    return data, None


def _load_manifest(path: str) -> dict:
    return _manifest_data(path)[0]


def _preserve_invalid_artifact(path: str) -> str:
    """Retain corrupt bytes before an atomic repair; fail if evidence cannot be saved."""
    with open(path, "rb") as fh:
        raw = fh.read()
    backup = f"{path}.corrupt.{hashlib.sha256(raw).hexdigest()}"
    if os.path.exists(backup):
        with open(backup, "rb") as fh:
            if fh.read() != raw:
                raise OSError("existing corruption backup does not match source evidence")
    else:
        atomic_write_bytes(backup, raw)
    return backup


def _coverage_issue(data: object, *, rich_allowed: bool = True) -> str | None:
    if isinstance(data, list):
        if any(not isinstance(row, dict) or not isinstance(row.get("reason"), str)
               or not row["reason"].strip()
               or not isinstance(row.get("status", PHASE_DEGRADED), str)
               or row.get("status", PHASE_DEGRADED) not in _STATUS_RANK for row in data):
            return "invalid coverage entry schema"
        return None
    if rich_allowed and isinstance(data, dict) and any(key in data for key in (
            "degraded", "probed_hosts", "total_hosts", "tested_ops", "tested_public_operations",
            "scope_blocked", "transport_errors")):
        for key in ("probed_hosts", "total_hosts", "tested_ops", "tested_public_operations",
                    "total_probeable_ops", "total_probeable_public_operations", "scope_blocked",
                    "attempted_hosts", "attempted_ops", "attempted_public_operations", "transport_errors"):
            value = data.get(key)
            if value is not None and (type(value) is not int or value < 0):
                return "invalid API coverage count schema"
        completed = data.get("probed_hosts")
        attempted = data.get("attempted_hosts", completed)
        total = data.get("total_hosts")
        tested = data.get("tested_public_operations", data.get("tested_ops"))
        attempted_ops = data.get("attempted_public_operations", data.get("attempted_ops", tested))
        operations = data.get("total_probeable_public_operations", data.get("total_probeable_ops"))
        if any(type(left) is int and type(right) is int and left > right
               for left, right in ((completed, attempted), (attempted, total),
                                   (tested, attempted_ops), (attempted_ops, operations))):
            return "inconsistent API coverage counts"
        if "degraded" in data and not isinstance(data["degraded"], (bool, list)):
            return "invalid API coverage degradation schema"
        if isinstance(data.get("degraded"), list) and any(
                not (isinstance(row, str) and row.strip())
                and _coverage_issue([row], rich_allowed=False)
                for row in data["degraded"]):
            return "invalid API coverage degradation entry schema"
        if "integrity_errors" in data and _coverage_issue(data["integrity_errors"], rich_allowed=False):
            return "invalid API integrity metadata"
        return None
    return "invalid coverage document schema"


def api_completion_shortfall(coverage: dict) -> str:
    """Independently detect incomplete requests, even if a producer lost error details."""
    completed = coverage.get("probed_hosts")
    attempted = coverage.get("attempted_hosts", completed)
    tested = coverage.get("tested_public_operations", coverage.get("tested_ops"))
    attempted_ops = coverage.get("attempted_public_operations", coverage.get("attempted_ops", tested))
    gaps = []
    for count, attempts, label in ((completed, attempted, "hosts"),
                                  (tested, attempted_ops, "public operations")):
        if label == "public operations" and coverage.get("discover_only"):
            continue
        if type(attempts) is int and attempts > 0 and (type(count) is not int or count < attempts):
            gaps.append(f"completed {count if type(count) is int else 'unknown'} of {attempts} attempted {label}")
    return "request completion shortfall — " + ", ".join(gaps) if gaps else ""


def write_coverage(findings_dir: str, rows: list) -> str:
    """Atomically publish coverage, preserving invalid prior evidence and its failure."""
    if _coverage_issue(rows, rich_allowed=False):
        raise ValueError("refusing to publish invalid coverage entries")
    path = os.path.join(findings_dir, COVERAGE_NAME)
    old, issue = _read_json_artifact(path)
    if old is not _MISSING and issue is None:
        issue = _coverage_issue(old)
    result = list(rows)
    old_errors = old if isinstance(old, list) else old.get("integrity_errors", []) if isinstance(old, dict) else []
    if isinstance(old_errors, list):
        for row in old_errors:
            if (isinstance(row, dict) and row.get("source") == "coverage_integrity"
                    and _coverage_issue([row], rich_allowed=False) is None and row not in result):
                result.append(dict(row))
    if issue:
        _preserve_invalid_artifact(path)
        row = _integrity_row(path, issue)
        if row not in result:
            result.append(row)
    atomic_write_json(path, result)
    return path


def write_coverage_summary(path: str, summary: dict) -> dict:
    """Atomic rich API coverage with durable errors for an invalid prior document."""
    old, issue = _read_json_artifact(path)
    if old is not _MISSING and issue is None:
        issue = _coverage_issue(old)
    old_errors = old.get("integrity_errors", []) if isinstance(old, dict) else []
    errors = [dict(row) for row in old_errors if _coverage_issue([row], rich_allowed=False) is None
              ] if isinstance(old_errors, list) else []
    if issue:
        _preserve_invalid_artifact(path)
        row = _integrity_row(path, issue)
        if row not in errors:
            errors.append(row)
    result = dict(summary)
    if errors:
        result["integrity_errors"] = errors
        result["degraded"] = True
    atomic_write_json(path, result)
    return result


PHASE_NEVER_INVOKED = "never_invoked"


def derive_status(exit_code=None, timed_out: bool = False, signal=None,
                  degraded: bool = False) -> str:
    """Map raw phase signals to a status. Fail-closed ordering: aborted > failed > degraded.

    Exit code -9 / signal 9 is a timeout kill (SIGKILL), not a generic failure and
    not "never invoked". A missing phase record is the never-invoked case.
    """
    if timed_out or signal or exit_code == -9:
        return PHASE_ABORTED
    if exit_code is not None and exit_code != 0:
        return PHASE_FAILED
    if degraded:
        return PHASE_DEGRADED
    return PHASE_OK


def invocation_outcome(record: dict | None) -> str:
    """Distinguish a phase that never started from one killed by timeout (-9)."""
    if not record:
        return PHASE_NEVER_INVOKED
    exit_code = record.get("exit_code")
    signal = record.get("signal")
    if record.get("timed_out") or signal == 9 or exit_code == -9:
        return "timeout"
    status = record.get("status")
    if status == PHASE_SKIPPED:
        return "skipped"
    return "invoked"


def _fold(doc: dict) -> None:
    worst = max((max(_STATUS_RANK.get(p.get("status"), 0),
                     _STATUS_RANK[derive_status(p.get("exit_code"), bool(p.get("timed_out")), p.get("signal"))])
                 for p in doc["phases"]), default=0)
    doc["success"] = (worst < _NOT_SUCCESS_THRESHOLD and not doc.get("integrity_errors")
                      and doc.get("success") is not False)
    doc["overall_status"] = "success" if doc["success"] else "inconclusive"


def record_phase(findings_dir: str, name: str, *, command: str = "", tool: str = "",
                 tool_version: str = "", start=None, end=None, exit_code=None,
                 timed_out: bool = False, signal=None, degraded: bool = False,
                 status: str | None = None, artifact_counts: dict | None = None) -> str | None:
    """Append one phase record and re-fold the overall status. Returns the manifest path.

    ``status`` may be passed explicitly; otherwise it is derived from
    exit_code/timed_out/signal/degraded. Never raises — a manifest write failure must not
    abort the assessment (but the coverage/success signal still lives in-memory in hunt.py)."""
    if not findings_dir or not name:
        return None
    try:
        os.makedirs(findings_dir, exist_ok=True)
    except OSError:
        return None
    path = _manifest_path(findings_dir)
    doc, issue = _manifest_data(path)
    if exit_code == -9 and signal is None:
        signal = 9
    if exit_code == -9 or signal == 9:
        timed_out = True
    if status is None:
        status = derive_status(exit_code, timed_out, signal, degraded)
    record = {
        "phase": name,
        "command": command,
        "tool": tool,
        "tool_version": tool_version,
        "start": start,
        "end": end,
        "exit_code": exit_code,
        "timed_out": bool(timed_out),
        "signal": signal,
        "status": status,
        "artifact_counts": artifact_counts or {},
    }
    record["outcome"] = invocation_outcome(record)
    doc["phases"].append(record)
    _fold(doc)
    try:
        if issue:
            _preserve_invalid_artifact(path)
        atomic_write_json(path, doc)
    except OSError:
        return None
    return path


def read_manifest(findings_dir: str) -> dict:
    """Return the manifest doc ({phases, overall_status, success}); empty doc if absent."""
    if not findings_dir:
        return _new_doc()
    return _load_manifest(_manifest_path(findings_dir))


def is_inconclusive(findings_dir: str) -> bool:
    """True when the manifest records any failed/aborted/degraded phase (fail-closed)."""
    return not read_manifest(findings_dir).get("success", True)


def _norm_reason(reason: str) -> str:
    return " ".join(str(reason or "").split()).strip()


def resolve_session_dirs(session_dir: str) -> tuple[str, str]:
    """Resolve the same session in the recon and findings trees.

    Replace only the first tree segment, preserving target/session names that
    happen to contain ``recon``, ``findings``, or ``reports`` themselves. Unknown
    legacy layouts keep their original directory for both artifact kinds.
    """
    session_dir = (session_dir or "").rstrip("/")
    match = re.search(r"(^|/)(recon|findings|reports)/", session_dir)
    if match is None:
        return session_dir, session_dir
    start, end = match.span(2)
    return (session_dir[:start] + "recon" + session_dir[end:],
            session_dir[:start] + "findings" + session_dir[end:])


def _degraded_marker_paths(findings_dir: str) -> list[str]:
    recon_dir, findings_dir = resolve_session_dirs(findings_dir)
    # The parent location supports the legacy <session>/findings layout. The
    # sibling recon location is the canonical split-tree layout used by hunt.py.
    return list(dict.fromkeys(
        os.path.join(directory, "coverage_degraded.json")
        for directory in (findings_dir, os.path.dirname(findings_dir), recon_dir)
    ))


def collect_coverage(findings_dir: str) -> list:
    """Read and normalize all coverage artifacts without modifying any of them.

    Sources, all optional:
      * ``coverage.json``                       — hunt.py list of {tool,reason}, an
                                                  already-merged list, or an api_audit dict.
      * ``manual_review/coverage_gaps.txt``     — scanner.sh '[COVERAGE-GAP] class: reason'.
      * ``coverage_degraded.json``              — local/legacy/sibling recon fallback gaps.
      * ``api_specs/{coverage,api_coverage}.json`` — same-session API producer coverage.

    Output element: {source, tool_or_phase, reason, status}. De-duplicated, idempotent.
    """
    if not findings_dir:
        return []
    recon_dir, findings_dir = resolve_session_dirs(findings_dir)
    merged: list = []
    seen: dict = {}

    def _add(source: str, tool: str, reason: str, status: str = "degraded") -> None:
        source = str(source or "").strip()
        tool = str(tool or "").strip()
        reason = _norm_reason(reason)
        if not reason:
            return
        key = (source, tool, reason)
        if key in seen:
            previous = seen[key]
            if _STATUS_RANK.get(status, 0) > _STATUS_RANK.get(previous["status"], 0):
                previous["status"] = status
            return
        row = {"source": source, "tool_or_phase": tool or "",
               "reason": reason, "status": status}
        seen[key] = row
        merged.append(row)

    def _read_coverage(path: str, *, rich_allowed: bool = True):
        data, issue = _read_json_artifact(path)
        if data is _MISSING:
            return None
        if issue is None:
            issue = _coverage_issue(data, rich_allowed=rich_allowed)
        if issue:
            row = _integrity_row(path, issue)
            _add(row["source"], row["tool_or_phase"], row["reason"], row["status"])
            return None
        return data

    for error in read_manifest(findings_dir).get("integrity_errors", []):
        if isinstance(error, dict):
            _add(error.get("source", "coverage_integrity"), error.get("tool_or_phase", "coverage"),
                 error.get("reason", "manifest integrity failure"), PHASE_FAILED)

    cov = os.path.join(findings_dir, COVERAGE_NAME)
    data = _read_coverage(cov)

    if isinstance(data, list):
        for e in data:
            if not isinstance(e, dict):
                continue
            if "tool_or_phase" in e or "source" in e:        # already-merged element
                _add(e.get("source", "hunt"), e.get("tool_or_phase", ""),
                     e.get("reason", ""), e.get("status", "degraded"))
            else:                                            # hunt.py {tool,reason}
                status = "aborted" if str(e.get("reason", "")).startswith("ABORTED") else "degraded"
                _add("hunt", e.get("tool", ""), e.get("reason", ""), status)
    elif isinstance(data, dict):                             # api_audit dict schema
        deg = data.get("degraded")
        if isinstance(deg, list):
            for d in deg:
                if isinstance(d, dict):
                    _add("api_audit", d.get("tool", ""), d.get("reason", ""))
                elif isinstance(d, str):
                    _add("api_audit", "", d)
        probed, total = data.get("probed_hosts"), data.get("total_hosts")
        attempted = data.get("attempted_hosts", probed)
        if isinstance(attempted, int) and isinstance(total, int) and 0 <= attempted < total:
            _add("api_audit", "api_audit",
                 f"probed {probed} of {total} hosts (surface capped)", "degraded")
        if data.get("transport_errors"):
            _add("api_audit", "api_audit",
                 f"transport failed {data['transport_errors']} request(s); partial coverage")
        if data.get("scope_blocked"):
            _add("api_audit", "api_audit",
                 f"scope blocked {data['scope_blocked']} destination(s) or policy failures; partial coverage")
        shortfall = api_completion_shortfall(data)
        if shortfall:
            _add("api_audit", "api_audit", shortfall)
        for error in data.get("integrity_errors", []):
            _add(error.get("source", "coverage_integrity"), error.get("tool_or_phase", "coverage"),
                 error.get("reason", "coverage integrity failure"), PHASE_FAILED)
        if deg is True and not data.get("integrity_errors") and not any(
                row["source"] == "api_audit" for row in merged):
            _add("api_audit", "api_audit", "API audit reported degraded coverage")

    # The OpenAPI producer writes below recon/api_specs, not the findings
    # root. Read only the matching session's explicit producer paths: walking
    # parents or globbing other sessions would leak unrelated engagement gaps.
    for directory in dict.fromkeys((recon_dir, findings_dir)):
        api_dir = os.path.join(directory, "api_specs")
        for filename in (COVERAGE_NAME, "api_coverage.json"):
            api = _read_coverage(os.path.join(api_dir, filename))
            if isinstance(api, list):
                for entry in api:
                    if isinstance(entry, dict):
                        _add(entry.get("source", "api_audit"),
                             entry.get("tool_or_phase") or entry.get("tool") or "api_audit",
                             entry.get("reason", ""), entry.get("status", "degraded"))
                continue
            if not isinstance(api, dict):
                continue
            for error in api.get("integrity_errors", []):
                if isinstance(error, dict):
                    _add(error.get("source", "coverage_integrity"), error.get("tool_or_phase", "coverage"),
                         error.get("reason", "API coverage integrity failure"), PHASE_FAILED)
            # A rich summary is also authoritative when the canonical producer
            # list is missing. Match the producer's reason so reading both and
            # later merging the canonical list stays idempotent.
            probed, total = api.get("probed_hosts"), api.get("total_hosts")
            attempted_hosts = api.get("attempted_hosts", probed)
            tested = api.get("tested_public_operations", api.get("tested_ops"))
            attempted_ops = api.get("attempted_public_operations", api.get("attempted_ops", tested))
            operations = api.get("total_probeable_public_operations", api.get("total_probeable_ops"))
            host_cap = (type(attempted_hosts) is int and type(total) is int and 0 <= attempted_hosts < total)
            op_cap = (not api.get("discover_only") and type(attempted_ops) is int
                      and type(operations) is int and 0 <= attempted_ops < operations)
            blocked = api.get("scope_blocked", 0)
            blocked = blocked if type(blocked) is int and blocked > 0 else 0
            reason = ""
            if host_cap or op_cap:
                reason = (f"surface capped — probed {probed} of {total} hosts, "
                          f"{tested} of {operations} public operations")
            if blocked:
                reason += ("; " if reason else "") + f"scope blocked {blocked} destination(s) or policy failures; partial coverage"
            shortfall = api_completion_shortfall(api)
            if shortfall:
                reason += ("; " if reason else "") + shortfall
            transport_errors = api.get("transport_errors", 0)
            if type(transport_errors) is int and transport_errors > 0:
                reason += ("; " if reason else "") + f"transport failed {transport_errors} request(s); partial coverage"
            if reason:
                _add("api_audit", "api_audit", reason)
            if api.get("degraded") is True and not reason and not api.get("integrity_errors"):
                _add("api_audit", "api_audit", "API audit reported degraded coverage")
            elif isinstance(api.get("degraded"), list):
                for entry in api["degraded"]:
                    if isinstance(entry, dict):
                        _add("api_audit", entry.get("tool_or_phase") or entry.get("tool") or "api_audit",
                             entry.get("reason", ""), entry.get("status", "degraded"))
                    elif isinstance(entry, str):
                        _add("api_audit", "api_audit", entry)

    gap_directories = [(findings_dir, "scanner.sh")]
    if recon_dir != findings_dir:
        gap_directories.append((recon_dir, "recon.sh"))
    for directory, source in gap_directories:
        gaps = os.path.join(directory, "manual_review", "coverage_gaps.txt")
        try:
            with open(gaps, encoding="utf-8") as fh:
                for ln in fh:
                    txt = ln.replace("[COVERAGE-GAP]", "").strip()
                    if not txt:
                        continue
                    if ":" in txt:
                        cls, reason = txt.split(":", 1)
                        _add(source, cls.strip(), reason.strip())
                    else:
                        _add(source, "", txt)
        except FileNotFoundError:
            pass
        except (OSError, UnicodeError):
            row = _integrity_row(gaps, "coverage gap artifact could not be read")
            _add(row["source"], row["tool_or_phase"], row["reason"], row["status"])

    # Read every supported location: an empty or stale local marker must not
    # hide fallback failures stored in the sibling recon session.
    for deg_path in _degraded_marker_paths(findings_dir):
        dd = _read_coverage(deg_path, rich_allowed=False)
        if isinstance(dd, list):
            for e in dd:
                if isinstance(e, dict):
                    _add(e.get("source", "vikramaditya"),
                         e.get("tool_or_phase") or e.get("tool") or e.get("phase", ""),
                         e.get("reason", ""), e.get("status", "degraded"))

    return merged


def assessment_status(findings_dir: str, coverage: list | None = None) -> str:
    """Canonical report/CLI outcome, including persisted non-core coverage gaps.

    ``is_inconclusive`` intentionally retains its manifest-only public meaning.
    Callers already collecting rows may supply that snapshot to avoid rereading.
    A completed zero-finding phase is conclusive when no failure/gap is recorded.
    """
    _, findings_dir = resolve_session_dirs(findings_dir)
    coverage = collect_coverage(findings_dir) if coverage is None else coverage
    inconclusive = is_inconclusive(findings_dir) or any(
        row.get("status") in (PHASE_DEGRADED, PHASE_FAILED, PHASE_ABORTED)
        for row in coverage
    )
    return "inconclusive" if inconclusive else "complete"


def merge_coverage(findings_dir: str, *, prior_rows: list | None = None) -> list:
    """Persist normalized rows, retaining an optional pre-write resume snapshot.

    Persistence errors reach the owner so they cannot be reported as clean
    completion merely because collection itself succeeded.
    """
    if not findings_dir:
        return []
    _, findings_dir = resolve_session_dirs(findings_dir)
    merged = collect_coverage(findings_dir)
    # Hunt writes its current in-memory list before consolidation. Retain prior
    # canonical rows so that targeted resumes cannot erase unaddressed gaps.
    seen = {(row["source"], row["tool_or_phase"], row["reason"]) for row in merged}
    for row in prior_rows or []:
        key = (row["source"], row["tool_or_phase"], row["reason"])
        if key not in seen:
            merged.append(dict(row))
            seen.add(key)
    write_coverage(findings_dir, merged)
    return merged

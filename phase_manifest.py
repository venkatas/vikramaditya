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
import os

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


def _manifest_path(findings_dir: str) -> str:
    return os.path.join(findings_dir, MANIFEST_NAME)


def _new_doc() -> dict:
    return {"phases": [], "overall_status": "success", "success": True}


def _load_manifest(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if isinstance(doc, dict) and isinstance(doc.get("phases"), list):
            return doc
    except (OSError, ValueError):
        pass
    return _new_doc()


def derive_status(exit_code=None, timed_out: bool = False, signal=None,
                  degraded: bool = False) -> str:
    """Map raw phase signals to a status. Fail-closed ordering: aborted > failed > degraded."""
    if timed_out or signal:
        return PHASE_ABORTED
    if exit_code is not None and exit_code != 0:
        return PHASE_FAILED
    if degraded:
        return PHASE_DEGRADED
    return PHASE_OK


def _fold(doc: dict) -> None:
    worst = max((_STATUS_RANK.get(p.get("status"), 0) for p in doc["phases"]), default=0)
    doc["success"] = worst < _NOT_SUCCESS_THRESHOLD
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
    doc = _load_manifest(path)
    if status is None:
        status = derive_status(exit_code, timed_out, signal, degraded)
    doc["phases"].append({
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
    })
    _fold(doc)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
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
    return " ".join((reason or "").split()).strip()


def merge_coverage(findings_dir: str) -> list:
    """Consolidate the three coverage artifacts into the canonical coverage.json list.

    Sources, all optional:
      * ``coverage.json``                       — hunt.py list of {tool,reason}, an
                                                  already-merged list, or an api_audit dict.
      * ``manual_review/coverage_gaps.txt``     — scanner.sh '[COVERAGE-GAP] class: reason'.
      * ``coverage_degraded.json``              — vikramaditya {tool,reason,phase,ts} list.

    Output element: {source, tool_or_phase, reason, status}. De-duplicated, idempotent.
    """
    if not findings_dir:
        return []
    merged: list = []
    seen: set = set()

    def _add(source: str, tool: str, reason: str, status: str = "degraded") -> None:
        reason = _norm_reason(reason)
        if not reason:
            return
        key = (source, tool, reason)
        if key in seen:
            return
        seen.add(key)
        merged.append({"source": source, "tool_or_phase": tool or "",
                       "reason": reason, "status": status})

    cov = os.path.join(findings_dir, COVERAGE_NAME)
    data = None
    try:
        with open(cov, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = None

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
        if isinstance(probed, int) and isinstance(total, int) and 0 <= probed < total:
            _add("api_audit", "api_audit",
                 f"probed {probed} of {total} hosts (surface capped)", "degraded")

    gaps = os.path.join(findings_dir, "manual_review", "coverage_gaps.txt")
    try:
        with open(gaps, encoding="utf-8") as fh:
            for ln in fh:
                txt = ln.replace("[COVERAGE-GAP]", "").strip()
                if not txt:
                    continue
                if ":" in txt:
                    cls, reason = txt.split(":", 1)
                    _add("scanner.sh", cls.strip(), reason.strip())
                else:
                    _add("scanner.sh", "", txt)
    except OSError:
        pass

    # vikramaditya writes coverage_degraded.json to the session dir; look in findings_dir
    # and one level up (findings/ is usually a child of the session dir).
    for deg_path in (os.path.join(findings_dir, "coverage_degraded.json"),
                     os.path.join(os.path.dirname(findings_dir.rstrip("/")), "coverage_degraded.json")):
        try:
            with open(deg_path, encoding="utf-8") as fh:
                dd = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(dd, list):
            for e in dd:
                if isinstance(e, dict):
                    _add("vikramaditya", e.get("tool") or e.get("phase", ""), e.get("reason", ""))
        break

    try:
        with open(cov, "w", encoding="utf-8") as fh:
            json.dump(merged, fh, indent=2)
    except OSError:
        pass
    return merged

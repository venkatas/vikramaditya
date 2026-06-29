"""atomic_red_team — index Atomic Red Team tests by MITRE technique and link them to Vikramaditya
findings via technique_kb.

WHY: a finding tells you a weakness exists; an Atomic Red Team (ART) test tells you exactly how to
*validate/exploit* the corresponding ATT&CK technique. Linking the two means a report (or the
brain) can surface "here is the atomic test that proves this" for a finding's technique.

PROVENANCE: this is a clean-room PARSER of the open ART YAML schema. The ART test corpus itself is
MIT-licensed and is NOT vendored here — point `art_path` at a local `redcanaryco/atomic-red-team`
checkout (the operator supplies it). No third-party code or data is bundled; no copyleft.
"""
import glob
import os


def _yaml():
    import yaml  # PyYAML; raised to the caller if absent
    return yaml


def load_atomics(art_path: str) -> dict:
    """Walk an ART checkout and return {technique_id: [atomic_test, ...]}.

    Accepts either the repo root (containing `atomics/`) or the `atomics/` dir directly. Each
    atomic_test is normalized to {name, description, platforms, executor, command}. Malformed
    YAML files are skipped, not fatal.
    """
    if not art_path or not os.path.isdir(art_path):
        return {}
    yaml = _yaml()
    base = os.path.join(art_path, "atomics")
    if not os.path.isdir(base):
        base = art_path
    index: dict = {}
    for path in glob.glob(os.path.join(base, "*", "T*.yaml")):
        try:
            with open(path, errors="replace") as fh:
                doc = yaml.safe_load(fh)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        tid = doc.get("attack_technique")
        tests = doc.get("atomic_tests") or []
        if not tid or not tests:
            continue
        for t in tests:
            if not isinstance(t, dict):
                continue
            ex = t.get("executor", {}) or {}
            index.setdefault(tid, []).append({
                "name": t.get("name", ""),
                "description": (t.get("description", "") or "").strip(),
                "platforms": t.get("supported_platforms", []) or [],
                "executor": ex.get("name", ""),
                "command": ex.get("command", ""),
            })
    return index


def tests_for_mitre_id(index: dict, mitre_id: str) -> list:
    """ART tests for a MITRE id, technique-tree aware:
      * exact match returns that technique's atomics;
      * a PARENT id (T1558) also aggregates every sub-technique's atomics (T1558.001, .003, …);
      * a SUB id with no direct atomics falls back to its parent.
    So a finding maps to relevant atomics whether ART or technique_kb used the parent or the sub.
    """
    if not mitre_id:
        return []
    out = list(index.get(mitre_id, []))
    if "." not in mitre_id:
        for tid, tests in index.items():
            if tid.startswith(mitre_id + "."):
                out.extend(tests)
    elif not out:
        out = list(index.get(mitre_id.split(".")[0], []))
    return out


def tests_for_vtype(index: dict, vtype: str) -> list:
    """ART tests for a Vikramaditya finding vtype, resolved through technique_kb's MITRE mapping."""
    try:
        import technique_kb
        t = technique_kb.get(vtype)
    except Exception:
        t = None
    return tests_for_mitre_id(index, t.mitre_id) if t else []


def summarize(index: dict) -> dict:
    """{technique_count, test_count} — for a one-line load confirmation."""
    return {"techniques": len(index), "tests": sum(len(v) for v in index.values())}

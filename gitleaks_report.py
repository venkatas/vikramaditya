#!/usr/bin/env python3
"""
gitleaks_report.py — opt-in Gitleaks → SARIF/JSON + finding_schema glue.

Gitleaks is already provisioned by setup.sh (Homebrew). This module wires
*reporting*: run (or ingest) Gitleaks JSON/SARIF, redact secrets, normalize into
Vikramaditya findings that pass finding_schema / finding_validator gates, and
write artefacts under findings/<label>/gitleaks/ (+ exposure/gitleaks.txt).

Not on the default scan path — invoke via CLI or --gitleaks.

Usage:
    python3 gitleaks_report.py --source /path/to/repo --findings-dir findings/acme
    python3 gitleaks_report.py --ingest-json leaks.json --findings-dir findings/acme
    python3 gitleaks_report.py --source . --mode dir --sarif-out out.sarif.json

Docs: docs/gitleaks-syft-bagit.md  ·  License (tool): MIT (gitleaks)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

WRAPPER_VERSION = "1.0.0"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

Runner = Callable[..., Any]

# Rule families that imply critical exposure when matched.
_CRITICAL_RULE_HINTS = (
    "private-key",
    "privatekey",
    "rsa",
    "ssh",
    "aws-access",
    "aws_secret",
    "gcp-service",
    "pkcs",
    "pgp",
)
_HIGH_RULE_HINTS = (
    "api",
    "token",
    "secret",
    "password",
    "credential",
    "bearer",
    "jwt",
    "oauth",
    "slack",
    "github",
    "gitlab",
    "stripe",
    "twilio",
)


def _which(name: str) -> str | None:
    return shutil.which(name)


def resolve_gitleaks(bin_env: str = "GITLEAKS_BIN") -> str | None:
    """Return path to gitleaks binary, or None."""
    override = (os.environ.get(bin_env) or "").strip()
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    return _which("gitleaks")


def install_hint() -> str:
    return (
        "gitleaks not found.\n"
        "  Homebrew: brew install gitleaks\n"
        "  Or: https://github.com/gitleaks/gitleaks/releases\n"
        "  Then: export GITLEAKS_BIN=/path/to/gitleaks"
    )


def redact_secret(value: str, keep: int = 4) -> str:
    """Redact a secret value; keep a short prefix for triage fingerprints."""
    if not value:
        return "<redacted>"
    if len(value) <= keep * 2:
        return "<redacted>"
    return f"{value[:keep]}…<redacted>"


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip() or default


def severity_for_leak(item: Mapping[str, Any]) -> str:
    """Map a Gitleaks finding to critical|high|medium using rule + tags."""
    rule = _as_str(item.get("RuleID") or item.get("rule_id") or item.get("Rule")).lower()
    desc = _as_str(item.get("Description") or item.get("description")).lower()
    tags = item.get("Tags") or item.get("tags") or []
    tag_blob = " ".join(str(t).lower() for t in tags) if isinstance(tags, (list, tuple)) else str(tags).lower()
    blob = f"{rule} {desc} {tag_blob}"
    for hint in _CRITICAL_RULE_HINTS:
        if hint in blob:
            return "critical"
    for hint in _HIGH_RULE_HINTS:
        if hint in blob:
            return "high"
    # Entropy / generic → medium (still reportable with verification)
    return "medium"


def gitleaks_item_to_finding(item: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one Gitleaks JSON object into a Vikramaditya finding dict.

    Uses finding_schema VerificationMethod.data_extracted (secret literally
    recovered from the artefact) so medium+ clears should_report().
    """
    try:
        from finding_schema import (  # type: ignore
            VerificationMethod,
            adjust_severity,
            classify_evidence,
            should_report,
        )
    except ImportError:  # pragma: no cover — tests may run without path
        VerificationMethod = None  # type: ignore
        adjust_severity = None  # type: ignore
        classify_evidence = None  # type: ignore
        should_report = None  # type: ignore

    rule_id = _as_str(item.get("RuleID") or item.get("rule_id") or item.get("Rule"), "gitleaks")
    description = _as_str(item.get("Description") or item.get("description"), "Secret detected")
    file_path = _as_str(item.get("File") or item.get("file") or item.get("Path"), "unknown")
    secret = _as_str(item.get("Secret") or item.get("secret"))
    match = _as_str(item.get("Match") or item.get("match"))
    start_line = item.get("StartLine") or item.get("start_line") or 0
    commit = _as_str(item.get("Commit") or item.get("commit"))
    fingerprint = _as_str(item.get("Fingerprint") or item.get("fingerprint"))
    if not fingerprint:
        fingerprint = f"{file_path}:{start_line}:{rule_id}"

    redacted_secret = redact_secret(secret) if secret else "<redacted>"
    # Keep classify_evidence keywords (api key / private key / credential) in
    # the evidence text WITHOUT the raw secret.
    evidence_bits = [
        f"gitleaks rule={rule_id}",
        f"file={file_path}:{start_line}",
        f"description={description}",
        f"secret={redacted_secret}",
    ]
    if "private" in rule_id.lower() or "private key" in description.lower():
        evidence_bits.append("private key material observed in repository")
    elif "api" in rule_id.lower() or "token" in rule_id.lower():
        evidence_bits.append("api key / access token exposure")
    else:
        evidence_bits.append("exposed secret / credential in source")
    if commit:
        evidence_bits.append(f"commit={commit[:12]}")
    evidence = "; ".join(evidence_bits)

    declared = severity_for_leak(item)
    method = "data_extracted"
    if adjust_severity is not None:
        declared = adjust_severity(declared, method)
    if classify_evidence is not None:
        classified = classify_evidence(evidence, "exposure")
        if classified:
            # Prefer the stronger of rule-map vs keyword classify.
            from finding_schema import SEVERITY_RANK  # type: ignore

            if SEVERITY_RANK.get(classified, 0) > SEVERITY_RANK.get(declared, 0):
                declared = classified

    finding: dict[str, Any] = {
        "title": f"Secret exposure: {rule_id}",
        "severity": declared,
        "vtype": "exposure",
        "type": "exposure",
        "url": file_path,
        "detail": description or f"Gitleaks rule {rule_id}",
        "evidence": evidence,
        "poc": match[:200] + ("…" if len(match) > 200 else "") if match else evidence,
        "source": "gitleaks",
        "rule_id": rule_id,
        "verification_method": method,
        "fingerprint": fingerprint,
        "file": file_path,
        "line": start_line,
        "confidence": "high",
        "raw": evidence,
    }
    if should_report is not None and not should_report(declared, method):
        finding["severity"] = "low"
        finding["_gated"] = True
    if VerificationMethod is not None:
        finding["verification_method"] = VerificationMethod.DATA_EXTRACTED.value
    return finding


def parse_gitleaks_json(data: Any) -> list[dict[str, Any]]:
    """Accept a list or {findings|results|leaks: [...]} wrapper."""
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("findings", "results", "leaks", "items"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
        else:
            items = []
    else:
        items = []
    return [gitleaks_item_to_finding(item) for item in items if isinstance(item, Mapping)]


def load_gitleaks_json(path: Path | str) -> list[dict[str, Any]]:
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_gitleaks_json(json.loads(raw))


def findings_to_sarif(
    findings: Sequence[Mapping[str, Any]],
    *,
    tool_name: str = "gitleaks",
    tool_version: str = "",
) -> dict[str, Any]:
    """Build a minimal SARIF 2.1.0 document from normalized findings."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    for f in findings:
        rule_id = _as_str(f.get("rule_id") or f.get("vtype"), "gitleaks")
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": _as_str(f.get("title") or rule_id)},
            }
        level = level_map.get(_as_str(f.get("severity"), "medium").lower(), "warning")
        uri = _as_str(f.get("file") or f.get("url"), "unknown")
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": _as_str(f.get("evidence") or f.get("detail") or f.get("title"))},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": int(f.get("line") or 1) or 1},
                    }
                }
            ],
        }
        fp = _as_str(f.get("fingerprint"))
        if fp:
            result["fingerprints"] = {"primaryLocationLineHash": fp[:64]}
        results.append(result)

    driver: dict[str, Any] = {
        "name": tool_name,
        "informationUri": "https://github.com/gitleaks/gitleaks",
        "rules": list(rules_by_id.values()),
    }
    if tool_version:
        driver["version"] = tool_version
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def write_findings_artifacts(
    findings: Sequence[Mapping[str, Any]],
    findings_dir: Path | str,
    *,
    native_json: Any | None = None,
    native_sarif: Any | None = None,
    tool_version: str = "",
) -> dict[str, Any]:
    """Write gitleaks/ + exposure/gitleaks.txt under findings_dir."""
    base = Path(findings_dir)
    gdir = base / "gitleaks"
    gdir.mkdir(parents=True, exist_ok=True)
    exp = base / "exposure"
    exp.mkdir(parents=True, exist_ok=True)

    findings_list = [dict(f) for f in findings]
    (gdir / "findings.json").write_text(
        json.dumps(findings_list, indent=2) + "\n", encoding="utf-8"
    )

    if native_json is not None:
        (gdir / "gitleaks.json").write_text(
            json.dumps(native_json, indent=2) + "\n", encoding="utf-8"
        )
    else:
        # Redacted export shaped like gitleaks JSON
        redacted = []
        for f in findings_list:
            redacted.append(
                {
                    "RuleID": f.get("rule_id"),
                    "Description": f.get("detail"),
                    "File": f.get("file"),
                    "StartLine": f.get("line"),
                    "Secret": "<redacted>",
                    "Fingerprint": f.get("fingerprint"),
                }
            )
        (gdir / "gitleaks.json").write_text(
            json.dumps(redacted, indent=2) + "\n", encoding="utf-8"
        )

    sarif_doc = native_sarif if native_sarif is not None else findings_to_sarif(
        findings_list, tool_version=tool_version
    )
    (gdir / "gitleaks.sarif.json").write_text(
        json.dumps(sarif_doc, indent=2) + "\n", encoding="utf-8"
    )

    lines = []
    for f in findings_list:
        sev = _as_str(f.get("severity"), "medium").upper()
        lines.append(
            f"[{sev}] {f.get('title')} | {f.get('file')}:{f.get('line')} | {f.get('evidence')}"
        )
    (exp / "gitleaks.txt").write_text(
        ("\n".join(lines) + "\n") if lines else "", encoding="utf-8"
    )

    summary = {
        "tool": "gitleaks",
        "wrapper_version": WRAPPER_VERSION,
        "count": len(findings_list),
        "by_severity": {},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    for f in findings_list:
        sev = _as_str(f.get("severity"), "medium").lower()
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
    (gdir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def run_gitleaks(
    source: Path | str,
    out_dir: Path | str,
    *,
    mode: str = "dir",
    redact: bool = True,
    gitleaks_bin: str | None = None,
    runner: Runner = subprocess.run,
    exit_code_on_leak: int = 0,
) -> dict[str, Any]:
    """Shell out to gitleaks; write JSON+SARIF under out_dir; return meta.

    exit_code_on_leak=0 so findings don't abort the glue (Gitleaks defaults to 1).
    """
    binary = gitleaks_bin or resolve_gitleaks()
    if not binary:
        raise FileNotFoundError(install_hint())

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "gitleaks.raw.json"
    sarif_path = out / "gitleaks.raw.sarif.json"
    source_path = str(Path(source).resolve())

    # Prefer modern `gitleaks dir|git`; fall back to legacy `detect`.
    subcmd = "git" if mode == "git" else "dir"
    base_cmd = [binary, subcmd, "--source", source_path, "--no-banner",
                "--exit-code", str(exit_code_on_leak)]
    if redact:
        base_cmd.append("--redact")

    def _run(fmt: str, path: Path) -> subprocess.CompletedProcess[str]:
        cmd = list(base_cmd) + ["--report-format", fmt, "--report-path", str(path)]
        try:
            return runner(cmd, capture_output=True, text=True, check=False)
        except TypeError:
            # Some fakes omit kwargs
            return runner(cmd)

    # Try modern subcommands first
    r_json = _run("json", json_path)
    if r_json.returncode not in (0, 1) and (
        "unknown command" in (r_json.stderr or "").lower()
        or "invalid" in (r_json.stderr or "").lower()
    ):
        # Legacy: gitleaks detect --source ...
        base_cmd = [binary, "detect", "--source", source_path, "--no-banner",
                    "--exit-code", str(exit_code_on_leak)]
        if redact:
            base_cmd.append("--redact")
        r_json = _run("json", json_path)

    r_sarif = _run("sarif", sarif_path)

    native_json: Any = []
    if json_path.is_file() and json_path.stat().st_size > 0:
        try:
            native_json = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            native_json = []

    native_sarif: Any | None = None
    if sarif_path.is_file() and sarif_path.stat().st_size > 0:
        try:
            native_sarif = json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            native_sarif = None

    findings = parse_gitleaks_json(native_json)
    return {
        "findings": findings,
        "native_json": native_json,
        "native_sarif": native_sarif,
        "json_path": str(json_path),
        "sarif_path": str(sarif_path),
        "returncode_json": getattr(r_json, "returncode", 0),
        "returncode_sarif": getattr(r_sarif, "returncode", 0),
        "stderr": (getattr(r_json, "stderr", "") or "")[-2000:],
    }


def validate_with_gate(findings: Sequence[Mapping[str, Any]]) -> dict[str, list]:
    """Run finding_validator.validate_finding on each normalized finding."""
    try:
        from finding_validator import validate_finding  # type: ignore
    except ImportError:
        return {"pass": list(findings), "kill": [], "downgrade": [], "chain_required": []}

    buckets: dict[str, list] = {"pass": [], "kill": [], "downgrade": [], "chain_required": []}
    for f in findings:
        result = validate_finding(dict(f))
        result["finding"] = dict(f)
        buckets[result["decision"]].append(result)
    return buckets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Opt-in Gitleaks SARIF/JSON reporting into Vikramaditya findings"
    )
    p.add_argument("--source", default="", help="Repo or directory to scan")
    p.add_argument("--ingest-json", default="", help="Ingest existing Gitleaks JSON (skip run)")
    p.add_argument("--findings-dir", required=True, help="findings/<label> directory")
    p.add_argument("--mode", choices=("dir", "git"), default="dir",
                   help="gitleaks dir (default) or git history scan")
    p.add_argument("--sarif-out", default="", help="Optional extra SARIF copy path")
    p.add_argument("--no-redact", action="store_true", help="Do not pass --redact to gitleaks")
    p.add_argument("--json", action="store_true", help="Print summary JSON to stdout")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    findings_dir = Path(args.findings_dir)
    findings_dir.mkdir(parents=True, exist_ok=True)

    native_json: Any = None
    native_sarif: Any = None
    findings: list[dict[str, Any]]

    if args.ingest_json:
        findings = load_gitleaks_json(args.ingest_json)
        try:
            native_json = json.loads(
                Path(args.ingest_json).read_text(encoding="utf-8", errors="replace")
            )
        except (OSError, json.JSONDecodeError):
            native_json = None
    else:
        if not args.source:
            print("[-] Provide --source or --ingest-json", file=sys.stderr)
            return 2
        if not resolve_gitleaks():
            print(install_hint(), file=sys.stderr)
            return 1
        meta = run_gitleaks(
            args.source,
            findings_dir / "gitleaks" / ".raw",
            mode=args.mode,
            redact=not args.no_redact,
        )
        findings = meta["findings"]
        native_json = meta["native_json"]
        native_sarif = meta["native_sarif"]

    summary = write_findings_artifacts(
        findings, findings_dir, native_json=native_json, native_sarif=native_sarif
    )
    gate = validate_with_gate(findings)
    summary["validator"] = {k: len(v) for k, v in gate.items()}
    (findings_dir / "gitleaks" / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if args.sarif_out:
        sarif_src = findings_dir / "gitleaks" / "gitleaks.sarif.json"
        Path(args.sarif_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.sarif_out).write_text(sarif_src.read_text(encoding="utf-8"), encoding="utf-8")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(
            f"[+] gitleaks: {summary['count']} finding(s) → "
            f"{findings_dir / 'gitleaks'} (validator: {summary['validator']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

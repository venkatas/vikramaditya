#!/usr/bin/env python3
"""Opt-in findings JSON to SARIF 2.1.0 exporter (+ optional MITRE CLI).

Native writer always works. Optional shell-out to MITRE convert helpers
when installed (never a hard dependency).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "vikramaditya"
TOOL_INFO_URI = "https://github.com/venkatas/obsidian"

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
    "information": "note",
    "none": "none",
}

_LEVEL_RANK = {"error": 0, "warning": 1, "note": 2, "none": 3}

Runner = Callable[..., Any]


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip() or default


def normalize_severity(raw: Any) -> str:
    label = _as_str(raw, "info").lower()
    if label == "information":
        return "informational"
    if label in _SEVERITY_TO_LEVEL:
        return label
    return "info"


def severity_to_level(severity: Any) -> str:
    return _SEVERITY_TO_LEVEL.get(normalize_severity(severity), "note")


def _rule_id(finding: Mapping[str, Any]) -> str:
    for key in ("rule_id", "ruleId", "vtype", "type", "vuln_class", "vuln_type"):
        val = _as_str(finding.get(key))
        if val:
            cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in val)
            return cleaned[:128] or "finding"
    return "finding"


def _finding_title(finding: Mapping[str, Any]) -> str:
    for key in ("title", "name", "summary"):
        val = _as_str(finding.get(key))
        if val:
            return val
    return _rule_id(finding)


def _finding_message(finding: Mapping[str, Any]) -> str:
    parts: list[str] = []
    title = _finding_title(finding)
    if title:
        parts.append(title)
    for key in ("detail", "description", "notes", "evidence", "poc"):
        val = _as_str(finding.get(key))
        if val and val not in parts:
            parts.append(val)
    text = "\n\n".join(parts).strip()
    return text or title or "Finding"


def _finding_uri(finding: Mapping[str, Any]) -> Optional[str]:
    for key in ("uri", "url", "endpoint", "target", "host"):
        val = _as_str(finding.get(key))
        if not val or val.upper() == "N/A":
            continue
        if "://" in val:
            return val
        if val.startswith("/") or "." in val or ":" in val:
            return val
    return None


def _result_fingerprint(finding: Mapping[str, Any]) -> str:
    raw = "|".join([
        _rule_id(finding),
        _finding_title(finding),
        _as_str(finding.get("url") or finding.get("endpoint") or finding.get("target")),
        _as_str(finding.get("detail") or finding.get("notes")),
    ])
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def load_findings(source: Any) -> list[dict[str, Any]]:
    """Load findings from a path, list, or dict."""
    if isinstance(source, (str, Path)):
        data = json.loads(Path(source).read_text(encoding="utf-8"))
    else:
        data = source
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("findings", "results", "issues", "items"):
            inner = data.get(key)
            if isinstance(inner, list):
                return [x for x in inner if isinstance(x, dict)]
        if any(k in data for k in ("title", "severity", "vtype", "type", "vuln_class", "url")):
            return [data]
    return []


def findings_to_sarif(
    findings: Sequence[Mapping[str, Any]],
    *,
    tool_name: str = TOOL_NAME,
    tool_version: str = "0.0.0",
    information_uri: str = TOOL_INFO_URI,
) -> dict[str, Any]:
    """Convert a list of finding dicts into a SARIF 2.1.0 document."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        rid = _rule_id(finding)
        level = severity_to_level(finding.get("severity"))
        title = _finding_title(finding)
        message = _finding_message(finding)

        existing = rules_by_id.get(rid)
        if existing is None:
            rules_by_id[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": title[:256]},
                "fullDescription": {"text": message[:4096]},
                "defaultConfiguration": {"level": level},
            }
        else:
            prev = existing.get("defaultConfiguration", {}).get("level", "note")
            if _LEVEL_RANK.get(level, 9) < _LEVEL_RANK.get(prev, 9):
                existing["defaultConfiguration"] = {"level": level}

        result: dict[str, Any] = {
            "ruleId": rid,
            "level": level,
            "message": {"text": message[:16384]},
            "fingerprints": {"vikramaditya/v1": _result_fingerprint(finding)},
        }

        uri = _finding_uri(finding)
        if uri:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": uri}}}
            ]

        props: dict[str, Any] = {}
        for key in (
            "severity",
            "confidence",
            "verification_method",
            "cvss",
            "cwe",
            "source",
            "poc",
            "evidence",
            "tags",
        ):
            if key in finding and finding[key] not in (None, "", [], {}):
                props[key] = finding[key]
        if props:
            result["properties"] = props

        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": information_uri,
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": results,
        }],
    }


def write_sarif(findings: Any, out_path: str | Path, **kwargs: Any) -> Path:
    """Write SARIF for findings (list or loadable source) to out_path."""
    if isinstance(findings, (str, Path)):
        items = load_findings(findings)
    elif isinstance(findings, dict) and "findings" in findings:
        items = load_findings(findings)
    elif isinstance(findings, Sequence) and not isinstance(findings, (str, bytes)):
        items = [f for f in findings if isinstance(f, Mapping)]
    else:
        items = load_findings(findings)

    doc = findings_to_sarif(items, **kwargs)
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


def resolve_saf_bin(
    explicit: str | Path | None = None,
    *,
    which: Callable[[str], Optional[str]] | None = None,
) -> Optional[str]:
    """Resolve optional MITRE CLI binary."""
    if explicit is not None:
        candidate = Path(explicit).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        nested = candidate / 'saf'
        if nested.is_file():
            return str(nested.resolve())
        # Trust an explicit path for injectable runners / offline CI mocks.
        return str(candidate)
    finder = which or shutil.which
    return finder('saf')


def convert_sarif_with_saf(
    sarif_path: str | Path,
    *,
    hdf_path: str | Path | None = None,
    asff_path: str | Path | None = None,
    saf_bin: str | Path | None = None,
    runner: Runner | None = None,
    aws_account: str = "000000000000",
    aws_region: str = "us-east-1",
    asff_target: str = "vikramaditya",
    which: Callable[[str], Optional[str]] | None = None,
) -> dict[str, Path]:
    """Convert SARIF via optional MITRE CLI; runner injectable for tests."""
    sarif = Path(sarif_path)
    if not sarif.is_file():
        raise FileNotFoundError(f"SARIF input not found: {sarif}")
    bin_path = resolve_saf_bin(saf_bin, which=which)
    if not bin_path:
        raise FileNotFoundError(
            'MITRE SAF CLI not found. Install optionally with: npm i -g @mitre/saf'
        )
    run = runner or subprocess.run
    outputs: dict[str, Path] = {}
    if hdf_path is None and asff_path is not None:
        hdf_path = Path(asff_path).with_suffix(".hdf.json")
    if hdf_path is None:
        raise ValueError("convert_sarif_with_saf requires hdf_path and/or asff_path")
    hdf = Path(hdf_path)
    hdf.parent.mkdir(parents=True, exist_ok=True)
    cmd_hdf = [bin_path, "convert", 'sarif2hdf', "-i", str(sarif), "-o", str(hdf)]
    result = run(cmd_hdf, check=False, capture_output=True, text=True)
    if getattr(result, "returncode", 1) != 0:
        stderr = getattr(result, "stderr", "") or getattr(result, "stdout", "") or ""
        raise RuntimeError(f"saf convert sarif2hdf failed: {stderr.strip()}")
    outputs["hdf"] = hdf
    if asff_path is not None:
        asff = Path(asff_path)
        asff.mkdir(parents=True, exist_ok=True)
        cmd_asff = [
            bin_path,
            "convert",
            'hdf2asff',
            "-i",
            str(hdf),
            "-o",
            str(asff),
            "-a",
            aws_account,
            "-r",
            aws_region,
            "-t",
            asff_target,
        ]
        result = run(cmd_asff, check=False, capture_output=True, text=True)
        if getattr(result, "returncode", 1) != 0:
            stderr = getattr(result, "stderr", "") or getattr(result, "stdout", "") or ""
            raise RuntimeError(f"saf convert hdf2asff failed: {stderr.strip()}")
        outputs["asff"] = asff
    return outputs



def _load_findings_from_dir(path: str | Path) -> tuple[list[dict[str, Any]], str]:
    """Load finding dicts from a session/findings directory."""
    root = Path(path)
    if not root.is_dir():
        raise FileNotFoundError(f"findings dir not found: {root}")
    candidates: list[Path] = []
    for name in ("findings.json", "validated_findings.json", "all_findings.json"):
        p = root / name
        if p.is_file():
            candidates.append(p)
    if not candidates:
        candidates = sorted(root.rglob("*.json"))
    findings: list[dict[str, Any]] = []
    for p in candidates:
        try:
            findings.extend(load_findings(p))
        except Exception:
            continue
    target = root.name
    for parent in root.parents:
        if parent.name and parent.name not in ("sessions", "findings", "export"):
            # prefer hostname-like parent under findings/
            if parent.parent.name == "findings":
                target = parent.name
                break
    return findings, target

def export_findings(
    findings: Any,
    export_dir: str | Path,
    *,
    target: str = "",
    want_sarif: bool = True,
    want_hdf: bool = False,
    want_asff: bool = False,
    sarif_path: str | Path | None = None,
    hdf_path: str | Path | None = None,
    asff_dir: str | Path | None = None,
    asff_account: str = "",
    asff_region: str = "",
    asff_target: str = "",
    asff_upload: bool = False,
    saf_bin: str | Path | None = None,
    runner: Runner | None = None,
    tool_version: str = "0.0.0",
) -> dict[str, Path]:
    """High-level export used by reporter/vikramaditya (opt-in)."""
    del asff_upload  # upload requires live AWS; local ASFF files only here
    if isinstance(findings, (str, Path)):
        items = load_findings(findings)
    elif isinstance(findings, dict):
        items = load_findings(findings)
    else:
        items = [f for f in findings if isinstance(f, dict)]
    out_dir = Path(export_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    produced: dict[str, Path] = {}
    if not want_sarif and not want_hdf and not want_asff:
        want_sarif = True
    sarif_out = Path(sarif_path) if sarif_path else (out_dir / "findings.sarif.json")
    if want_sarif or want_hdf or want_asff:
        write_sarif(items, sarif_out, tool_version=tool_version)
        produced["sarif"] = sarif_out
    if want_hdf or want_asff:
        hdf_out = Path(hdf_path) if hdf_path else (out_dir / "findings.hdf.json")
        asff_out = Path(asff_dir) if asff_dir else (out_dir / "asff")
        conv = convert_sarif_with_saf(
            sarif_out,
            hdf_path=hdf_out if (want_hdf or want_asff) else None,
            asff_path=asff_out if want_asff else None,
            saf_bin=saf_bin,
            runner=runner,
            aws_account=asff_account or "000000000000",
            aws_region=asff_region or "us-east-1",
            asff_target=asff_target or target or "vikramaditya",
        )
        produced.update(conv)
    return produced


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Export Vikramaditya findings JSON to SARIF 2.1.0 "
            "(optional MITRE SAF HDF/ASFF conversion)."
        )
    )
    p.add_argument("findings", help="Path to findings JSON or a findings session directory")
    p.add_argument("-o", "--output", required=True, help="Output SARIF path")
    p.add_argument("--hdf", help="Also write Heimdall HDF JSON via saf convert sarif2hdf")
    p.add_argument("--asff", help="Also write ASFF folder via saf convert hdf2asff")
    p.add_argument("--saf-bin", dest="saf_bin", help="Path to MITRE saf CLI (optional; otherwise PATH)")
    p.add_argument("--tool-version", default="0.0.0", help="Tool version stamped into SARIF")
    p.add_argument("--aws-account", default="000000000000", help="AWS account id for ASFF")
    p.add_argument("--aws-region", default="us-east-1", help="AWS region for ASFF")
    p.add_argument("--asff-target", default="vikramaditya", help="Target name for ASFF convert")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    findings_path = Path(args.findings)
    if findings_path.is_dir():
        items, _target = _load_findings_from_dir(findings_path)
        out = write_sarif(items, args.output, tool_version=args.tool_version)
    elif findings_path.is_file():
        out = write_sarif(findings_path, args.output, tool_version=args.tool_version)
    else:
        print(f"[-] findings not found: {findings_path}", file=sys.stderr)
        return 1
    print(f"[+] wrote SARIF {out}")
    if args.hdf or args.asff:
        try:
            produced = convert_sarif_with_saf(
                out,
                hdf_path=args.hdf,
                asff_path=args.asff,
                saf_bin=args.saf_bin,
                aws_account=args.aws_account,
                aws_region=args.aws_region,
                asff_target=args.asff_target,
            )
        except FileNotFoundError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 2
        except RuntimeError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 3
        if "hdf" in produced:
            print(f"[+] wrote HDF {produced['hdf']}")
        if "asff" in produced:
            print(f"[+] wrote ASFF {produced['asff']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

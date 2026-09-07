#!/usr/bin/env python3
from __future__ import annotations
"""
Mandatory tool parsers — normalize nuclei / sqlmap / ffuf / nmap output into
structured finding dicts. Pure stdlib.

Inspired by PentestCode tool-parser discipline (MIT) — clean-room Python.
Scanner hits alone stay status=suspected unless the tool clearly confirms.
"""

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from typing import Any


def _read_text(text_or_path: str) -> str:
    if text_or_path is None:
        return ""
    s = text_or_path
    # Heuristic: path if it exists as a file and looks like a path
    if ("\n" not in s) and (len(s) < 4096) and os.path.isfile(s):
        with open(s, encoding="utf-8", errors="replace") as f:
            return f.read()
    return s


def _norm_sev(s: str | None) -> str:
    if not s:
        return "info"
    s = str(s).lower().strip()
    if s in ("critical", "high", "medium", "low", "info", "unknown"):
        return "info" if s == "unknown" else s
    return "info"


# ── nuclei ────────────────────────────────────────────────────────────────────

def parse_nuclei_json(text_or_path: str) -> list[dict]:
    """Parse nuclei JSONL or JSON array/object → list of finding dicts."""
    text = _read_text(text_or_path).strip()
    if not text:
        return []
    objs: list[dict] = []
    # Try JSON array / single object first
    if text[0] in "[{":
        try:
            data = json.loads(text)
            if isinstance(data, list):
                objs = [x for x in data if isinstance(x, dict)]
            elif isinstance(data, dict):
                objs = [data]
        except json.JSONDecodeError:
            objs = []
    if not objs:
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(o, dict):
                objs.append(o)

    findings = []
    for o in objs:
        info = o.get("info") if isinstance(o.get("info"), dict) else {}
        title = info.get("name") or o.get("template-id") or o.get("template_id") or "nuclei-hit"
        sev = _norm_sev(info.get("severity") or o.get("severity"))
        host = o.get("host") or o.get("ip") or ""
        url = o.get("matched-at") or o.get("matched_at") or o.get("url") or host
        tid = o.get("template-id") or o.get("template_id") or o.get("templateID") or ""
        matched = o.get("matched-at") or o.get("matched_at") or o.get("matcher-name") or ""
        evidence = ""
        extr = o.get("extracted-results") or o.get("extracted_results") or []
        if isinstance(extr, list) and extr:
            evidence = "; ".join(str(x) for x in extr[:5])
        elif o.get("curl-command"):
            evidence = str(o.get("curl-command"))[:500]
        findings.append({
            "tool": "nuclei",
            "title": str(title),
            "severity": sev,
            "host": str(host),
            "url": str(url),
            "template_id": str(tid),
            "matched": str(matched),
            "evidence": evidence,
            "status": "suspected",
        })
    return findings


# ── sqlmap ────────────────────────────────────────────────────────────────────

_SQLMAP_INJECTABLE_RE = re.compile(
    r"parameter\s+['\"]?(\w+)['\"]?\s+is\s+vulnerable|"
    r"['\"]?(\w+)['\"]?\s+parameter\s+.*\binjectable\b|"
    r"\binjectable\b.*parameter\s+['\"]?(\w+)['\"]?|"
    r"identified\s+the\s+following\s+injection\s+point",
    re.I,
)
_SQLMAP_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.I)
_SQLMAP_TECH_RE = re.compile(
    r"type:\s*(.+?)(?:\n|$)|technique:\s*['\"]?([A-Z]\b|\w[\w\s-]+)",
    re.I,
)
_SQLMAP_PARAM_RE = re.compile(
    r"Place:\s*\w+\s+Parameter:\s*(\w+)|"
    r"Parameter:\s*(\w+)\s+\(",
    re.I,
)


def parse_sqlmap_output(text: str) -> list[dict]:
    """Extract injectable params / DBMS / technique from sqlmap text output.

    status=confirmed only when sqlmap clearly says injectable/vulnerable.
    """
    text = text or ""
    if not text.strip():
        return []

    confirmed = bool(
        re.search(r"\bis vulnerable\b|\binjectable\b", text, re.I)
        and not re.search(r"does not seem to be injectable|all tested parameters "
                          r"do not appear to be injectable|not injectable", text, re.I)
    )
    # If sqlmap only printed "not injectable", return empty or suspected-negative skip
    if re.search(r"all tested parameters do not appear to be injectable|"
                 r"does not seem to be injectable", text, re.I) and not confirmed:
        return []

    dbms_m = _SQLMAP_DBMS_RE.search(text)
    dbms = dbms_m.group(1).strip() if dbms_m else ""

    params: list[str] = []
    for m in _SQLMAP_INJECTABLE_RE.finditer(text):
        for g in m.groups():
            if g:
                params.append(g)
    for m in _SQLMAP_PARAM_RE.finditer(text):
        for g in m.groups():
            if g and g not in params:
                params.append(g)
    # Dedupe preserve order
    seen = set()
    uniq = []
    for p in params:
        pl = p.lower()
        if pl not in seen:
            seen.add(pl)
            uniq.append(p)

    techs = []
    for m in re.finditer(r"Type:\s*(.+)", text, re.I):
        techs.append(m.group(1).strip())
    technique = "; ".join(techs[:5]) if techs else ""

    if not uniq and not confirmed and not dbms:
        return []

    findings = []
    if uniq:
        for p in uniq:
            findings.append({
                "tool": "sqlmap",
                "title": f"SQL injection on parameter '{p}'",
                "severity": "critical" if confirmed else "info",
                "host": "",
                "url": "",
                "param": p,
                "dbms": dbms,
                "technique": technique,
                "evidence": f"dbms={dbms}; technique={technique}" if (dbms or technique) else "",
                "status": "confirmed" if confirmed else "suspected",
            })
    elif confirmed or dbms:
        findings.append({
            "tool": "sqlmap",
            "title": "SQL injection indicated by sqlmap",
            "severity": "critical" if confirmed else "info",
            "host": "",
            "url": "",
            "param": "",
            "dbms": dbms,
            "technique": technique,
            "evidence": f"dbms={dbms}; technique={technique}" if (dbms or technique) else "",
            "status": "confirmed" if confirmed else "suspected",
        })
    return findings


# ── ffuf ──────────────────────────────────────────────────────────────────────

def parse_ffuf_json(text_or_path: str) -> list[dict]:
    """Parse ffuf ``-of json`` results → interesting paths."""
    text = _read_text(text_or_path).strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    results = []
    if isinstance(data, dict):
        results = data.get("results") or data.get("Results") or []
    elif isinstance(data, list):
        results = data
    if not isinstance(results, list):
        return []

    findings = []
    for r in results:
        if not isinstance(r, dict):
            continue
        url = r.get("url") or r.get("URL") or ""
        status = r.get("status") or r.get("status-code") or r.get("status_code") or 0
        length = r.get("length") or r.get("words") or r.get("lines") or 0
        try:
            status_i = int(status)
        except (TypeError, ValueError):
            status_i = 0
        # Interesting: non-404 generally; keep all but mark
        findings.append({
            "tool": "ffuf",
            "title": f"ffuf hit {status_i} len={length}",
            "severity": "info",
            "host": "",
            "url": str(url),
            "status_code": status_i,
            "length": length,
            "evidence": json.dumps({k: r.get(k) for k in ("input", "host", "content-type") if k in r})[:300],
            "status": "suspected",
        })
    return findings


# ── nmap ──────────────────────────────────────────────────────────────────────

def parse_nmap_xml(text_or_path: str) -> list[dict]:
    """Parse nmap XML → hosts/ports/services (xml.etree)."""
    text = _read_text(text_or_path).strip()
    if not text:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    findings = []
    for host in root.findall("host"):
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6", None):
                addr = a.get("addr") or addr
        hostnames = []
        hn = host.find("hostnames")
        if hn is not None:
            for h in hn.findall("hostname"):
                if h.get("name"):
                    hostnames.append(h.get("name"))
        host_label = hostnames[0] if hostnames else addr
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state_el = port.find("state")
            state = (state_el.get("state") if state_el is not None else "") or ""
            if state and state != "open":
                continue
            portid = port.get("portid") or ""
            proto = port.get("protocol") or "tcp"
            svc_el = port.find("service")
            svc = ""
            product = ""
            version = ""
            if svc_el is not None:
                svc = svc_el.get("name") or ""
                product = svc_el.get("product") or ""
                version = svc_el.get("version") or ""
            title = f"open {proto}/{portid} {svc} {product} {version}".strip()
            findings.append({
                "tool": "nmap",
                "title": title,
                "severity": "info",
                "host": host_label or addr,
                "url": "",
                "port": portid,
                "protocol": proto,
                "service": svc,
                "product": product,
                "version": version,
                "evidence": f"{addr} {proto}/{portid} {svc} {product} {version}".strip(),
                "status": "suspected",
            })
    return findings


# ── write helpers ─────────────────────────────────────────────────────────────

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _subdir_for(finding: dict) -> str | None:
    tool = (finding.get("tool") or "").lower()
    sev = _norm_sev(finding.get("severity"))
    status = (finding.get("status") or "").lower()
    if tool == "sqlmap" and status == "confirmed":
        return "sqli"
    if tool == "nuclei":
        # Conservative: info/low stay out of severity subdirs (or misconfig only if medium+)
        if _SEV_RANK.get(sev, 4) <= 1:  # critical/high
            tid = (finding.get("template_id") or "").lower()
            title = (finding.get("title") or "").lower()
            if "cve-" in tid or "cve-" in title or "cve" in tid:
                return "cves"
            return "misconfig"
        if sev == "medium":
            return "misconfig"
        return None  # info/low → parsed json only
    if tool == "ffuf":
        return None  # discovery noise — parsed json only
    if tool == "nmap":
        return None
    return None


def write_parsed_findings(session_or_findings_dir: str, findings: list[dict]) -> dict:
    """Write under parsed/<tool>.json and append human lines when severity warrants."""
    base = session_or_findings_dir
    parsed_dir = os.path.join(base, "parsed")
    os.makedirs(parsed_dir, exist_ok=True)

    by_tool: dict[str, list] = {}
    for f in findings or []:
        tool = (f.get("tool") or "unknown").lower()
        by_tool.setdefault(tool, []).append(f)

    written = {"parsed": {}, "appended": []}
    for tool, items in by_tool.items():
        out_path = os.path.join(parsed_dir, f"{tool}.json")
        existing: list = []
        if os.path.isfile(out_path):
            try:
                with open(out_path, encoding="utf-8") as fh:
                    existing = json.load(fh)
                if not isinstance(existing, list):
                    existing = []
            except (OSError, json.JSONDecodeError):
                existing = []
        existing.extend(items)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(existing, fh, indent=2)
            fh.write("\n")
        written["parsed"][tool] = out_path

        for item in items:
            sub = _subdir_for(item)
            if not sub:
                continue
            subdir = os.path.join(base, sub)
            os.makedirs(subdir, exist_ok=True)
            line = (
                f"[{(item.get('severity') or 'info').upper()}] "
                f"{item.get('title') or tool} "
                f"{item.get('url') or item.get('host') or ''} "
                f"status={item.get('status')} "
                f"evidence={str(item.get('evidence') or '')[:200]}"
            ).strip()
            fn = os.path.join(subdir, f"{tool}_parsed.txt")
            with open(fn, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            written["appended"].append(fn)
    return written


def summarize_for_feedback(findings: list[dict], limit: int = 12) -> str:
    """Short structured summary for brain_scanner feedback (no invented vulns)."""
    if not findings:
        return ""
    lines = [f"PARSED TOOL OUTPUT ({len(findings)} item(s) — leads, not proof unless status=confirmed):"]
    for f in findings[:limit]:
        lines.append(
            f"- [{f.get('status')}/{f.get('severity')}] {f.get('tool')}: "
            f"{f.get('title')} {f.get('url') or f.get('host') or ''}".strip()
        )
    if len(findings) > limit:
        lines.append(f"  ... +{len(findings) - limit} more")
    return "\n".join(lines)


def auto_parse_stdout(stdout: str) -> list[dict]:
    """Best-effort detect tool output shape and parse. Never invents vulns."""
    s = (stdout or "").strip()
    if not s:
        return []
    out: list[dict] = []
    # nuclei JSONL: lines starting with { containing template-id / "info"
    if re.search(r'"template-id"\s*:|"template_id"\s*:', s) or (
        s.startswith("{") and '"matched-at"' in s
    ):
        out.extend(parse_nuclei_json(s))
    # ffuf json
    if '"results"' in s and ("ffuf" in s.lower() or '"status"' in s) and s.lstrip().startswith("{"):
        try:
            data = json.loads(s)
            if isinstance(data, dict) and "results" in data:
                out.extend(parse_ffuf_json(s))
        except json.JSONDecodeError:
            pass
    # sqlmap text cues
    if re.search(r"sqlmap|injectable|back-end DBMS", s, re.I):
        out.extend(parse_sqlmap_output(s))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Parse scanner tool outputs into structured findings")
    p.add_argument("--nuclei", default="", help="Nuclei JSON/JSONL file")
    p.add_argument("--sqlmap", default="", help="sqlmap text output file")
    p.add_argument("--ffuf", default="", help="ffuf -of json file")
    p.add_argument("--nmap", default="", help="nmap XML file")
    p.add_argument("--out", required=True, help="Session/findings directory to write into")
    args = p.parse_args(argv)

    findings: list[dict] = []
    if args.nuclei:
        findings.extend(parse_nuclei_json(args.nuclei))
    if args.sqlmap:
        findings.extend(parse_sqlmap_output(_read_text(args.sqlmap)))
    if args.ffuf:
        findings.extend(parse_ffuf_json(args.ffuf))
    if args.nmap:
        findings.extend(parse_nmap_xml(args.nmap))

    written = write_parsed_findings(args.out, findings)
    print(json.dumps({"count": len(findings), "written": written}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

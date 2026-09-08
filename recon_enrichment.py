#!/usr/bin/env python3
"""Recon enrichment glue — uncover / tlsx / waymore / xnLinkFinder summaries.

Alterx-style discipline: keep full artefacts under recon session dirs, but emit
compact summary JSON (count + sample) so reports never ingest huge noisy dumps.
Pure stdlib. Invoked by recon.sh; also importable for tests.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_HOST_RE = re.compile(
    r"(?i)^(?:\*+\.)?"
    r"([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$"
)
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$")
_IP_PORT_HOST = re.compile(
    r"(?i)(?:^|\s)((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?(?:\s|$)"
)


def _read_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def sample_lines(lines: list[str], n: int = 20) -> list[str]:
    if n <= 0:
        return []
    return lines[:n]


def summarize_lines(
    lines: list[str],
    *,
    sample_n: int = 20,
    tool: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compact summary suitable for reports (counts + samples only)."""
    uniq: list[str] = []
    seen: set[str] = set()
    for ln in lines:
        if ln not in seen:
            seen.add(ln)
            uniq.append(ln)
    out: dict[str, Any] = {
        "tool": tool,
        "count": len(uniq),
        "sample": sample_lines(uniq, sample_n),
    }
    if extra:
        out.update(extra)
    return out


def write_summary_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalize_host_token(raw: str) -> str | None:
    """Extract a hostname or host:port from uncover/tlsx-ish lines."""
    value = raw.strip().strip("[]").lower()
    if not value or value.startswith("#"):
        return None
    if "://" in value:
        host = urlsplit(value).hostname
        if not host:
            return None
        port = urlsplit(value).port
        host = host.rstrip(".").lower()
        return f"{host}:{port}" if port else host
    # strip trailing path junk
    value = value.split("/")[0].split("?")[0].split("#")[0]
    if _IP_RE.match(value):
        return value
    # host:port
    if value.count(":") == 1:
        left, right = value.rsplit(":", 1)
        if right.isdigit():
            left = left.rstrip(".")
            if _IP_RE.match(left) or _HOST_RE.match(left):
                return f"{left}:{right}"
    m = _HOST_RE.match(value.rstrip("."))
    if m:
        return m.group(1).lower()
    # uncover sometimes emits "ip [host] [engine]"
    m2 = _IP_PORT_HOST.search(raw)
    if m2:
        ip, port = m2.group(1), m2.group(2)
        return f"{ip}:{port}" if port else ip
    return None


def parse_uncover_hosts(text_or_lines: str | list[str]) -> list[str]:
    if isinstance(text_or_lines, str):
        lines = [ln.strip() for ln in text_or_lines.splitlines() if ln.strip()]
    else:
        lines = [ln.strip() for ln in text_or_lines if ln and ln.strip()]
    out: list[str] = []
    seen: set[str] = set()
    for ln in lines:
        # JSONL from uncover -json
        if ln.startswith("{"):
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                candidates = [
                    obj.get("ip"),
                    obj.get("host"),
                    obj.get("url"),
                ]
                port = obj.get("port")
                for c in candidates:
                    if not c:
                        continue
                    token = normalize_host_token(str(c))
                    if not token:
                        continue
                    if port and ":" not in token and str(port).isdigit():
                        token = f"{token}:{port}"
                    if token not in seen:
                        seen.add(token)
                        out.append(token)
                continue
        token = normalize_host_token(ln)
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    return out


def parse_xnlinkfinder_endpoints(text_or_lines: str | list[str]) -> list[str]:
    if isinstance(text_or_lines, str):
        lines = [ln.strip() for ln in text_or_lines.splitlines() if ln.strip()]
    else:
        lines = [ln.strip() for ln in text_or_lines if ln and ln.strip()]
    out: list[str] = []
    seen: set[str] = set()
    for ln in lines:
        if ln.startswith("#") or ln.lower().startswith("links found"):
            continue
        # strip common prefixes from verbose modes
        cleaned = re.sub(r"^\[[^\]]+\]\s*", "", ln).strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out


def in_scope_hosts(hosts: list[str], target: str) -> list[str]:
    """Keep hosts that are the target apex or a subdomain of it."""
    apex = target.strip().lower().rstrip(".")
    if not apex:
        return []
    kept: list[str] = []
    for h in hosts:
        host = h.split(":")[0].lower().rstrip(".")
        if host == apex or host.endswith("." + apex):
            kept.append(h if ":" in h else host)
    return kept


def tlsx_scope_delta(sans: list[str], known_subs: list[str], target: str) -> dict[str, list[str]]:
    """Split SANs into in-scope-new vs out-of-scope candidates."""
    known = {s.strip().lower().rstrip(".") for s in known_subs if s.strip()}
    known.add(target.strip().lower().rstrip("."))
    domainish = []
    for s in sans:
        tok = normalize_host_token(s)
        if not tok or _IP_RE.match(tok.split(":")[0]):
            continue
        domainish.append(tok.split(":")[0])
    uniq = []
    seen: set[str] = set()
    for d in domainish:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    in_scope_new = [d for d in uniq if d not in known and (d == target or d.endswith("." + target.strip().lower().rstrip(".")))]
    out_of_scope = [d for d in uniq if d not in known and d not in in_scope_new]
    return {"in_scope_new": in_scope_new, "out_of_scope": out_of_scope, "all_new": [d for d in uniq if d not in known]}


def cap_lines_for_merge(lines: list[str], cap: int) -> tuple[list[str], bool]:
    """Return (lines_for_merge, was_capped). cap<=0 means unlimited."""
    if cap <= 0 or len(lines) <= cap:
        return lines, False
    return lines[:cap], True


def cmd_summarize(args: argparse.Namespace) -> int:
    path = Path(args.path)
    lines = _read_lines(path)
    payload = summarize_lines(lines, sample_n=args.sample, tool=args.tool or path.stem)
    if args.out:
        write_summary_json(Path(args.out), payload)
    else:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


def cmd_cap_merge(args: argparse.Namespace) -> int:
    src = Path(args.src)
    lines = _read_lines(src)
    capped, was = cap_lines_for_merge(lines, args.cap)
    if args.full_out and was:
        Path(args.full_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.full_out).write_text("".join(f"{x}\n" for x in lines), encoding="utf-8")
    merge_path = Path(args.merge_out)
    merge_path.parent.mkdir(parents=True, exist_ok=True)
    merge_path.write_text("".join(f"{x}\n" for x in capped), encoding="utf-8")
    summary = summarize_lines(
        lines,
        sample_n=args.sample,
        tool=args.tool or "capped",
        extra={"merge_cap": args.cap, "merged_count": len(capped), "capped": was},
    )
    if args.summary_out:
        write_summary_json(Path(args.summary_out), summary)
    print(f"{len(lines)} {len(capped)} {int(was)}")
    return 0


def cmd_parse_uncover(args: argparse.Namespace) -> int:
    raw = Path(args.path).read_text(encoding="utf-8", errors="replace") if args.path else sys.stdin.read()
    hosts = parse_uncover_hosts(raw)
    if args.scope:
        hosts = in_scope_hosts(hosts, args.scope) if args.scope_filter else hosts
    out_hosts = Path(args.out_hosts)
    out_hosts.parent.mkdir(parents=True, exist_ok=True)
    out_hosts.write_text("".join(f"{h}\n" for h in hosts), encoding="utf-8")
    summary = summarize_lines(hosts, sample_n=args.sample, tool="uncover")
    if args.summary_out:
        write_summary_json(Path(args.summary_out), summary)
    print(len(hosts))
    return 0


def cmd_parse_xnlinkfinder(args: argparse.Namespace) -> int:
    raw = Path(args.path).read_text(encoding="utf-8", errors="replace") if args.path else sys.stdin.read()
    endpoints = parse_xnlinkfinder_endpoints(raw)
    capped, was = cap_lines_for_merge(endpoints, args.cap)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if was and args.full_out:
        Path(args.full_out).write_text("".join(f"{e}\n" for e in endpoints), encoding="utf-8")
    out.write_text("".join(f"{e}\n" for e in capped), encoding="utf-8")
    summary = summarize_lines(
        endpoints,
        sample_n=args.sample,
        tool="xnLinkFinder",
        extra={"merge_cap": args.cap, "merged_count": len(capped), "capped": was},
    )
    if args.summary_out:
        write_summary_json(Path(args.summary_out), summary)
    print(len(endpoints))
    return 0


def cmd_tlsx_feedback(args: argparse.Namespace) -> int:
    sans = _read_lines(Path(args.sans))
    known = _read_lines(Path(args.known)) if args.known else []
    delta = tlsx_scope_delta(sans, known, args.target)
    Path(args.out_in_scope).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_in_scope).write_text(
        "".join(f"{h}\n" for h in delta["in_scope_new"]), encoding="utf-8"
    )
    Path(args.out_candidates).write_text(
        "".join(f"{h}\n" for h in delta["all_new"]), encoding="utf-8"
    )
    summary = summarize_lines(
        sans,
        sample_n=args.sample,
        tool="tlsx",
        extra={
            "in_scope_new_count": len(delta["in_scope_new"]),
            "in_scope_new_sample": sample_lines(delta["in_scope_new"], args.sample),
            "out_of_scope_count": len(delta["out_of_scope"]),
            "out_of_scope_sample": sample_lines(delta["out_of_scope"], min(args.sample, 10)),
        },
    )
    if args.summary_out:
        write_summary_json(Path(args.summary_out), summary)
    print(len(delta["in_scope_new"]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recon_enrichment.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("summarize", help="Write count+sample summary JSON for a line file")
    s.add_argument("--path", required=True)
    s.add_argument("--out")
    s.add_argument("--tool", default="")
    s.add_argument("--sample", type=int, default=20)
    s.set_defaults(func=cmd_summarize)

    c = sub.add_parser("cap-merge", help="Cap a noisy artefact before merge; keep full aside")
    c.add_argument("--src", required=True)
    c.add_argument("--merge-out", required=True)
    c.add_argument("--full-out")
    c.add_argument("--summary-out")
    c.add_argument("--cap", type=int, default=50000)
    c.add_argument("--sample", type=int, default=20)
    c.add_argument("--tool", default="")
    c.set_defaults(func=cmd_cap_merge)

    u = sub.add_parser("parse-uncover", help="Normalize uncover output → host list + summary")
    u.add_argument("--path")
    u.add_argument("--out-hosts", required=True)
    u.add_argument("--summary-out")
    u.add_argument("--sample", type=int, default=20)
    u.add_argument("--scope", default="")
    u.add_argument("--scope-filter", action="store_true")
    u.set_defaults(func=cmd_parse_uncover)

    x = sub.add_parser("parse-xnlinkfinder", help="Normalize xnLinkFinder output + optional cap")
    x.add_argument("--path")
    x.add_argument("--out", required=True)
    x.add_argument("--full-out")
    x.add_argument("--summary-out")
    x.add_argument("--cap", type=int, default=5000)
    x.add_argument("--sample", type=int, default=20)
    x.set_defaults(func=cmd_parse_xnlinkfinder)

    t = sub.add_parser("tlsx-feedback", help="Diff tlsx SANs vs known subs; write in-scope new")
    t.add_argument("--sans", required=True)
    t.add_argument("--known", default="")
    t.add_argument("--target", required=True)
    t.add_argument("--out-in-scope", required=True)
    t.add_argument("--out-candidates", required=True)
    t.add_argument("--summary-out")
    t.add_argument("--sample", type=int, default=20)
    t.set_defaults(func=cmd_tlsx_feedback)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""findings_dedupe.py — fingerprint-based finding dedupe (codex-security inspired).

Clean-room port of the *idea* of stable fingerprints + sibling grouping from
openai/codex-security (Apache-2.0). No embeddings / no hosted service.

Fingerprint = sha256(normalized title|url|vtype)[:16]

Usage:
  python3 findings_dedupe.py findings/<target>/sessions/<id>
  python3 findings_dedupe.py findings/... --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any


def _norm(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"/+$", "", s)
    return s


def fingerprint(title: str = "", url: str = "", vtype: str = "") -> str:
    key = "|".join((_norm(title), _norm(url), _norm(vtype)))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def dedupe(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (kept, duplicates). First occurrence wins; dupes reference winner fp."""
    kept: list[dict[str, Any]] = []
    dupes: list[dict[str, Any]] = []
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        fp = f.get("fingerprint") or fingerprint(
            f.get("title") or f.get("raw") or "",
            f.get("url") or "",
            f.get("vtype") or "",
        )
        item = {**f, "fingerprint": fp}
        if fp in seen:
            item["duplicate_of"] = fp
            dupes.append(item)
        else:
            seen[fp] = item
            kept.append(item)
    return kept, dupes


def load_findings_dir(findings_dir: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for root, _dirs, files in os.walk(findings_dir):
        rel_root = os.path.relpath(root, findings_dir)
        vtype = rel_root.split(os.sep)[0] if rel_root != "." else ""
        for fn in files:
            if not fn.endswith(".txt"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        url_m = re.search(r"https?://\S+", line)
                        out.append({
                            "raw": line,
                            "title": line[:160],
                            "url": url_m.group(0) if url_m else "",
                            "vtype": vtype,
                            "source": os.path.relpath(path, findings_dir),
                        })
            except OSError:
                continue
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Dedupe findings by fingerprint")
    ap.add_argument("findings_dir")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not os.path.isdir(args.findings_dir):
        print(f"[-] not a directory: {args.findings_dir}", file=sys.stderr)
        return 1
    findings = load_findings_dir(args.findings_dir)
    kept, dupes = dedupe(findings)
    if args.json:
        print(json.dumps({"kept": len(kept), "duplicates": len(dupes),
                          "items_kept": kept[:50], "items_dupes": dupes[:50]}, indent=2))
    else:
        print(f"[+] kept={len(kept)} duplicates={len(dupes)} (of {len(findings)})")
        for d in dupes[:15]:
            print(f"  DUP {d.get('fingerprint')}: {d.get('source')}: {d.get('raw','')[:80]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

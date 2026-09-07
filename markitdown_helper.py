#!/usr/bin/env python3
"""markitdown_helper.py — convert office/docs to Markdown for LLM ingest.

Thin wrapper around Microsoft MarkItDown (MIT). Useful for SOWs, policies,
PPTX decks, PDFs, and HTML evidence before feeding brain/Obsidian.

Usage:
  python3 markitdown_helper.py path/to/file.pptx
  python3 markitdown_helper.py path/to/file.pdf -o out.md
  python3 markitdown_helper.py path/to/dir --glob "*.pdf" -o out_dir/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _converter():
    try:
        from markitdown import MarkItDown
    except ImportError as exc:
        raise SystemExit(
            "markitdown not installed. Prefer the repo venv:\n"
            "  .venv/bin/pip install 'markitdown[all]'\n"
            "or: python3 -m pip install --user --break-system-packages 'markitdown[all]'"
        ) from exc
    return MarkItDown()


def convert_one(src: Path, md: MarkItDown) -> str:
    result = md.convert(str(src))
    text = getattr(result, "text_content", None) or str(result)
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert docs/decks to Markdown via markitdown")
    ap.add_argument("path", help="File or directory")
    ap.add_argument("-o", "--output", help="Output .md file or directory")
    ap.add_argument("--glob", default="*", help="When path is a directory, glob (default *)")
    args = ap.parse_args()

    src = Path(args.path).expanduser().resolve()
    if not src.exists():
        print(f"[-] not found: {src}", file=sys.stderr)
        return 1

    md = _converter()
    files: list[Path]
    if src.is_dir():
        files = sorted(p for p in src.glob(args.glob) if p.is_file())
        if not files:
            print(f"[-] no files matched {args.glob} under {src}", file=sys.stderr)
            return 1
    else:
        files = [src]

    out = Path(args.output).expanduser().resolve() if args.output else None
    if out and len(files) > 1:
        out.mkdir(parents=True, exist_ok=True)

    for f in files:
        text = convert_one(f, md)
        if out is None:
            print(f"<!-- source: {f} -->\n")
            print(text)
            continue
        if out.is_dir() or len(files) > 1:
            dest = (out if out.is_dir() else out.parent) / (f.stem + ".md")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
            print(f"[+] {f.name} -> {dest}")
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            print(f"[+] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

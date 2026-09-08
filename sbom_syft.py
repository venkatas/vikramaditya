#!/usr/bin/env python3
"""
sbom_syft.py — opt-in Syft SBOM (+ optional Grype) for engagement packs.

Generates CycloneDX and/or SPDX JSON via Anchore Syft and optionally scans the
SBOM with Grype. Artefacts attach under engagements/<target>/sbom/ (or a
caller-supplied --pack-dir) so evidence bags and client packs can include them.

Not on the default scan path — invoke via CLI. No ALLOW_STATE_CHANGES changes.

Usage:
    python3 sbom_syft.py --target /path/to/app --pack-dir engagements/acme
    python3 sbom_syft.py --target dir:. --formats cyclonedx-json,spdx-json --grype
    python3 sbom_syft.py --attach-only --pack-dir engagements/acme --sbom path.cdx.json

Install (optional):
    brew install syft        # or curl install script from anchore/syft
    brew install grype       # optional vulnerability scan
    # SYFT_BIN=...  GRYPE_BIN=...

Docs: docs/gitleaks-syft-bagit.md
Licenses: Syft/Grype Apache-2.0 (Anchore) — not vendored.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

WRAPPER_VERSION = "1.0.0"
DEFAULT_FORMATS = ("cyclonedx-json", "spdx-json")

Runner = Callable[..., Any]

_FORMAT_EXT = {
    "cyclonedx-json": "cdx.json",
    "cyclonedx-xml": "cdx.xml",
    "spdx-json": "spdx.json",
    "spdx-tag-value": "spdx.txt",
    "json": "syft.json",
}


def _which(name: str) -> str | None:
    return shutil.which(name)


def resolve_syft(bin_env: str = "SYFT_BIN") -> str | None:
    override = (os.environ.get(bin_env) or "").strip()
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    return _which("syft")


def resolve_grype(bin_env: str = "GRYPE_BIN") -> str | None:
    override = (os.environ.get(bin_env) or "").strip()
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    return _which("grype")


def install_hint_syft() -> str:
    return (
        "syft not found.\n"
        "  Homebrew: brew install syft\n"
        "  Or: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin\n"
        "  Then: export SYFT_BIN=/path/to/syft"
    )


def install_hint_grype() -> str:
    return (
        "grype not found (optional).\n"
        "  Homebrew: brew install grype\n"
        "  Or: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
    )


def sbom_subdir(pack_dir: Path | str) -> Path:
    """Canonical SBOM folder under an engagement pack."""
    return Path(pack_dir) / "sbom"


def format_outfile(sbom_dir: Path, fmt: str) -> Path:
    ext = _FORMAT_EXT.get(fmt, fmt.replace("/", "_") + ".out")
    return sbom_dir / f"sbom.{ext}"


def build_syft_argv(
    target: str,
    outputs: Sequence[tuple[str, Path]],
) -> list[str]:
    """Build syft argv (without binary). outputs = [(format, path), ...]."""
    args = [target]
    for fmt, path in outputs:
        args.extend(["-o", f"{fmt}={path}"])
    return args


def run_syft(
    target: str,
    pack_dir: Path | str,
    *,
    formats: Sequence[str] = DEFAULT_FORMATS,
    syft_bin: str | None = None,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Generate SBOM file(s) under pack_dir/sbom/."""
    binary = syft_bin or resolve_syft()
    if not binary:
        raise FileNotFoundError(install_hint_syft())

    sbom_dir = sbom_subdir(pack_dir)
    sbom_dir.mkdir(parents=True, exist_ok=True)
    outputs = [(fmt, format_outfile(sbom_dir, fmt)) for fmt in formats]
    cmd = [binary] + build_syft_argv(target, outputs)
    try:
        proc = runner(cmd, capture_output=True, text=True, check=False)
    except TypeError:
        proc = runner(cmd)

    written = [str(p) for _, p in outputs if p.is_file() and p.stat().st_size > 0]
    return {
        "cmd": cmd,
        "returncode": getattr(proc, "returncode", 0),
        "stderr": (getattr(proc, "stderr", "") or "")[-2000:],
        "stdout": (getattr(proc, "stdout", "") or "")[-500:],
        "files": written,
        "sbom_dir": str(sbom_dir),
    }


def run_grype_on_sbom(
    sbom_path: Path | str,
    out_path: Path | str,
    *,
    grype_bin: str | None = None,
    output_format: str = "json",
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Scan an existing SBOM with Grype (sbom: scheme). Opt-in only."""
    binary = grype_bin or resolve_grype()
    if not binary:
        raise FileNotFoundError(install_hint_grype())

    sbom = Path(sbom_path)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    # Prefer -o json --file; fall back to stdout redirect semantics via -o
    cmd = [
        binary,
        f"sbom:{sbom}",
        "-o",
        output_format,
        "--file",
        str(out),
    ]
    try:
        proc = runner(cmd, capture_output=True, text=True, check=False)
    except TypeError:
        proc = runner(cmd)

    return {
        "cmd": cmd,
        "returncode": getattr(proc, "returncode", 0),
        "stderr": (getattr(proc, "stderr", "") or "")[-2000:],
        "file": str(out) if out.is_file() else "",
    }


def attach_sbom_to_pack(
    pack_dir: Path | str,
    sbom_paths: Sequence[Path | str],
    *,
    grype_path: Path | str | None = None,
    target_label: str = "",
) -> dict[str, Any]:
    """Copy/link SBOM (+ optional Grype) into pack_dir/sbom and write manifest.

    Safe to call with already-in-place paths (no-op copy when same file).
    """
    sbom_dir = sbom_subdir(pack_dir)
    sbom_dir.mkdir(parents=True, exist_ok=True)
    attached: list[str] = []
    for src in sbom_paths:
        src_p = Path(src)
        if not src_p.is_file():
            continue
        dest = sbom_dir / src_p.name
        if src_p.resolve() != dest.resolve():
            shutil.copy2(src_p, dest)
        attached.append(str(dest))

    grype_attached = ""
    if grype_path:
        gp = Path(grype_path)
        if gp.is_file():
            dest = sbom_dir / gp.name
            if gp.resolve() != dest.resolve():
                shutil.copy2(gp, dest)
            grype_attached = str(dest)

    manifest = {
        "tool": "syft",
        "wrapper_version": WRAPPER_VERSION,
        "target": target_label,
        "sbom_files": attached,
        "grype_file": grype_attached or None,
        "attached_at": datetime.now(timezone.utc).isoformat(),
    }
    (sbom_dir / "attach_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Opt-in Syft SBOM (+ optional Grype) attach to engagement packs"
    )
    p.add_argument("--target", default="", help="Syft target (dir:., image:…, or path)")
    p.add_argument("--pack-dir", required=True,
                   help="Engagement pack root (writes pack-dir/sbom/)")
    p.add_argument(
        "--formats",
        default="cyclonedx-json,spdx-json",
        help="Comma-separated Syft -o formats (default: cyclonedx-json,spdx-json)",
    )
    p.add_argument("--grype", action="store_true", help="Also run Grype on the CycloneDX/SPDX SBOM")
    p.add_argument("--attach-only", action="store_true",
                   help="Skip syft; only attach --sbom paths into pack-dir/sbom")
    p.add_argument("--sbom", action="append", default=[],
                   help="Existing SBOM file to attach (repeatable; with --attach-only)")
    p.add_argument("--json", action="store_true", help="Print manifest JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    pack = Path(args.pack_dir)
    pack.mkdir(parents=True, exist_ok=True)

    if args.attach_only:
        if not args.sbom:
            print("[-] --attach-only requires at least one --sbom", file=sys.stderr)
            return 2
        manifest = attach_sbom_to_pack(pack, args.sbom, target_label=args.target or "")
    else:
        if not args.target:
            print("[-] Provide --target (or use --attach-only)", file=sys.stderr)
            return 2
        if not resolve_syft():
            print(install_hint_syft(), file=sys.stderr)
            return 1
        formats = [f.strip() for f in args.formats.split(",") if f.strip()]
        result = run_syft(args.target, pack, formats=formats)
        if not result["files"]:
            print(
                f"[-] syft produced no files (rc={result['returncode']}): {result['stderr']}",
                file=sys.stderr,
            )
            return 1

        grype_out: Path | None = None
        if args.grype:
            if not resolve_grype():
                print(install_hint_grype(), file=sys.stderr)
                # SBOM still attached; grype is optional
            else:
                # Prefer cyclonedx, else first file
                primary = None
                for f in result["files"]:
                    if f.endswith("cdx.json") or "cyclonedx" in f:
                        primary = f
                        break
                if primary is None:
                    primary = result["files"][0]
                grype_out = sbom_subdir(pack) / "grype.json"
                g = run_grype_on_sbom(primary, grype_out)
                if not g["file"]:
                    print(f"[!] grype produced no file: {g['stderr']}", file=sys.stderr)
                    grype_out = None

        manifest = attach_sbom_to_pack(
            pack,
            result["files"],
            grype_path=grype_out,
            target_label=args.target,
        )
        manifest["syft"] = {
            "returncode": result["returncode"],
            "files": result["files"],
        }

    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        print(
            f"[+] SBOM attached under {sbom_subdir(pack)} "
            f"({len(manifest.get('sbom_files') or [])} file(s)"
            f"{', grype' if manifest.get('grype_file') else ''})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
evidence_bag.py — opt-in BagIt hashed evidence packs.

Builds a BagIt 0.97 bag (sha256/sha512 manifests) containing engagement
evidence: report HTML/MD, Burp exports, SARIF, SBOM, and screenshots.

Prefers LibraryOfCongress bagit-python (CC0) when installed; falls back to a
stdlib BagIt writer so glue/tests work without the dependency.

Usage:
    python3 evidence_bag.py --pack-dir engagements/acme --out engagements/acme/evidence-bags
    python3 evidence_bag.py --pack-dir engagements/acme \\
        --report reports/acme.html --burp findings/acme/burp \\
        --sarif findings/acme/gitleaks/gitleaks.sarif.json \\
        --sbom-dir engagements/acme/sbom --screenshots reports/poc_screenshots

Install (optional):
    pip install 'bagit>=1.8.1'

Docs: docs/gitleaks-syft-bagit.md
License: bagit-python CC0 — https://github.com/LibraryOfCongress/bagit-python
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

WRAPPER_VERSION = "1.0.0"
BAGIT_VERSION = "0.97"
DEFAULT_CHECKSUMS = ("sha256", "sha512")

# Relative destinations inside bag data/
_SLOT_MAP = {
    "report": "report",
    "burp": "burp",
    "sarif": "sarif",
    "sbom": "sbom",
    "screenshots": "screenshots",
}


def bagit_available() -> bool:
    try:
        import bagit  # noqa: F401
        return True
    except ImportError:
        return False


def install_hint() -> str:
    return (
        "bagit-python not installed (stdlib BagIt writer will be used).\n"
        "  Optional: pip install 'bagit>=1.8.1'"
    )


def _hash_file(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_into(src: Path, dest_dir: Path) -> list[Path]:
    """Copy a file or directory tree into dest_dir; return payload file paths."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    if src.is_file():
        dest = dest_dir / src.name
        shutil.copy2(src, dest)
        copied.append(dest)
        return copied
    if src.is_dir():
        for root, dirs, files in os.walk(src):
            # skip junk
            dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", ".DS_Store"}]
            rel = Path(root).relative_to(src)
            target_root = dest_dir / rel
            target_root.mkdir(parents=True, exist_ok=True)
            for fn in files:
                if fn.startswith(".") and fn not in {".done"}:
                    continue
                s = Path(root) / fn
                d = target_root / fn
                shutil.copy2(s, d)
                copied.append(d)
    return copied


def collect_evidence(
    bag_data_dir: Path,
    *,
    report: Sequence[Path | str] = (),
    burp: Sequence[Path | str] = (),
    sarif: Sequence[Path | str] = (),
    sbom: Sequence[Path | str] = (),
    screenshots: Sequence[Path | str] = (),
    extra: Mapping[str, Sequence[Path | str]] | None = None,
) -> dict[str, list[str]]:
    """Populate bag_data_dir/<slot>/ from caller paths. Returns slot→files map."""
    bag_data_dir.mkdir(parents=True, exist_ok=True)
    inventory: dict[str, list[str]] = {}

    slots: dict[str, Sequence[Path | str]] = {
        "report": report,
        "burp": burp,
        "sarif": sarif,
        "sbom": sbom,
        "screenshots": screenshots,
    }
    if extra:
        for k, v in extra.items():
            slots[k] = v

    for slot, paths in slots.items():
        if not paths:
            continue
        slot_dir = bag_data_dir / _SLOT_MAP.get(slot, slot)
        collected: list[str] = []
        for p in paths:
            src = Path(p)
            if not src.exists():
                continue
            for dest in _copy_into(src, slot_dir):
                collected.append(str(dest.relative_to(bag_data_dir)))
        if collected:
            inventory[slot] = collected
    return inventory


def _write_stdlib_bag(
    bag_dir: Path,
    bag_info: dict[str, str],
    checksums: Sequence[str] = DEFAULT_CHECKSUMS,
) -> dict[str, Any]:
    """Create BagIt tag files + manifests using stdlib only."""
    data_dir = bag_dir / "data"
    if not data_dir.is_dir():
        raise FileNotFoundError(f"missing data/ under {bag_dir}")

    (bag_dir / "bagit.txt").write_text(
        f"BagIt-Version: {BAGIT_VERSION}\nTag-File-Character-Encoding: UTF-8\n",
        encoding="utf-8",
    )

    # Payload oxum
    total_bytes = 0
    total_files = 0
    payload_files: list[Path] = []
    for root, _dirs, files in os.walk(data_dir):
        for fn in files:
            fp = Path(root) / fn
            total_files += 1
            total_bytes += fp.stat().st_size
            payload_files.append(fp)

    info = dict(bag_info)
    info.setdefault("Bagging-Date", date.today().isoformat())
    info.setdefault(
        "Bag-Software-Agent",
        f"vikramaditya evidence_bag.py/{WRAPPER_VERSION} (stdlib)",
    )
    info["Payload-Oxum"] = f"{total_bytes}.{total_files}"
    lines = [f"{k}: {v}" for k, v in info.items()]
    (bag_dir / "bag-info.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    for alg in checksums:
        manifest_lines = []
        for fp in sorted(payload_files):
            rel = fp.relative_to(bag_dir).as_posix()
            digest = _hash_file(fp, alg)
            manifest_lines.append(f"{digest}  {rel}")
        (bag_dir / f"manifest-{alg}.txt").write_text(
            "\n".join(manifest_lines) + ("\n" if manifest_lines else ""),
            encoding="utf-8",
        )

        # tagmanifest covers bagit.txt, bag-info.txt, and other manifests
        tag_files = [
            bag_dir / "bagit.txt",
            bag_dir / "bag-info.txt",
        ] + [bag_dir / f"manifest-{a}.txt" for a in checksums if a != alg]
        # include other algorithms' manifests too
        for a in checksums:
            mp = bag_dir / f"manifest-{a}.txt"
            if mp not in tag_files and mp.is_file():
                tag_files.append(mp)
        tag_lines = []
        for tf in sorted(set(tag_files), key=lambda p: p.name):
            if not tf.is_file():
                continue
            tag_lines.append(f"{_hash_file(tf, alg)}  {tf.name}")
        (bag_dir / f"tagmanifest-{alg}.txt").write_text(
            "\n".join(tag_lines) + "\n", encoding="utf-8"
        )

    return {
        "backend": "stdlib",
        "payload_files": total_files,
        "payload_bytes": total_bytes,
        "checksums": list(checksums),
    }


def make_evidence_bag(
    bag_dir: Path | str,
    *,
    bag_info: Mapping[str, str] | None = None,
    checksums: Sequence[str] = DEFAULT_CHECKSUMS,
    prefer_bagit_lib: bool = True,
) -> dict[str, Any]:
    """Finalize bag_dir (must already contain data/) as a BagIt bag."""
    bag_path = Path(bag_dir)
    bag_path.mkdir(parents=True, exist_ok=True)
    info = {
        "Source-Organization": "Vikramaditya",
        "External-Description": "Engagement evidence pack (report, burp, SARIF, SBOM, screenshots)",
        "Bagging-Date": date.today().isoformat(),
    }
    if bag_info:
        info.update({str(k): str(v) for k, v in bag_info.items()})

    if prefer_bagit_lib and bagit_available():
        import bagit

        # bagit.make_bag expects the directory to already hold payload files at
        # top-level OR under data/. If data/ exists, make_bag treats bag_dir as
        # already structured — but make_bag wants unbagged content. We keep
        # payload under data/ and use stdlib writer when data/ pre-exists, OR
        # call make_bag only when payload is still at top-level.
        data = bag_path / "data"
        if data.is_dir() and any(data.iterdir()):
            # Already staged under data/ — stdlib writer (bagit.make_bag would
            # nest another data/).
            meta = _write_stdlib_bag(bag_path, info, checksums=checksums)
            meta["bagit_lib_present"] = True
            return meta
        bag = bagit.make_bag(
            str(bag_path),
            bag_info=info,
            checksums=list(checksums),
            processes=1,
        )
        return {
            "backend": "bagit",
            "path": str(bag_path),
            "checksums": list(checksums),
            "payload_oxum": bag.info.get("Payload-Oxum"),
            "bagit_lib_present": True,
        }

    meta = _write_stdlib_bag(bag_path, info, checksums=checksums)
    meta["bagit_lib_present"] = bagit_available()
    return meta


def validate_bag(bag_dir: Path | str) -> dict[str, Any]:
    """Validate manifests (stdlib) or bagit.Bag.validate() when available."""
    bag_path = Path(bag_dir)
    if bagit_available():
        import bagit

        try:
            bag = bagit.Bag(str(bag_path))
            bag.validate()
            return {"valid": True, "backend": "bagit"}
        except Exception as exc:  # noqa: BLE001 — surface any validation error
            return {"valid": False, "backend": "bagit", "error": str(exc)}

    # Stdlib: re-hash and compare manifest-sha256.txt
    manifest = bag_path / "manifest-sha256.txt"
    if not manifest.is_file():
        return {"valid": False, "backend": "stdlib", "error": "missing manifest-sha256.txt"}
    errors: list[str] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, rel = parts
        fp = bag_path / rel
        if not fp.is_file():
            errors.append(f"missing {rel}")
            continue
        if _hash_file(fp, "sha256") != digest:
            errors.append(f"mismatch {rel}")
    return {"valid": not errors, "backend": "stdlib", "errors": errors}


def discover_pack_inputs(pack_dir: Path | str) -> dict[str, list[str]]:
    """Heuristic discovery of report/burp/sarif/sbom/screenshots under a pack."""
    root = Path(pack_dir)
    found: dict[str, list[str]] = {
        "report": [],
        "burp": [],
        "sarif": [],
        "sbom": [],
        "screenshots": [],
    }
    # reports
    for pattern in ("reports", "report"):
        d = root / pattern
        if d.is_dir():
            for p in sorted(d.rglob("*")):
                if p.is_file() and p.suffix.lower() in {".html", ".md", ".pdf", ".json"}:
                    found["report"].append(str(p))
        elif d.is_file():
            found["report"].append(str(d))
    # burp
    for cand in (root / "burp", root / "findings" / "burp", root / "findings"):
        burp_json = cand / "findings.json" if cand.name != "burp" else cand / "findings.json"
        if cand.name == "burp" and cand.is_dir():
            found["burp"].append(str(cand))
            break
        if burp_json.is_file() and "burp" in str(burp_json):
            found["burp"].append(str(burp_json.parent))
            break
    burp_dir = root / "findings"
    if not found["burp"] and burp_dir.is_dir():
        nested = burp_dir / "burp"
        if nested.is_dir():
            found["burp"].append(str(nested))
    # sarif
    for p in root.rglob("*.sarif.json"):
        found["sarif"].append(str(p))
    for p in root.rglob("*.sarif"):
        found["sarif"].append(str(p))
    # sbom
    sbom_dir = root / "sbom"
    if sbom_dir.is_dir():
        found["sbom"].append(str(sbom_dir))
    # screenshots
    for cand in (
        root / "screenshots",
        root / "poc_screenshots",
        root / "reports" / "poc_screenshots",
    ):
        if cand.is_dir():
            found["screenshots"].append(str(cand))
    return {k: v for k, v in found.items() if v}


def build_evidence_pack(
    pack_dir: Path | str,
    out_parent: Path | str,
    *,
    report: Sequence[Path | str] = (),
    burp: Sequence[Path | str] = (),
    sarif: Sequence[Path | str] = (),
    sbom: Sequence[Path | str] = (),
    screenshots: Sequence[Path | str] = (),
    bag_info: Mapping[str, str] | None = None,
    auto_discover: bool = True,
    stamp: str | None = None,
) -> dict[str, Any]:
    """Create a timestamped BagIt evidence bag under out_parent."""
    pack = Path(pack_dir)
    out_root = Path(out_parent)
    out_root.mkdir(parents=True, exist_ok=True)
    stamp = stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bag_dir = out_root / f"evidence-{stamp}"
    if bag_dir.exists():
        shutil.rmtree(bag_dir)
    data_dir = bag_dir / "data"
    data_dir.mkdir(parents=True)

    paths = {
        "report": list(report),
        "burp": list(burp),
        "sarif": list(sarif),
        "sbom": list(sbom),
        "screenshots": list(screenshots),
    }
    if auto_discover:
        discovered = discover_pack_inputs(pack)
        for k, vals in discovered.items():
            if not paths[k]:
                paths[k] = vals

    inventory = collect_evidence(
        data_dir,
        report=paths["report"],
        burp=paths["burp"],
        sarif=paths["sarif"],
        sbom=paths["sbom"],
        screenshots=paths["screenshots"],
    )
    info = {
        "External-Identifier": pack.name,
        "Internal-Sender-Identifier": str(pack),
    }
    if bag_info:
        info.update(dict(bag_info))

    # Stage a small inventory sidecar inside data/ BEFORE finalizing manifests.
    (data_dir / "inventory.json").write_text(
        json.dumps({"inventory": inventory, "pack_dir": str(pack)}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    meta = make_evidence_bag(bag_dir, bag_info=info)
    validation = validate_bag(bag_dir)
    summary = {
        "wrapper_version": WRAPPER_VERSION,
        "bag_dir": str(bag_dir),
        "inventory": inventory,
        "bag": meta,
        "validation": validation,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    (out_root / f"evidence-{stamp}.summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Opt-in BagIt hashed evidence packs")
    p.add_argument("--pack-dir", required=True, help="Engagement pack / session root")
    p.add_argument(
        "--out",
        default="",
        help="Parent dir for evidence-* bags (default: pack-dir/evidence-bags)",
    )
    p.add_argument("--report", action="append", default=[], help="Report file/dir (repeatable)")
    p.add_argument("--burp", action="append", default=[], help="Burp export file/dir")
    p.add_argument("--sarif", action="append", default=[], help="SARIF file/dir")
    p.add_argument("--sbom", action="append", default=[], dest="sbom",
                   help="SBOM file/dir (or pack-dir/sbom via discovery)")
    p.add_argument("--sbom-dir", default="", help="Alias for a single --sbom directory")
    p.add_argument("--screenshots", action="append", default=[], help="Screenshot dir/file")
    p.add_argument("--no-discover", action="store_true", help="Disable auto-discovery under pack-dir")
    p.add_argument("--json", action="store_true", help="Print summary JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    pack = Path(args.pack_dir)
    if not pack.is_dir():
        print(f"[-] pack-dir not found: {pack}", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else pack / "evidence-bags"
    sbom_paths = list(args.sbom)
    if args.sbom_dir:
        sbom_paths.append(args.sbom_dir)

    summary = build_evidence_pack(
        pack,
        out,
        report=args.report,
        burp=args.burp,
        sarif=args.sarif,
        sbom=sbom_paths,
        screenshots=args.screenshots,
        auto_discover=not args.no_discover,
    )
    if not summary["validation"].get("valid"):
        print(f"[!] bag validation issues: {summary['validation']}", file=sys.stderr)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(
            f"[+] evidence bag → {summary['bag_dir']} "
            f"(valid={summary['validation'].get('valid')}, "
            f"backend={summary['bag'].get('backend')})"
        )
    if not bagit_available():
        print(f"[*] note: {install_hint()}", file=sys.stderr)
    return 0 if summary["validation"].get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())

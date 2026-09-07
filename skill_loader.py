#!/usr/bin/env python3
"""skill_loader.py — on-demand vuln skill pack loader for brain_scanner.

Loads concise SKILL.md packs from skills/web|recon|cloud/<name>/ and related trees.
Heuristic matching maps findings/briefing text → skill names.

Env:
  VIK_SKILLS=0  disables injection callers should honor.

Public API:
  list_skills() -> list[str]
  load_skill(name_or_path) -> str
  skills_for_findings(text) -> list[str]
  format_skills_context(names, max_chars=12000) -> str
"""

from __future__ import annotations

import os
import re
from typing import Iterable

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILLS_ROOT = os.path.join(_THIS_DIR, "skills")
WEB_SKILLS_DIR = os.path.join(SKILLS_ROOT, "web")

# Canonical pack name → path relative to skills/
_PACKS: dict[str, str] = {
    "ssrf": "web/ssrf/SKILL.md",
    "sqli": "web/sqli/SKILL.md",
    "ssti": "web/ssti/SKILL.md",
    "lfi-traversal": "web/lfi-traversal/SKILL.md",
    "auth-bypass-idor": "web/auth-bypass-idor/SKILL.md",
    "xxe": "web/xxe/SKILL.md",
    "upload-rce": "web/upload-rce/SKILL.md",
    "deserialization": "web/deserialization/SKILL.md",
    # Portable CAI-inspired packs (checklists only — no CAI runtime)
    "http-security-headers": "web/http-security-headers/SKILL.md",
    "api-authz-matrix": "web/api-authz-matrix/SKILL.md",
    "passive-osint": "recon/passive-osint/SKILL.md",
    "attack-surface-map": "recon/attack-surface-map/SKILL.md",
    "cloud-metadata-imds": "cloud/cloud-metadata-imds/SKILL.md",
    "storage-exposure": "cloud/storage-exposure/SKILL.md",
}

_ALIASES: dict[str, str] = {
    "ssrf": "ssrf",
    "server-side-request-forgery": "ssrf",
    "sqli": "sqli",
    "sql-injection": "sqli",
    "sql injection": "sqli",
    "ssti": "ssti",
    "template-injection": "ssti",
    "template injection": "ssti",
    "lfi": "lfi-traversal",
    "rfi": "lfi-traversal",
    "path-traversal": "lfi-traversal",
    "path traversal": "lfi-traversal",
    "directory-traversal": "lfi-traversal",
    "directory traversal": "lfi-traversal",
    "local-file-inclusion": "lfi-traversal",
    "auth-bypass": "auth-bypass-idor",
    "auth bypass": "auth-bypass-idor",
    "broken-auth": "auth-bypass-idor",
    "access-control": "auth-bypass-idor",
    "idor": "auth-bypass-idor",
    "bola": "auth-bypass-idor",
    "xxe": "xxe",
    "xml-external-entity": "xxe",
    "upload": "upload-rce",
    "file-upload": "upload-rce",
    "upload-rce": "upload-rce",
    "webshell": "upload-rce",
    "deserialization": "deserialization",
    "insecure-deserialization": "deserialization",
    "pickle": "deserialization",
    "ysoserial": "deserialization",
    "objectinputstream": "deserialization",
    "http-security-headers": "http-security-headers",
    "security-headers": "http-security-headers",
    "cors": "http-security-headers",
    "csp": "http-security-headers",
    "api-authz-matrix": "api-authz-matrix",
    "api-authz": "api-authz-matrix",
    "bfla": "api-authz-matrix",
    "authz-matrix": "api-authz-matrix",
    "passive-osint": "passive-osint",
    "osint": "passive-osint",
    "shodan": "passive-osint",
    "attack-surface-map": "attack-surface-map",
    "attack-surface": "attack-surface-map",
    "surface-map": "attack-surface-map",
    "cloud-metadata-imds": "cloud-metadata-imds",
    "imds": "cloud-metadata-imds",
    "cloud-metadata": "cloud-metadata-imds",
    "instance-metadata": "cloud-metadata-imds",
    "storage-exposure": "storage-exposure",
    "s3": "storage-exposure",
    "bucket-exposure": "storage-exposure",
    "blob-exposure": "storage-exposure",
}

# Keyword → pack heuristics (longer / more specific first via sorted length)
_KEYWORD_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(sql[-\s]?injection|sqli|sqlmap)\b", re.I), "sqli"),
    (re.compile(r"\b(server[-\s]?side[-\s]?request[-\s]?forgery|ssrf|169\.254\.169\.254)\b", re.I), "ssrf"),
    (re.compile(r"\b(ssti|template[-\s]?injection|jinja2|freemarker|twig)\b", re.I), "ssti"),
    (re.compile(r"\b(lfi|rfi|path[-\s]?traversal|directory[-\s]?traversal|local[-\s]?file[-\s]?inclusion|\.\./\.\./)\b", re.I), "lfi-traversal"),
    (re.compile(r"\b(idor|bola|broken[-\s]?access|auth[-\s]?bypass|insecure[-\s]?direct[-\s]?object)\b", re.I), "auth-bypass-idor"),
    (re.compile(r"\b(xxe|xml[-\s]?external|external[-\s]?entity)\b", re.I), "xxe"),
    (re.compile(r"\b(file[-\s]?upload|upload[-\s]?rce|webshell|polyglot\s+upload)\b", re.I), "upload-rce"),
    (re.compile(r"\b(deseriali[sz]ation|ysoserial|objectinputstream|pickle\.loads|unserialize\()\b", re.I), "deserialization"),
    (re.compile(r"\b(security[\-\s]?headers|content[\-\s]?security[\-\s]?policy|\bcsp\b|\bcors\b|access[\-\s]?control[\-\s]?allow)\b", re.I), "http-security-headers"),
    (re.compile(r"\b(api[\-\s]?authz|bfla|broken[\-\s]?function[\-\s]?level|mass[\-\s]?assignment|authz[\-\s]?matrix)\b", re.I), "api-authz-matrix"),
    (re.compile(r"\b(osint|certificate[\-\s]?transparency|\bct[\-\s]?log|shodan|censys|passive[\-\s]?recon)\b", re.I), "passive-osint"),
    (re.compile(r"\b(attack[\-\s]?surface|surface[\-\s]?map|endpoint[\-\s]?map|tech[\-\s]?detect)\b", re.I), "attack-surface-map"),
    (re.compile(r"\b(imds|instance[\-\s]?metadata|169\.254\.169\.254|metadata\.google\.internal|imdSv2)\b", re.I), "cloud-metadata-imds"),
    (re.compile(r"\b(s3[\-\s]?bucket|storage[\-\s]?exposure|blob[\-\s]?storage|gcs[\-\s]?bucket|azure[\-\s]?blob)\b", re.I), "storage-exposure"),
]


def skills_enabled() -> bool:
    return os.environ.get("VIK_SKILLS", "1").strip() not in {"0", "false", "False", "no", "OFF"}


def list_skills() -> list[str]:
    names: list[str] = []
    for name, rel in sorted(_PACKS.items()):
        path = os.path.join(SKILLS_ROOT, rel)
        if os.path.isfile(path):
            names.append(name)
    # Also discover any extra skills/{web,recon,cloud}/*/SKILL.md not in the map
    for tree in ("web", "recon", "cloud"):
        base = os.path.join(SKILLS_ROOT, tree)
        if not os.path.isdir(base):
            continue
        for entry in sorted(os.listdir(base)):
            skill = os.path.join(base, entry, "SKILL.md")
            if os.path.isfile(skill) and entry not in names:
                names.append(entry)
    return names


def _resolve(name_or_path: str) -> str | None:
    raw = (name_or_path or "").strip()
    if not raw:
        return None
    if os.path.isfile(raw):
        return raw
    # Absolute/relative under skills/
    candidate = os.path.join(SKILLS_ROOT, raw)
    if os.path.isfile(candidate):
        return candidate
    if os.path.isfile(candidate + ".md"):
        return candidate + ".md"
    key = raw.lower().replace("_", "-").strip("/")
    if key.endswith("/skill.md"):
        key = key[: -len("/skill.md")]
    for prefix in ("web/", "recon/", "cloud/"):
        if key.startswith(prefix):
            key = key[len(prefix):]
            break
    key = _ALIASES.get(key, key)
    rel = _PACKS.get(key)
    if rel:
        path = os.path.join(SKILLS_ROOT, rel)
        if os.path.isfile(path):
            return path
    # Fallback: skills/{web,recon,cloud}/<key>/SKILL.md
    for tree in ("web", "recon", "cloud"):
        path = os.path.join(SKILLS_ROOT, tree, key, "SKILL.md")
        if os.path.isfile(path):
            return path
    # Prefix forms: recon/foo, cloud/foo, web/foo already stripped above for web/
    for prefix in ("recon/", "cloud/", "web/"):
        if key.startswith(prefix):
            path = os.path.join(SKILLS_ROOT, key, "SKILL.md")
            if os.path.isfile(path):
                return path
    return None


def load_skill(name_or_path: str) -> str:
    path = _resolve(name_or_path)
    if not path:
        available = ", ".join(list_skills()) or "(none)"
        return f"[skill_loader] skill not found: {name_or_path!r}. available: {available}"
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        return f"[skill_loader] could not read {path}: {exc}"


def skills_for_findings(text: str) -> list[str]:
    """Heuristic: return ordered unique pack names matching vuln-class keywords."""
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for pattern, name in _KEYWORD_RULES:
        if name in seen:
            continue
        if pattern.search(text):
            seen.add(name)
            found.append(name)
    return found


def format_skills_context(names: Iterable[str], max_chars: int = 12000) -> str:
    """Concatenate skill markdown until max_chars (hard cap for prompt injection)."""
    if not skills_enabled():
        return ""
    max_chars = max(0, int(max_chars))
    chunks: list[str] = []
    used = 0
    for name in names:
        body = load_skill(name)
        if body.startswith("[skill_loader]"):
            continue
        header = f"\n\n----- SKILL PACK: {name} -----\n"
        piece = header + body.strip() + "\n"
        if used + len(piece) > max_chars:
            remaining = max_chars - used
            if remaining < 64:
                break
            chunks.append(piece[:remaining] + "\n[truncated]\n")
            used = max_chars
            break
        chunks.append(piece)
        used += len(piece)
    if not chunks:
        return ""
    body = "".join(chunks)
    header = "ON-DEMAND VULN SKILL CONTEXT (static checklists — still require live proof):\n"
    out = header + body
    # Hard-cap total prompt injection size (header counts toward the budget).
    if len(out) > max_chars:
        keep = max(0, max_chars - len("\n[truncated]\n"))
        out = out[:keep] + "\n[truncated]\n"
    return out


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="List/load Vikramaditya web skill packs")
    parser.add_argument("name", nargs="?", help="Skill name to print")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--match", help="Run skills_for_findings on this text")
    args = parser.parse_args()
    if args.list or (not args.name and not args.match):
        print("\n".join(list_skills()))
        return 0
    if args.match:
        print("\n".join(skills_for_findings(args.match)))
        return 0
    print(load_skill(args.name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""skill_loader.py — on-demand vuln skill pack loader for brain_scanner.

Loads concise SKILL.md packs from skills/web/<name>/ and related trees.
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
    "api-authz-hadrian": "web/api-authz-hadrian/SKILL.md",
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
    "hadrian": "api-authz-hadrian",
    "api-authz": "api-authz-hadrian",
    "api-authz-hadrian": "api-authz-hadrian",
    "bfla": "api-authz-hadrian",
    "bopla": "api-authz-hadrian",
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
    (re.compile(r"\b(hadrian|bfla|bopla|api[\-\s]?authz|broken[\-\s]?function[\-\s]?level|role[\-\s]?matrix)\b", re.I), "api-authz-hadrian"),
]


def skills_enabled() -> bool:
    return os.environ.get("VIK_SKILLS", "1").strip() not in {"0", "false", "False", "no", "OFF"}


def list_skills() -> list[str]:
    names: list[str] = []
    for name, rel in sorted(_PACKS.items()):
        path = os.path.join(SKILLS_ROOT, rel)
        if os.path.isfile(path):
            names.append(name)
    # Also discover any extra skills/web/*/SKILL.md not in the map
    web = WEB_SKILLS_DIR
    if os.path.isdir(web):
        for entry in sorted(os.listdir(web)):
            skill = os.path.join(web, entry, "SKILL.md")
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
    if key.startswith("web/"):
        key = key[4:]
    key = _ALIASES.get(key, key)
    rel = _PACKS.get(key)
    if rel:
        path = os.path.join(SKILLS_ROOT, rel)
        if os.path.isfile(path):
            return path
    # Fallback: skills/web/<key>/SKILL.md
    path = os.path.join(WEB_SKILLS_DIR, key, "SKILL.md")
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

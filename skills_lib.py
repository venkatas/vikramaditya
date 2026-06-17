#!/usr/bin/env python3
"""
skills_lib.py — VAPT playbook library + loader.

Adapted from xalgorix (MIT) — internal/tools/skills/skills.go
(the read_skill loader + skillAliases shorthand map) and
internal/tools/skills/data/<category>/<skill>/SKILL.md (the playbook content).
The upstream `skills.go` embeds `data/<category>/<skill>/SKILL.md` and resolves
shorthand aliases (xss, sqli, lfi, rce, …) literal-first / alias-fallback before
reading the file. This module ports that loader to pure-stdlib Python and ships a
curated set of high-ROI web-app VAPT playbooks as markdown under
`skills/playbooks/`.

Why this exists
---------------
Vikramaditya's agent / brain decide what to test next from the tech fingerprint
and current findings. Giving the LLM a concise, confirmation-focused playbook for
the vuln class it is about to test sharply reduces false positives (it knows the
exact differential to run) and false negatives (it knows the variants scanners
miss). The playbooks deliberately lead with "Critical checks most often missed",
"How to confirm", and "False-positive traps" rather than long tool transcripts.

Public API
----------
    read_playbook(name)      -> str   markdown of the playbook (literal or alias);
                                      a friendly "not found, available: [...]"
                                      string on a miss (never raises).
    list_playbooks()         -> list  sorted unique playbook names (no extension).
    suggest_for_tech(techs)  -> list  playbook names relevant to a tech fingerprint
                                      (php -> sqli+lfi, nodejs -> ssti+xss, …).
    ALIASES                  -> dict  shorthand -> playbook filename (stem).

No network. No third-party deps. Reads markdown from the sibling
`skills/playbooks/` directory.

Credit
------
Playbook content adapted from the MIT-licensed xalgorix project
(https://github.com — internal/tools/skills/data/.../SKILL.md). Please retain the
xalgorix credit embedded in each playbook when redistributing.
"""

from __future__ import annotations

import os
from typing import Dict, List

# ── Locations ──────────────────────────────────────────────────────────────

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PLAYBOOKS_DIR = os.path.join(_THIS_DIR, "skills", "playbooks")

_EXT = ".md"


# ── Alias map (adapted from skills.go skillAliases) ────────────────────────
# Shorthand -> canonical playbook filename stem. Literal name always wins; an
# alias is only consulted when no literal playbook matches (see read_playbook).
ALIASES: Dict[str, str] = {
    # ── core required shorthands ─────────────────────────────────────────
    "xss": "xss",
    "sqli": "sqli",
    "idor": "idor",
    "ssrf": "ssrf",
    "lfi": "lfi",
    "ssti": "ssti",
    "rce": "file-upload-rce",
    "jwt": "jwt",
    "cors": "cors",
    "redirect": "open-redirect",
    "takeover": "subdomain-takeover",
    "upload": "file-upload-rce",
    # ── extra natural-language reachability aliases ──────────────────────
    "sql-injection": "sqli",
    "sql_injection": "sqli",
    "cross-site-scripting": "xss",
    "dom-xss": "xss",
    "insecure-direct-object-reference": "idor",
    "broken-access-control": "idor",
    "bola": "idor",
    "server-side-request-forgery": "ssrf",
    "blind-ssrf": "ssrf",
    "template-injection": "ssti",
    "server-side-template-injection": "ssti",
    "local-file-inclusion": "lfi",
    "path-traversal": "lfi",
    "directory-traversal": "lfi",
    "file-read": "lfi",
    "rfi": "lfi",
    "file-upload": "file-upload-rce",
    "upload-rce": "file-upload-rce",
    "webshell": "file-upload-rce",
    "remote-code-execution": "file-upload-rce",
    "auth-bypass": "auth-bypass",
    "authentication-bypass": "auth-bypass",
    "forced-browsing": "auth-bypass",
    "jwt-attack": "jwt",
    "json-web-token": "jwt",
    "cors-misconfiguration": "cors",
    "open-redirect": "open-redirect",
    "unvalidated-redirect": "open-redirect",
    "subdomain-takeover": "subdomain-takeover",
    "dangling-dns": "subdomain-takeover",
}


# ── Tech fingerprint -> playbook suggestions ───────────────────────────────
# Keys are matched as case-insensitive *substrings* against each detected tech
# string (so "Apache/2.4 (PHP/8.1)" still hits "php"). Order of the value list
# reflects rough priority. Adapted from the engagement-driven routing the
# xalgorix agent applies off its fingerprint.
_TECH_SUGGESTIONS: Dict[str, List[str]] = {
    # languages / runtimes
    "php": ["sqli", "lfi", "file-upload-rce", "xss"],
    "asp": ["sqli", "lfi", "file-upload-rce", "open-redirect"],
    ".net": ["sqli", "ssti", "open-redirect", "jwt"],
    "java": ["ssti", "lfi", "jwt", "file-upload-rce"],
    "spring": ["ssti", "ssrf", "jwt", "auth-bypass"],
    "python": ["ssti", "sqli", "ssrf", "lfi"],
    "django": ["ssti", "idor", "open-redirect", "sqli"],
    "flask": ["ssti", "ssrf", "open-redirect", "idor"],
    "ruby": ["ssti", "sqli", "open-redirect", "file-upload-rce"],
    "rails": ["ssti", "idor", "open-redirect", "sqli"],
    "node": ["ssti", "xss", "ssrf", "jwt"],
    "express": ["ssti", "xss", "jwt", "idor"],
    "go": ["ssti", "ssrf", "jwt", "idor"],
    # frontend frameworks (DOM/CSTI surface)
    "react": ["xss", "open-redirect", "cors", "idor"],
    "angular": ["ssti", "xss", "open-redirect", "cors"],
    "vue": ["ssti", "xss", "cors", "open-redirect"],
    # CMS / platforms
    "wordpress": ["sqli", "xss", "file-upload-rce", "lfi"],
    "drupal": ["sqli", "ssti", "file-upload-rce", "xss"],
    "joomla": ["sqli", "lfi", "file-upload-rce", "xss"],
    "magento": ["sqli", "xss", "open-redirect", "file-upload-rce"],
    # servers / proxies
    "nginx": ["lfi", "open-redirect", "ssrf"],
    "apache": ["lfi", "file-upload-rce", "open-redirect"],
    "iis": ["lfi", "file-upload-rce", "open-redirect"],
    "tomcat": ["file-upload-rce", "lfi", "auth-bypass"],
    # API / auth surfaces
    "graphql": ["idor", "ssrf", "auth-bypass", "jwt"],
    "rest": ["idor", "jwt", "auth-bypass", "cors"],
    "jwt": ["jwt", "auth-bypass", "idor"],
    "oauth": ["open-redirect", "jwt", "auth-bypass"],
    "swagger": ["idor", "auth-bypass", "jwt"],
    "api": ["idor", "jwt", "auth-bypass", "cors"],
    # cloud hints (SSRF metadata, dangling DNS)
    "aws": ["ssrf", "subdomain-takeover"],
    "azure": ["ssrf", "subdomain-takeover"],
    "gcp": ["ssrf", "subdomain-takeover"],
    "cloudfront": ["subdomain-takeover", "open-redirect"],
    "heroku": ["subdomain-takeover", "ssrf"],
    "s3": ["subdomain-takeover", "ssrf"],
}


# ── Internal helpers ───────────────────────────────────────────────────────


def _normalize(name: str) -> str:
    """Trim, lowercase, strip a trailing .md / path, normalise underscores.

    Mirrors the xalgorix loader which strips a trailing /SKILL.md or .md and
    sanitises the slug before lookup.
    """
    name = (name or "").strip()
    # accept "skills/playbooks/sqli.md" or "sqli/SKILL.md" or "sqli.md"
    name = name.replace("\\", "/")
    if name.endswith("/SKILL.md"):
        name = name[: -len("/SKILL.md")]
    name = os.path.basename(name)
    if name.lower().endswith(_EXT):
        name = name[: -len(_EXT)]
    name = name.strip().lower()
    name = name.replace("_", "-")
    return name


def _playbook_path(stem: str) -> str:
    return os.path.join(PLAYBOOKS_DIR, stem + _EXT)


# ── Public API ─────────────────────────────────────────────────────────────


def list_playbooks() -> List[str]:
    """Return the sorted, unique list of available playbook names (no extension)."""
    if not os.path.isdir(PLAYBOOKS_DIR):
        return []
    names = {
        fn[: -len(_EXT)]
        for fn in os.listdir(PLAYBOOKS_DIR)
        if fn.endswith(_EXT) and not fn.startswith(".")
    }
    return sorted(names)


def read_playbook(name: str) -> str:
    """Return the markdown for a playbook.

    Resolution order (literal-first, alias-fallback — same as xalgorix
    read_skill): try the supplied name as a literal filename, then resolve it
    through ALIASES and retry. On a miss, return a clear human-readable string
    listing the available playbooks. Never raises.
    """
    stem = _normalize(name)
    available = list_playbooks()

    if stem:
        # 1. literal match
        path = _playbook_path(stem)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        # 2. alias fallback
        alias_target = ALIASES.get(stem)
        if alias_target and alias_target != stem:
            apath = _playbook_path(alias_target)
            if os.path.isfile(apath):
                with open(apath, "r", encoding="utf-8") as fh:
                    return fh.read()

    return (
        f"Playbook not found: {name!r}. "
        f"Available playbooks: {', '.join(available) if available else '(none)'}. "
        f"Aliases: {', '.join(sorted(ALIASES))}."
    )


def suggest_for_tech(techs: List[str]) -> List[str]:
    """Map a tech fingerprint to relevant playbook names.

    Each detected tech string is matched case-insensitively as a substring
    against the routing table (so "Apache/2.4 (PHP/8.1)" still hits "php").
    Returns a de-duplicated, order-preserving list restricted to playbooks that
    actually exist on disk. Empty input or unknown tech -> [].
    """
    if not techs:
        return []
    available = set(list_playbooks())
    out: List[str] = []
    seen = set()
    for tech in techs:
        if not isinstance(tech, str):
            continue
        low = tech.lower()
        for key, pbs in _TECH_SUGGESTIONS.items():
            if key in low:
                for pb in pbs:
                    if pb in available and pb not in seen:
                        seen.add(pb)
                        out.append(pb)
    return out


# ── CLI (parity with eol_check.py / prioritize.py style) ───────────────────


def _main(argv: List[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="VAPT playbook library — read_playbook / list / suggest-for-tech."
    )
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--read", metavar="NAME", help="print a playbook (literal name or alias)")
    g.add_argument("--list", action="store_true", help="list available playbooks")
    g.add_argument(
        "--suggest",
        metavar="TECH",
        help="comma-separated tech fingerprint -> suggested playbooks",
    )
    args = ap.parse_args(argv)

    if args.list:
        for n in list_playbooks():
            print(n)
        return 0
    if args.read:
        print(read_playbook(args.read))
        return 0
    if args.suggest:
        techs = [t.strip() for t in args.suggest.split(",") if t.strip()]
        sugg = suggest_for_tech(techs)
        print(", ".join(sugg) if sugg else "(no suggestions)")
        return 0
    return 1


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv[1:]))

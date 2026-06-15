#!/usr/bin/env python3
"""Leak guard — block commits/pushes that contain client identifiers or live secrets.

WHY: three confidentiality leaks slipped past *manual* pre-commit greps. A human check is not a
reliable gate. This runs as a git pre-commit AND pre-push hook and HARD-FAILS (exit 1) if the
added content matches a client identifier or a live-secret pattern.

The client blocklist lives LOCAL-ONLY at ~/.config/vikramaditya/leak_blocklist.txt (it contains
the real names, so it must never be committed). Built-in secret patterns catch real AWS keys and
private-key bodies. Tool-owned placeholders (AWS's AKIAIOSFODNN7EXAMPLE, the literal regex
``AKIA[0-9A-Z]{16}``) are explicitly allowed so the tool's own detector docs/tests don't trip it.

Usage:
  leak_guard.py --staged          scan staged changes      (pre-commit)
  leak_guard.py --range A..B      scan a commit range      (pre-push)
"""
import argparse
import os
import re
import subprocess
import sys

BLOCKLIST_FILE = os.path.expanduser(
    os.environ.get("LEAK_BLOCKLIST", "~/.config/vikramaditya/leak_blocklist.txt"))

# Live-secret patterns. Allowlist defuses the tool's OWN detector content (not real secrets).
_SECRET_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"), "private key"),
]
_SECRET_ALLOW = {"AKIAIOSFODNN7EXAMPLE"}            # AWS's documented example key
_SECRET_ALLOW_SUBSTR = ("AKIA[0-9A-Z]", "AKIA...")   # the literal regex / placeholder in docs
# Obvious placeholder/fixture markers — a secret-shaped string carrying one of these is not a
# real leaked key (this is a SECURITY tool: its docs/fixtures are full of example secrets).
_FIXTURE_MARKERS = ("\\n", "abcd", "example", "placeholder", "your_", "fake", "dummy", "redacted", "xxxx")


def _load_blocklist():
    try:
        terms = []
        for line in open(BLOCKLIST_FILE, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line.lower())
        return terms
    except OSError:
        return []


def _added_changes(diff_args):
    """Yield (path, added_line) for every added line, tracking the current file from the diff."""
    out = subprocess.run(["git", "diff", "--no-color", *diff_args],
                         capture_output=True, text=True).stdout
    path = ""
    for ln in out.splitlines():
        if ln.startswith("+++ b/"):
            path = ln[6:]
        elif ln.startswith("+") and not ln.startswith("+++"):
            yield path, ln[1:]


def _is_test_path(path):
    """Test files legitimately carry FAKE secret-shaped fixtures (e.g. AKIAEXAMPLE...). Client
    NAMES are still blocked there (blocklist), but the generic secret regex is relaxed."""
    p = (path or "").lower()
    base = p.rsplit("/", 1)[-1]
    return "/tests/" in p or base.startswith("test_") or base.endswith("_test.py")


def _scan(changes, terms):
    hits = []
    for path, ln in changes:
        low = ln.lower()
        for t in terms:                       # client names: blocked EVERYWHERE
            if t in low:
                hits.append((t, ln.strip()[:120]))
        if _is_test_path(path):               # don't flag fake AKIA fixtures in test files
            continue
        if any(mk in low for mk in _FIXTURE_MARKERS):
            continue                          # placeholder/fixture secret, not a real key
        for rx, label in _SECRET_PATTERNS:
            for m in rx.findall(ln):
                if m in _SECRET_ALLOW or any(s in ln for s in _SECRET_ALLOW_SUBSTR):
                    continue
                hits.append((label, ln.strip()[:120]))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--staged", action="store_true")
    ap.add_argument("--range", dest="rng", default=None)
    args = ap.parse_args()

    terms = _load_blocklist()
    if not terms:
        print("leak-guard: WARNING — blocklist empty/missing "
              f"({BLOCKLIST_FILE}); only secret patterns enforced.", file=sys.stderr)

    if args.staged:
        changes = _added_changes(["--cached"])
    elif args.rng:
        changes = _added_changes([args.rng])
    else:
        changes = _added_changes(["HEAD~1..HEAD"])

    hits = _scan(changes, terms)
    if hits:
        print("\n🛑 LEAK-GUARD BLOCKED: client identifier / secret in the change:", file=sys.stderr)
        seen = set()
        for what, line in hits:
            key = (what, line)
            if key in seen:
                continue
            seen.add(key)
            print(f"   • [{what}] {line}", file=sys.stderr)
        print("\nScrub it (use placeholders) before committing/pushing. "
              "Override (NOT recommended): git commit/push --no-verify.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

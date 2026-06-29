#!/usr/bin/env python3
"""Leak guard — block commits/pushes that contain client identifiers or live secrets.

WHY: four confidentiality leaks slipped past *manual* pre-commit greps. A human check is not a
reliable gate. This runs as git pre-commit, commit-msg AND pre-push hooks and HARD-FAILS (exit 1)
if added content, a changed FILENAME, or a commit MESSAGE matches a client identifier or a
live-secret pattern.

The client blocklist lives LOCAL-ONLY at ~/.config/vikramaditya/leak_blocklist.txt (override the
path with $LEAK_BLOCKLIST). It contains the real names, so it must never be committed. Built-in
secret patterns catch real AWS/GitHub/Slack/Google/Stripe keys, JWT/Bearer tokens, hardcoded
passwords, basic-auth URLs and private-key bodies. Tool-owned placeholders (AKIAIOSFODNN7EXAMPLE,
tokens carrying EXAMPLE/FAKE/PLACEHOLDER…) are allowed so the tool's own detector docs/tests don't
trip it.

Usage:
  leak_guard.py --staged           scan staged changes              (pre-commit)
  leak_guard.py --msg-file FILE     scan a commit-message file       (commit-msg)
  leak_guard.py --range A..B        scan a commit range + messages   (pre-push / CI)
"""
import argparse
import os
import re
import subprocess
import sys
import unicodedata

BLOCKLIST_FILE = os.path.expanduser(
    os.environ.get("LEAK_BLOCKLIST", "~/.config/vikramaditya/leak_blocklist.txt"))

# ── Live-secret patterns ──────────────────────────────────────────────────────────────────────
# HARD: high-confidence secret shapes — blocked EVERYWHERE (incl. test paths; a real key in a
# fixture still leaks). Suppressed ONLY by an allowlisted value or a marker embedded INSIDE the
# matched token (e.g. AKIAEXAMPLE…). A PRIVATE KEY header has no token body, so it additionally
# accepts a one-line fixture identified by a line marker.
_HARD_SECRETS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "GitHub fine-grained PAT"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"), "Stripe live key"),
    (re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"), "private key"),
]
# SOFT: higher false-positive shapes — blocked only in NON-test files and only when no fixture
# marker is present on the line (a real Bearer/JWT/password is far likelier than a fixture there).
_SOFT_SECRETS = [
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}"), "JWT / Bearer token"),
    (re.compile(r"""(?i)\bpass(?:wd|word)?\s*[:=]\s*['"][^'"\s]{6,}['"]"""), "hardcoded password"),
    (re.compile(r"""\b[a-z][a-z0-9+.\-]*://[^/\s:@'"]+:[^/\s:@'"]+@[^/\s'"]+"""), "basic-auth URL"),
]
_SECRET_ALLOW = {"AKIAIOSFODNN7EXAMPLE"}             # AWS's documented example key
_SECRET_ALLOW_SUBSTR = ("AKIA[0-9A-Z]", "AKIA...")   # the literal regex / placeholder in docs
# A marker found INSIDE a matched secret token => fixture, not a real key (AKIAEXAMPLE…, ghp_FAKE…).
_TOKEN_MARKERS = ("EXAMPLE", "FAKE", "DUMMY", "PLACEHOLDER", "REDACTED", "SAMPLE",
                  "XXXX", "TEST", "YOUR", "CHANGEME", "NOTREAL")
# A PRIVATE KEY header / a SOFT secret accepts a one-line fixture identified by a LINE marker.
_LINE_MARKERS = ("abcd", "\\n", "example", "placeholder", "your_", "fake", "dummy",
                 "redacted", "xxxx", "sample", "changeme")
# Data-dump artifacts: block by extension even when the name carries no client token.
_DUMP_EXTS = (".sql", ".har", ".dump", ".bak", ".sqlite", ".db")
_NORM_MIN_LEN = 5                                    # min term length for normalized/fuzzy matching


def _allow_dumps():
    return {x.strip().lower() for x in os.environ.get("LEAK_GUARD_ALLOW_DUMPS", "").split(",") if x.strip()}


def _norm(s):
    """NFKD-fold, drop combining marks + all non-alphanumerics, casefold — collapses separator and
    unicode variants so 'acme-bank' / 'acme.bank' / 'ACME Bank' all normalize to 'acmebank'."""
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "", s.casefold())


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


# Force raw UTF-8 paths from git. Without this, git escapes non-ASCII path bytes as octal
# (core.quotepath defaults ON) — e.g. "caf\303\251.sql" — so a client identifier with any
# non-ASCII character (accented name, CJK) never matches the verbatim/normalized blocklist and
# the FILENAME leak-guard is silently bypassed. quotepath=false emits the raw bytes; git still
# C-quotes paths containing a literal quote/tab/newline, which _unquote_git_path decodes back.
def _git(*args):
    return subprocess.run(["git", "-c", "core.quotepath=false", *args],
                          capture_output=True, text=True).stdout


def _unquote_git_path(p):
    """Decode git's C-style quoting. Even with quotepath=false, git wraps a path in double quotes
    and backslash-escapes it when it contains a quote/tab/newline. Return the literal path."""
    if len(p) >= 2 and p.startswith('"') and p.endswith('"'):
        try:
            # git uses C escapes (\", \\, \t, \n, octal \NNN); codecs unicode_escape decodes them,
            # then re-encode latin-1 / decode utf-8 to recover multibyte chars from octal bytes.
            inner = p[1:-1]
            return inner.encode("latin-1", "backslashreplace").decode("unicode_escape") \
                        .encode("latin-1", "backslashreplace").decode("utf-8", "replace")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return p[1:-1]
    return p


def _added_changes(diff_args):
    """Yield (path, added_line) for every added line, tracking the current file from the diff."""
    out = _git("diff", "--no-color", *diff_args)
    path = ""
    for ln in out.splitlines():
        if ln.startswith("+++ b/"):
            path = _unquote_git_path(ln[6:])
        elif ln.startswith("+") and not ln.startswith("+++"):
            yield path, ln[1:]


def _is_test_path(path):
    """Test files legitimately carry FAKE secret-shaped fixtures (e.g. AKIAEXAMPLE…). The SOFT
    secret regex is relaxed there; client NAMES and HARD secrets are still blocked."""
    p = (path or "").lower()
    base = p.rsplit("/", 1)[-1]
    return "/tests/" in p or base.startswith("test_") or base.endswith("_test.py")


def _changed_paths(diff_args):
    """All changed file PATHS — incl. files with no added text lines (binaries/renames)
    that ``_added_changes`` would never yield."""
    out = _git("diff", "--no-color", "--name-only", *diff_args)
    return [_unquote_git_path(p) for p in out.splitlines() if p.strip()]


def _msg_changes(text):
    """Commit-message lines as ('COMMIT_MSG', line) so the same name/secret scan applies to a
    message-only leak (the diff-based scans are blind to commit messages)."""
    return [("COMMIT_MSG", ln) for ln in (text or "").splitlines()]


def _range_messages(rng):
    """Every commit MESSAGE in a range — closes the message-only leak the diff scan can't see
    (a prior incident was remediated by scrubbing commit messages specifically)."""
    shas = _git("rev-list", rng).split()
    out = []
    for sha in shas:
        body = _git("show", "-s", "--format=%B", sha)
        out += _msg_changes(body)
    return out


def _secret_hits(path, ln):
    low = ln.lower()
    hits = []

    def _allowed(tok):
        if tok in _SECRET_ALLOW:
            return True
        if any(s in ln for s in _SECRET_ALLOW_SUBSTR):
            return True
        return any(mk in tok.upper() for mk in _TOKEN_MARKERS)    # marker INSIDE the token

    for rx, label in _HARD_SECRETS:                              # blocked everywhere
        for m in rx.findall(ln):
            tok = m if isinstance(m, str) else next((g for g in m if g), "")
            if _allowed(tok):
                continue
            if label == "private key" and any(mk in low for mk in _LINE_MARKERS):
                continue                                          # one-line placeholder PEM literal
            hits.append((label, ln.strip()[:120]))

    # SOFT secrets are relaxed ONLY on test paths (which legitimately carry fixture tokens) and
    # only suppressed by an in-TOKEN marker via _allowed(). The previous broad line-level
    # _LINE_MARKERS substring check is NOT applied here: it suppressed every SOFT secret on any
    # line that merely contained 'example'/'abcd'/'fake'/… anywhere — so a real basic-auth URL
    # against example.com, or a real JWT on a line annotated "# example", silently passed.
    if not _is_test_path(path):
        for rx, label in _SOFT_SECRETS:                          # marker-IN-TOKEN suppression only
            for m in rx.findall(ln):
                tok = m if isinstance(m, str) else next((g for g in m if g), "")
                # For a basic-auth URL the SECRET is the user:pass credential, not the host —
                # scope the marker check to the credential so a real cred against example.com
                # (host carries the marker word) is NOT suppressed.
                marker_tok = tok
                if label == "basic-auth URL":
                    cred = re.search(r"://([^@]+)@", tok)
                    marker_tok = cred.group(1) if cred else tok
                if _allowed(marker_tok):
                    continue
                hits.append((label, ln.strip()[:120]))
    return hits


_WARNED_SHORT_TERMS = False


def _warn_short_terms(terms):
    """One-time stderr notice: curated blocklist terms below the normalization floor are still
    matched VERBATIM everywhere, but NOT separator-normalized (so 'ac me'/'ac-me' variants of a
    4-char term are not caught). The floor exists to bound fuzzy false positives; surface it so the
    operator knows these terms are verbatim-only rather than assuming silent full coverage."""
    global _WARNED_SHORT_TERMS
    if _WARNED_SHORT_TERMS:
        return
    short = sorted({t for t in terms if 0 < len(t) < _NORM_MIN_LEN})
    if short:
        print(f"⚠️  leak-guard: blocklist terms shorter than {_NORM_MIN_LEN} chars are matched "
              f"VERBATIM only (no separator-normalized/fuzzy match): {', '.join(short)}",
              file=sys.stderr)
    _WARNED_SHORT_TERMS = True


def _scan(changes, terms, extra_paths=()):
    _warn_short_terms(terms)
    changes = list(changes)
    norm_terms = [(_norm(t), t) for t in terms if len(t) >= _NORM_MIN_LEN]
    allow_dumps = _allow_dumps()
    hits = []

    # FILENAME leaks: a client identifier (verbatim OR separator-normalized) in a changed PATH —
    # a clean-content file (acmebank_dump.sql) still leaks the client via its name. Plus data-dump
    # artifacts blocked by extension even when the name carries no client token.
    for path in dict.fromkeys([p for p, _ in changes] + list(extra_paths)):
        lp = (path or "").lower()
        matched = set()
        for t in terms:
            if t in lp:
                hits.append((t, f"[client filename] {path}"))
                matched.add(t)
        np = _norm(path)
        for nt, t in norm_terms:
            if t not in matched and nt and nt in np:
                hits.append((t, f"[client filename] {path}"))
        ext = os.path.splitext(lp)[1]
        if ext in _DUMP_EXTS and os.path.basename(lp) not in allow_dumps:
            hits.append(("dump artifact", f"[blocked dump artifact] {path}"))

    # CONTENT leaks: client names everywhere (verbatim + normalized) + secret patterns.
    for path, ln in changes:
        low = ln.lower()
        matched = set()
        for t in terms:                       # client names: blocked EVERYWHERE
            if t in low:
                hits.append((t, ln.strip()[:120]))
                matched.add(t)
        pending = [(nt, t) for nt, t in norm_terms if t not in matched]
        if pending:                           # separator/normalization variants (acme-bank…)
            nl = _norm(ln)
            for nt, t in pending:
                if nt and nt in nl:
                    hits.append((t, ln.strip()[:120]))
        hits.extend(_secret_hits(path, ln))
    return hits


def main():
    try:
        ap = argparse.ArgumentParser()
        ap.add_argument("--staged", action="store_true")
        ap.add_argument("--range", dest="rng", default=None)
        ap.add_argument("--msg-file", dest="msg_file", default=None)
        args = ap.parse_args()

        terms = _load_blocklist()
        # FAIL CLOSED: a missing/empty blocklist must BLOCK, not silently pass. The original
        # WARN-then-proceed is exactly how a brand-new engagement's identifiers slipped through.
        if not terms and not os.environ.get("LEAK_GUARD_ALLOW_NO_BLOCKLIST"):
            print("🛑 leak-guard: blocklist missing/empty — refusing to pass "
                  f"({BLOCKLIST_FILE}). Register the engagement's identifiers "
                  "(scripts/engagement_start.sh) or set LEAK_GUARD_ALLOW_NO_BLOCKLIST=1 "
                  "to override (logged).", file=sys.stderr)
            return 2

        if args.msg_file:
            try:
                text = open(args.msg_file, encoding="utf-8", errors="replace").read()
            except OSError:
                text = ""
            hits = _scan(_msg_changes(text), terms)
        elif args.rng:
            hits = _scan(_added_changes([args.rng]), terms, _changed_paths([args.rng]))
            hits += _scan(_range_messages(args.rng), terms)        # also scan commit MESSAGES
        elif args.staged:
            hits = _scan(_added_changes(["--cached"]), terms, _changed_paths(["--cached"]))
        else:
            hits = _scan(_added_changes(["HEAD~1..HEAD"]), terms, _changed_paths(["HEAD~1..HEAD"]))
            hits += _scan(_range_messages("HEAD~1..HEAD"), terms)
    except SystemExit:
        raise                                  # argparse --help / usage errors
    except Exception as e:
        # FAIL CLOSED on ANY internal error (regex throw, missing dep, git failure) —
        # never fall through to a silent exit 0.
        print(f"🛑 leak-guard: internal error — failing closed: {e}", file=sys.stderr)
        return 2

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

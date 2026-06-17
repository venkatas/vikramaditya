#!/usr/bin/env python3
"""exposed_data_pii.py — fetch an exposed web directory/file and check for ACTUAL PII.

Recon flags open paths (/db/, /uploads/) as "[EXPOSED]" but never looks inside. This module
closes that gap: given an exposed URL it fetches the response, detects an autoindex directory
listing, enumerates the filenames, and flags (a) strong PII indicators in the names/body
(aadhaar/PAN/payroll/…) and (b) downloadable DB backups (.sql/.dump/.bak/…). Severity is
raised when an OPEN LISTING exposes PII or a backup — i.e. data an unauthenticated attacker
can enumerate and pull.

Stdlib only (urllib) so it runs on the bare system python the tool shells out to. The PII
vocabulary is reused from cred_blast_radius so cloud + web PII detection stay consistent.
"""
from __future__ import annotations

import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from cred_blast_radius import _PII_RE  # reuse the strong, false-positive-tuned vocabulary
except Exception:
    _PII_RE = re.compile(
        r"(?i)(aadhaar|aadhar|pancard|\bpan\b|passport|\bkyc\b|\bssn\b|payroll|salary|"
        r"employe|emp[_-]?id|resume|\bdob\b|voter[_-]?id|gstin|\bifsc\b|credit[_-]?card|"
        r"\bcvv\b|bank[_-]?acc|nominee|beneficiary|biometric)")

# Downloadable data / DB-dump extensions an attacker could exfiltrate wholesale.
_BACKUP_RE = re.compile(r"(?i)\.(sql|dump|bak|db|sqlite3?|mdb|csv|xls[xm]?|tar\.gz|tgz|zip|7z|gz|bz2|backup|dmp)$")
_LISTING_MARKERS = ("index of /", "directory listing for", "<title>index of",
                    "[to parent directory]", 'id="indexlist"')
_NAV = {"../", "parent directory", "[to parent directory]", "name", "last modified", "size", "description"}
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


def _fetch(url: str, timeout: int = 15):
    """Return (status, body_text). (0, '') on any failure — never raises."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (vikramaditya-pii-check)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - authorized VAPT target
            status = getattr(resp, "status", 200) or 200
            body = resp.read(2_000_000).decode("utf-8", "ignore")  # cap 2MB
            return status, body
    except Exception as e:
        code = getattr(e, "code", 0)
        try:
            body = e.read(500_000).decode("utf-8", "ignore") if hasattr(e, "read") else ""
        except Exception:
            body = ""
        return (code or 0), body


def is_dir_listing(body: str) -> bool:
    low = (body or "").lower()
    return any(m in low for m in _LISTING_MARKERS)


def extract_listing_files(body: str) -> list:
    """Filenames from an autoindex page, minus navigation/sort links."""
    out, seen = [], set()
    for href in _HREF_RE.findall(body or ""):
        name = href.strip()
        low = name.lower()
        if not name or low in _NAV or name.startswith(("?", "#", "/")) or low.startswith(("http://", "https://")):
            continue
        if name in ("..", "../") or "parent" in low:
            continue
        name = name.rstrip("/")
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def scan_for_pii(items: list) -> list:
    """Flag items (filenames or body lines) whose text carries a strong PII indicator.

    Filenames separate words with _ - . / — which are \\w (no regex word-boundary), so
    `\\bpan\\b` would miss `pan_cards.csv`. Normalise separators to spaces first so
    boundary-anchored indicators match within names (without matching e.g. 'japan')."""
    hits = []
    for it in items:
        norm = re.sub(r"[_\-./\\]+", " ", it or "")
        m = _PII_RE.search(norm)
        if m:
            hits.append({"item": it, "indicator": m.group(1).lower()})
    return hits


def classify_backups(names: list) -> list:
    return [n for n in names if _BACKUP_RE.search(n or "")]


def assess_exposed_url(url: str, timeout: int = 15) -> dict:
    """Fetch one exposed URL and assess PII / backup exposure."""
    status, body = _fetch(url, timeout=timeout)
    result = {"url": url, "status": status, "is_listing": False,
              "files": [], "pii_indicators": [], "backups": [], "severity": "info"}
    if not status or status >= 400 or not body:
        return result

    listing = is_dir_listing(body)
    result["is_listing"] = listing
    files = extract_listing_files(body) if listing else []
    result["files"] = files

    # PII: scan filenames (if listing) AND a sample of the body text itself.
    scan_targets = list(files)
    if not listing:
        scan_targets += [ln for ln in body.splitlines() if ln.strip()][:400]
    result["pii_indicators"] = scan_for_pii(scan_targets)
    result["backups"] = classify_backups(files)

    # Severity: an OPEN listing that exposes PII or a DB backup is critical (an
    # unauthenticated attacker can enumerate + download). PII in a non-listing body
    # is high. A bare open listing with no sensitive content is low.
    if (listing and (result["pii_indicators"] or result["backups"])):
        result["severity"] = "critical"
    elif result["pii_indicators"]:
        result["severity"] = "high"
    elif listing or result["backups"]:
        result["severity"] = "low"
    else:
        result["severity"] = "info"
    return result


def run(exposed_urls: list, timeout: int = 15) -> list:
    """Assess every exposed URL; return results sorted worst-first."""
    order = {"critical": 0, "high": 1, "low": 2, "info": 3}
    results = [assess_exposed_url(u, timeout=timeout) for u in exposed_urls if u]
    results.sort(key=lambda r: order.get(r["severity"], 9))
    return results

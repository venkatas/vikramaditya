"""idor_scanner — IDOR / Broken Object-Level Authorization detector.

Closes a critical broken-authorization gap: one MAKER session read every client's record via
/RecordDetails?recordId=N and /FeeRecordDetails?feeRecordId=N
(sequential primary keys, no per-object authorization).

Two modes (friends' #1 recommendation):
  * scan_enumeration(get_fn, refs): one session loads object refs; if >=2 return DISTINCT
    sensitive records => object references are not access-controlled (BOLA).
  * scan_differential(owner_get, other_get, refs): a non-owner session receives the same
    sensitive object data the owner does => cross-user object access (IDOR).

Composes pii_detector (sensitive-content) + bfla_scanner.classify (gating). Detection is
recall-oriented; severity scales with the number of objects exposed.

Iteration-2 backlog: learn object-ref params + id ranges from the crawl/site-map; opaque
vs sequential id heuristics; subject-id ≠ authenticated-user correlation; pagination-aware.
"""
import difflib
import hashlib
import html

import bfla_scanner
import pii_detector

# government identifiers = "sensitive record" signal (reuse pii_detector's compiled patterns)
_GOVT_RES = (pii_detector._PAN_RE, pii_detector._GSTIN_RE, pii_detector._AADHAAR_RE)


def _norm(ret):
    if len(ret) == 2:
        return ret[0], ret[1], ""
    return ret[0], ret[1], ret[2]


def _has_sensitive(body):
    if not body:
        return False
    d = html.unescape(body)
    return any(rx.search(d) for rx in _GOVT_RES)


def _signature(body):
    """Stable hash of the sensitive values in a body (to measure record distinctness).

    Raw values are hashed, never stored/emitted — so distinctness is measured without
    retaining PII.
    """
    d = html.unescape(body or "")
    vals = []
    for rx in _GOVT_RES:
        vals += rx.findall(d)
    return hashlib.sha1("|".join(sorted(set(vals))).encode()).hexdigest()[:12]


def _similar(a, b, threshold=0.9):
    if not a or not b:
        return False
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio() >= threshold


def scan_enumeration(get_fn, refs):
    """One session loads each ref; flag BOLA if >=2 refs return DISTINCT sensitive records."""
    leaking = []
    for ref in refs:
        status, body, location = _norm(get_fn(ref))
        if (status == 200 and _has_sensitive(body)
                and bfla_scanner.classify(status, body, location) == "accessible"):
            leaking.append((ref, _signature(body)))
    distinct = len({sig for _, sig in leaking})
    if len(leaking) >= 2 and distinct >= 2:
        n = len(leaking)
        sev = "critical" if n >= 100 else "high" if n >= 10 else "medium"
        return [{
            "type": "idor_bola_enumeration",
            "vuln_class": "IDOR/BOLA",
            "severity": sev,
            "confidence": "confirmed",
            "refs_tested": len(refs),
            "refs_leaking": n,
            "distinct_records": distinct,
            "evidence": (f"{n} object references returned DISTINCT sensitive records "
                         f"({distinct} distinct) to a single session — object references are "
                         f"not access-controlled (BOLA via sequential/predictable ids)"),
        }]
    return []


def scan_differential(owner_get, other_get, refs):
    """Flag IDOR where a non-owner session receives the owner's sensitive object data."""
    findings = []
    for ref in refs:
        os_, ob, ol = _norm(owner_get(ref))
        if not (os_ == 200 and _has_sensitive(ob)):
            continue  # ref must be a valid sensitive object for the owner to compare against
        ts, tb, tl = _norm(other_get(ref))
        if bfla_scanner.classify(ts, tb, tl) in ("gated", "absent"):
            continue  # other session properly denied
        if ts == 200 and (_has_sensitive(tb) or _similar(ob, tb)):
            findings.append({
                "type": "idor_bola_differential",
                "vuln_class": "IDOR/BOLA",
                "severity": "high",
                "confidence": "confirmed",
                "ref": ref,
                "evidence": (f"a second (non-owner) session received sensitive object data at "
                             f"{ref} that the owning session also receives — cross-user object "
                             f"access (IDOR), object-level authorization absent"),
            })
    return findings

"""pii_detector — flag sensitive PII + bulk data exposure in AUTHENTICATED responses.

Closes a gap surfaced in an authenticated ASP.NET WebForms VAPT engagement: bulk PII (PAN/GSTIN) and a
1583-entry internal directory embedded in authenticated HTML dropdowns/tables were
invisible to the scanner (its PII_KEYS had no PAN/GSTIN/Aadhaar and it never regex-scanned
authenticated HTML). This is a *disclosure analyst*, not a payload engine.

Design (reviewed by codex + grok): recall-oriented STRUCTURE matching for detection;
VOLUME + type SENSITIVITY drive severity; GSTIN chars 3-12 ARE a PAN so the embedded PAN
is de-duplicated; samples are masked (never emit raw PII).

Iteration-2 backlog (from friends' review, intentionally not in v1):
  Aadhaar Verhoeff + GSTIN checksum (for confidence/precision); placeholder & sequential
  downranking; decode base64 / \\uXXXX before match; context-window + header<->cell binding;
  log-scale volume; authz-context multiplier (unauth > low-priv IDOR > admin > own-profile);
  cross-response correlation; DPDP wording ("N data principals, M identifiers").
"""
import html
import re

# --- structure patterns (recall-oriented) ---
_PAN_RE = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')
_GSTIN_RE = re.compile(r'\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]\b')
_AADHAAR_RE = re.compile(r'\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b')
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
# Indian mobile: 10 digits 6-9 lead; lookarounds (not \b) so a 12-digit Aadhaar doesn't match
_PHONE_RE = re.compile(r'(?<![0-9])(?:\+?91[\-\s]?)?[6-9][0-9]{9}(?![0-9])')
_OPTION_RE = re.compile(r'<option\b', re.I)
_TR_RE = re.compile(r'<tr\b', re.I)

_SENSITIVE = {"pan", "gstin", "aadhaar"}   # government identifiers
_BULK_LIST_THRESHOLD = 30                  # <option>/<tr> count that signals bulk disclosure


def _mask(v):
    """first-2 + last-1, middle redacted; never returns the raw value."""
    v = v.replace(" ", "")
    if len(v) <= 3:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 3) + v[-1:]


def _severity(count, sensitive):
    if sensitive:
        if count >= 100:
            return "high"
        if count >= 10:
            return "medium"
        return "low"
    if count >= 100:
        return "medium"
    if count >= 20:
        return "low"
    return "info"


def _find(rx, text, exclude_spans=()):
    out = []
    for m in rx.finditer(text):
        s, e = m.span()
        if any(xs <= s < xe for xs, xe in exclude_spans):
            continue
        out.append((m.group(0), (s, e)))
    return out


def scan(text, url=None, content_type="text/html", allowlist=()):
    """Scan a (decoded) response body for PII + bulk-data exposure.

    Returns {'counts': {type:int}, 'samples': {type:[masked,...]}, 'findings': [..]}.
    A finding carries: type, severity, count, confidence, masked_samples, evidence, url.
    """
    if not text:
        return {"counts": {}, "samples": {}, "findings": []}
    decoded = html.unescape(text)
    allow = {a.replace(" ", "") for a in allowlist}

    # GSTIN first — its chars 3-12 are a PAN; record spans so we don't double-count the PAN.
    gstins = _find(_GSTIN_RE, decoded)
    gstin_spans = [sp for _, sp in gstins]
    pans = _find(_PAN_RE, decoded, exclude_spans=gstin_spans)
    aadhaars = _find(_AADHAAR_RE, decoded)
    emails = _find(_EMAIL_RE, decoded)
    phones = _find(_PHONE_RE, decoded, exclude_spans=[sp for _, sp in aadhaars])

    matched = {"gstin": gstins, "pan": pans, "aadhaar": aadhaars,
               "email": emails, "phone": phones}

    counts, samples, findings = {}, {}, []
    for typ, items in matched.items():
        vals = [v for v, _ in items if v.replace(" ", "") not in allow]
        if not vals:
            continue
        counts[typ] = len(vals)
        masked, seen = [], set()
        for v in vals:
            if v not in seen:
                seen.add(v)
                masked.append(_mask(v))
            if len(masked) >= 5:
                break
        samples[typ] = masked
        # emit a finding for any government identifier; for contact PII only when non-trivial
        if typ in _SENSITIVE or len(vals) >= 5:
            findings.append({
                "type": typ,
                "severity": _severity(len(vals), typ in _SENSITIVE),
                "count": len(vals),
                "confidence": "candidate",
                "masked_samples": masked,
                "evidence": f"{len(vals)} {typ.upper()} value(s) in response"
                            + (f" at {url}" if url else ""),
                "url": url,
            })

    # bulk list / directory exposure (excessive embedded records in one response)
    bulk_n = max(len(_OPTION_RE.findall(decoded)), len(_TR_RE.findall(decoded)))
    if bulk_n >= _BULK_LIST_THRESHOLD:
        findings.append({
            "type": "bulk_list_exposure",
            "severity": "high" if bulk_n >= 100 else "medium",
            "count": bulk_n,
            "confidence": "candidate",
            "masked_samples": [],
            "evidence": f"{bulk_n} embedded list entries (<option>/<tr>) in a single response"
                        + (f" at {url}" if url else "")
                        + " — possible bulk directory/record disclosure (data-minimisation)",
            "url": url,
        })

    return {"counts": counts, "samples": samples, "findings": findings}

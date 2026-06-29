"""bac_matrix — multi-user Broken Access Control / IDOR matrix.

Replay a set of requests across N authenticated CONTEXTS (roles/users), strip dynamic content
out of each response, diff every non-owner context against a designated BASELINE (owner), and
flag BAC/IDOR where a non-owner context receives substantially the owner's response.

WHY this over a 2-party differential: a lone IDOR check (owner vs one other) misses the matrix —
maker vs admin vs unauth vs a second maker, across many object refs. And a naive body-diff
false-positives on per-request dynamic content (ASP.NET __VIEWSTATE, CSRF tokens, GUIDs,
timestamps). Normalizing those out before the similarity compare is what makes the verdict
trustworthy — the same anti-fabrication discipline the rest of the engine uses.

PROVENANCE: the multi-user-replay + baseline-diff + dynamic-content-filter approach is inspired
by TokenTwin-Checker (MIT, github.com/rootdr-backup/TokenTwin-Checker), a Burp extension. This is
a clean-room reimplementation in Vikramaditya's Python idiom — no code copied; it composes the
existing detectors (bfla_scanner.classify for gating, idor_scanner for sensitive-value signals).
"""
import difflib
import html
import re

import bfla_scanner

try:
    import idor_scanner
    _sensitive_values = idor_scanner._sensitive_values
    _has_sensitive = idor_scanner._has_sensitive
except Exception:  # pragma: no cover - detectors are optional
    def _sensitive_values(_b):
        return set()

    def _has_sensitive(_b):
        return False


# Per-request DYNAMIC content stripped before comparison so two structurally-identical responses
# are not falsely "different". Covers ASP.NET WebForms tokens, anti-CSRF tokens, GUIDs, ISO/locale
# timestamps, and nonces.
_DYNAMIC_RES = [
    # whole hidden-input tags whose NAME is a per-request token (any attribute order)
    re.compile(r'<input\b[^>]*\bname="(?:__VIEWSTATE\w*|__EVENTVALIDATION|__PREVIOUSPAGE|'
               r'__RequestVerificationToken|[A-Za-z_]*(?:csrf|xsrf)[A-Za-z_]*|authenticity_token)"'
               r'[^>]*>', re.I),
    # bare token assignments in JS/JSON
    re.compile(r'(csrf[_-]?token|authenticity_token|xsrf[_-]?token)["\':=\s]+[^"\'&\s<]+', re.I),
    re.compile(r'\bnonce["\':=\s]+[^"\'&\s<]+', re.I),
    re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I),  # GUID
    re.compile(r'\b\d{1,2}[:/\-]\d{1,2}[:/\-]\d{2,4}([ T]\d{1,2}:\d{2}(:\d{2})?)?\b'),       # date/time
    re.compile(r'\b\d{10,13}\b'),                                                            # epoch ms/s
]


def _norm3(r):
    """Tolerate (status, body) or (status, body, location)."""
    return (r[0], r[1], r[2] if len(r) > 2 else "")


def normalize(body, extra_ignore=()):
    """Strip dynamic content so two responses can be compared for STRUCTURAL sameness without
    false diffs. `extra_ignore` is a list of additional regex strings (the operator's ignore list)."""
    if not body:
        return ""
    t = html.unescape(body)
    for rx in _DYNAMIC_RES:
        t = rx.sub("", t)
    for pat in extra_ignore:
        try:
            t = re.sub(pat, "", t, flags=re.I)
        except re.error:
            continue
    return re.sub(r"\s+", " ", t).strip()


def similarity(a, b, extra_ignore=()):
    """Structural similarity (0..1) of two response bodies after dynamic-content normalization."""
    na, nb = normalize(a, extra_ignore), normalize(b, extra_ignore)
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    return difflib.SequenceMatcher(None, na[:8000], nb[:8000]).ratio()


def compare(baseline, other, sim_threshold=0.95, extra_ignore=()):
    """Classify a non-owner context's access to an object vs the BASELINE (owner) response.

    baseline/other = (status, body[, location]). Returns
    {verdict: bac|safe|na, severity?, similarity, sensitive, reason}.
      * other is gated/denied (login redirect, 401/403, soft-deny, 404)  -> safe
      * baseline is not a 200 owner page                                  -> na (nothing to compare)
      * other is 200 AND ~identical to owner (>= threshold) after norm    -> BAC (high if the shared
        content carries the owner's sensitive identifiers, else medium)
      * otherwise                                                          -> safe
    """
    bs, bb, _ = _norm3(baseline)
    os_, ob, ol = _norm3(other)
    ocls = bfla_scanner.classify(os_, ob, ol)
    if ocls in ("gated", "absent"):
        return {"verdict": "safe", "similarity": 0.0, "sensitive": False,
                "reason": "non-owner context is gated/denied (%s)" % ocls}
    if bs != 200 or not bb:
        return {"verdict": "na", "similarity": 0.0, "sensitive": False,
                "reason": "baseline is not a 200 owner response"}
    sim = similarity(bb, ob, extra_ignore)
    owner_vals = _sensitive_values(bb)
    shared_sensitive = bool(owner_vals & _sensitive_values(ob))
    if os_ == 200 and sim >= sim_threshold:
        sev = "high" if (shared_sensitive or _has_sensitive(bb)) else "medium"
        return {"verdict": "bac", "severity": sev, "similarity": round(sim, 4),
                "sensitive": shared_sensitive,
                "reason": ("a non-owner context received a response ~identical to the owner's "
                           "(similarity %.3f after stripping dynamic content)%s" %
                           (sim, " carrying the owner's sensitive identifier(s)" if shared_sensitive
                            else ""))}
    return {"verdict": "safe", "similarity": round(sim, 4), "sensitive": False,
            "reason": "non-owner response differs materially (similarity %.3f)" % sim}


def run_matrix(contexts, requests, sim_threshold=0.95, extra_ignore=()):
    """Run the BAC matrix.

    contexts: list of {label, is_baseline(bool), get(callable path->(status,body[,location]))}.
              Exactly one should be baseline; if none is flagged, the first is used.
    requests: list of request paths (object refs) to replay across every context.

    For each request, the baseline (owner) response is compared against every other context;
    a 'bac' verdict yields a finding. Returns a flat list of findings:
      {type, vuln_class, severity, confidence, context, baseline, request, similarity, evidence}.
    """
    if not contexts or not requests:
        return []
    baseline = next((c for c in contexts if c.get("is_baseline")), contexts[0])
    others = [c for c in contexts if c is not baseline]
    findings = []
    for req in requests:
        try:
            base_resp = baseline["get"](req)
        except Exception:
            continue
        for ctx in others:
            try:
                resp = ctx["get"](req)
            except Exception:
                continue
            res = compare(base_resp, resp, sim_threshold=sim_threshold, extra_ignore=extra_ignore)
            if res["verdict"] == "bac":
                findings.append({
                    "type": "bac_cross_context",
                    "vuln_class": "Broken Access Control / IDOR",
                    "severity": res["severity"],
                    "confidence": "confirmed",
                    "context": ctx["label"],
                    "baseline": baseline["label"],
                    "request": req,
                    "similarity": res["similarity"],
                    "evidence": ("context '%s' received the same object as the owner '%s' at %s — %s"
                                 % (ctx["label"], baseline["label"], req, res["reason"])),
                })
    return findings

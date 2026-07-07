"""saml_xsw_tester — SAML XML Signature Wrapping (XSW1-8) forgery, extending scanner.sh Check 7 (which
already does endpoint discovery + signature stripping; XSW forgery is the gap).

v1 requires the operator to supply a captured, validly-signed SAMLResponse —
without one, XSW forgery is meaningless (there is nothing valid to wrap), so
this module degrades gracefully rather than attempt it against a synthetic
unsigned assertion.
"""
import base64
import os

from lxml import etree

import saml_xsw_tester as sx

_SAMPLE_RESPONSE = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">
  <saml:Assertion ID="_assertion1">
    <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo/><ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>"""

_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
_ATTACKER = "attacker@evil.example"


def test_load_captured_assertion_missing_file_returns_none(tmp_path):
    assert sx.load_captured_assertion(str(tmp_path / "missing.xml")) is None


def test_load_captured_assertion_reads_file(tmp_path):
    path = tmp_path / "captured.xml"
    path.write_text(_SAMPLE_RESPONSE)
    assert "alice@example.com" in sx.load_captured_assertion(str(path))


def test_generate_xsw_variants_produces_all_eight():
    variants = sx.generate_xsw_variants(_SAMPLE_RESPONSE)
    assert set(variants.keys()) == {f"XSW{i}" for i in range(1, 9)}
    for xml in variants.values():
        assert "alice@example.com" in xml or "attacker@evil.example" in xml


def test_xsw1_duplicates_assertion_with_attacker_subject():
    variants = sx.generate_xsw_variants(_SAMPLE_RESPONSE)
    assert variants["XSW1"].count("<saml:Assertion") == 2
    assert "attacker@evil.example" in variants["XSW1"]


def test_xsw3_relocates_original_signature_to_response_root():
    """XSW3 must physically move the ORIGINAL assertion's real ds:Signature
    so it is a direct child of the Response element (a sibling of both
    assertions), not merely wear a marker attribute."""
    variants = sx.generate_xsw_variants(_SAMPLE_RESPONSE)
    root = etree.fromstring(variants["XSW3"].encode())

    # No assertion (forged or original) may retain the signature as a
    # descendant any more.
    assert root.find(".//saml:Assertion//ds:Signature", namespaces=_NS) is None

    # The signature must be a DIRECT child of the Response root.
    direct_sig_children = root.findall("./ds:Signature", namespaces=_NS)
    assert len(direct_sig_children) == 1


def test_xsw4_relocates_forged_signature_leaving_original_signed():
    """XSW4 must be a genuinely different mechanic from XSW3: it relocates
    the FORGED copy's signature (leaving the original assertion's own
    signature untouched in place), whereas XSW3 relocates the original's."""
    variants = sx.generate_xsw_variants(_SAMPLE_RESPONSE)
    root = etree.fromstring(variants["XSW4"].encode())

    assertions = root.findall("./saml:Assertion", namespaces=_NS)
    assert len(assertions) == 2
    sig_counts = sorted(
        len(a.findall("./ds:Signature", namespaces=_NS)) for a in assertions
    )
    # Exactly one assertion (the original) still has its own signature
    # child; the other (forged) has none because its copy was relocated.
    assert sig_counts == [0, 1]
    assert len(root.findall("./ds:Signature", namespaces=_NS)) == 1


def test_xsw5_and_xsw6_use_different_node_mechanisms():
    """XSW5 (comment node) and XSW6 (CDATA text node) must use genuinely
    different DOM/serialization mechanisms, not just different strings
    inside the same escaped-text trick."""
    variants = sx.generate_xsw_variants(_SAMPLE_RESPONSE)

    assert "<!--" in variants["XSW5"]
    assert "<![CDATA[" not in variants["XSW5"]

    assert "<![CDATA[" in variants["XSW6"]
    assert "<!--" not in variants["XSW6"]

    # Confirm via the parsed DOM: XSW5's forged NameID (first in document
    # order, since the forged copy is inserted before the original) has a
    # genuine etree.Comment child node carrying the attacker identity.
    root5 = etree.fromstring(variants["XSW5"].encode())
    forged_nameid5 = root5.findall(".//saml:NameID", namespaces=_NS)[0]
    comment_children = [c for c in forged_nameid5 if c.tag is etree.Comment]
    assert len(comment_children) == 1
    assert _ATTACKER in comment_children[0].text
    assert forged_nameid5.text == "legit-user"


def test_xsw7_and_xsw8_use_alternate_namespace_prefix_for_forged_assertion():
    """XSW7/XSW8's forged assertion must genuinely use a namespace prefix
    other than `saml:` while still resolving to the real SAML assertion
    namespace URI -- not an arbitrary attribute with no namespace effect."""
    variants = sx.generate_xsw_variants(_SAMPLE_RESPONSE)

    # XSW7: aliased prefix `s2:`, inserted BEFORE the original.
    assert "<s2:Assertion" in variants["XSW7"]
    assert 'xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"' in variants["XSW7"]
    assert variants["XSW7"].count("<saml:Assertion") == 1
    assert variants["XSW7"].index("<s2:Assertion") < variants["XSW7"].index("<saml:Assertion")

    # XSW8: a DIFFERENT aliased prefix `s3:`, inserted AFTER the original.
    assert "<s3:Assertion" in variants["XSW8"]
    assert 'xmlns:s3="urn:oasis:names:tc:SAML:2.0:assertion"' in variants["XSW8"]
    assert variants["XSW8"].count("<saml:Assertion") == 1
    assert variants["XSW8"].index("<saml:Assertion") < variants["XSW8"].index("<s3:Assertion")

    # Confirm the aliased tags still resolve to the real SAML assertion
    # namespace URI (Clark notation is prefix-independent) while their
    # serialized prefix genuinely differs from `saml`.
    root7 = etree.fromstring(variants["XSW7"].encode())
    aliased7 = root7.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    assert len(aliased7) == 2
    assert {a.prefix for a in aliased7} == {"s2", "saml"}


class _FakeResponse:
    def __init__(self, status_code, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class _FakeClient:
    def __init__(self, acs_response, resource_response):
        self._acs_response = acs_response
        self._resource_response = resource_response
        self.cookies_sent = None

    def post(self, url, **kwargs):
        return self._acs_response

    def get(self, url, **kwargs):
        self.cookies_sent = kwargs.get("cookies")
        return self._resource_response


def test_confirm_new_session_true_when_protected_resource_returns_identity_content():
    acs_resp = _FakeResponse(302, headers={"Set-Cookie": "session=abc123"})
    resource_resp = _FakeResponse(200, text="Welcome, attacker@evil.example")
    client = _FakeClient(acs_resp, resource_resp)
    result = sx.confirm_new_session(client, "https://sp.example.com/acs",
                                     base64.b64encode(b"<forged/>").decode(),
                                     "https://sp.example.com/whoami")
    assert result.confirmed is True


def test_confirm_new_session_replays_the_real_cookie_name_not_a_literal_raw_key():
    # A dict keyed "raw" sends a cookie literally named "raw" (httpx/requests/
    # curl_cffi all build the Cookie header verbatim from dict keys) -- the
    # follow-up must split "name=value" apart so the real cookie name/value
    # actually reach the target's session check.
    acs_resp = _FakeResponse(302, headers={"Set-Cookie": "session=abc123"})
    resource_resp = _FakeResponse(200, text="Welcome, attacker@evil.example")
    client = _FakeClient(acs_resp, resource_resp)
    sx.confirm_new_session(client, "https://sp.example.com/acs",
                            base64.b64encode(b"<forged/>").decode(),
                            "https://sp.example.com/whoami")
    assert client.cookies_sent == {"session": "abc123"}


def test_confirm_new_session_false_when_resource_redirects_to_login():
    acs_resp = _FakeResponse(302, headers={"Set-Cookie": "session=abc123"})
    resource_resp = _FakeResponse(302, headers={"Location": "https://sp.example.com/login"})
    client = _FakeClient(acs_resp, resource_resp)
    result = sx.confirm_new_session(client, "https://sp.example.com/acs",
                                     base64.b64encode(b"<forged/>").decode(),
                                     "https://sp.example.com/whoami")
    assert result.confirmed is False


def test_confirm_new_session_false_when_no_session_cookie_set():
    acs_resp = _FakeResponse(200)
    resource_resp = _FakeResponse(200, text="Welcome")
    client = _FakeClient(acs_resp, resource_resp)
    result = sx.confirm_new_session(client, "https://sp.example.com/acs",
                                     base64.b64encode(b"<forged/>").decode(),
                                     "https://sp.example.com/whoami")
    assert result.confirmed is False

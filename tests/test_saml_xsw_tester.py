"""saml_xsw_tester — SAML XML Signature Wrapping (XSW1-8) forgery, extending scanner.sh Check 7 (which
already does endpoint discovery + signature stripping; XSW forgery is the gap).

v1 requires the operator to supply a captured, validly-signed SAMLResponse —
without one, XSW forgery is meaningless (there is nothing valid to wrap), so
this module degrades gracefully rather than attempt it against a synthetic
unsigned assertion.
"""
import base64
import os

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

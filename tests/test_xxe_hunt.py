"""xxe_hunt — content-type-swap and upload-vector XXE probing.

FP gate: a parser error alone is a [XXE-CANDIDATE] lead, never a confirmed
finding. Only in-band file-marker content or a correlated OOB callback confirms.
"""
import xxe_hunt as xh


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.headers = {}


class _FakeClient:
    def __init__(self, response):
        self._response = response
        self.last_request = None

    def post(self, url, **kwargs):
        self.last_request = (url, kwargs)
        return self._response


def test_content_type_swap_builds_xml_entity_payload():
    client = _FakeClient(_FakeResponse(200, "no marker here"))
    xh.probe_content_type_swap(client, "https://example.com/api/user", {"name": "x"})
    url, kwargs = client.last_request
    assert kwargs["headers"]["Content-Type"] == "application/xml"
    assert "<!ENTITY" in kwargs["data"]


def test_content_type_swap_confirms_on_in_band_file_marker():
    client = _FakeClient(_FakeResponse(200, "root:x:0:0:root:/root:/bin/bash"))
    result = xh.probe_content_type_swap(client, "https://example.com/api/user", {"name": "x"})
    assert result.verdict == "confirmed"
    assert "in-band" in result.evidence.lower()


def test_content_type_swap_candidate_on_parser_error_only():
    client = _FakeClient(_FakeResponse(500, "XML parsing error: undefined entity"))
    result = xh.probe_content_type_swap(client, "https://example.com/api/user", {"name": "x"})
    assert result.verdict == "candidate"


def test_content_type_swap_clean_on_no_signal():
    client = _FakeClient(_FakeResponse(400, "bad request"))
    result = xh.probe_content_type_swap(client, "https://example.com/api/user", {"name": "x"})
    assert result.verdict == "clean"


def test_upload_xxe_svg_payload_contains_entity_and_reasonable_dimensions():
    client = _FakeClient(_FakeResponse(200, ""))
    xh.probe_upload_xxe(client, "https://example.com/upload", doc_type="svg")
    url, kwargs = client.last_request
    body = kwargs["files"]["file"][1]
    assert b"<!ENTITY" in body
    assert b"<svg" in body


def test_upload_xxe_candidate_on_parser_error_with_error_status():
    client = _FakeClient(_FakeResponse(400, "XML parsing error: undefined entity"))
    result = xh.probe_upload_xxe(client, "https://example.com/upload", doc_type="svg")
    assert result.verdict == "candidate"


def test_upload_xxe_clean_when_parser_error_text_but_200_status():
    # A 200 response containing marker-like text (e.g. an unrelated generic
    # form-validation message) must NOT be tagged "candidate" — there is no
    # real error signal without an error-class status code.
    client = _FakeClient(_FakeResponse(200, "XML parsing error: undefined entity"))
    result = xh.probe_upload_xxe(client, "https://example.com/upload", doc_type="svg")
    assert result.verdict == "clean"


def test_upload_xxe_unsupported_doc_type_returns_clean_not_raise():
    client = _FakeClient(_FakeResponse(200, ""))
    result = xh.probe_upload_xxe(client, "https://example.com/upload", doc_type="docx")
    assert result.verdict == "clean"
    assert "docx" in result.evidence.lower()
    assert client.last_request is None


def test_blind_oob_confirms_on_matching_callback():
    class _Session:
        url = "https://tok123.interact.sh"
        def poll_callbacks(self, token):
            return [{"full-id": f"{token}.interact.sh", "protocol": "http"}]

    result = xh.confirm_blind_oob(_Session(), token="tok123")
    assert result.verdict == "confirmed"
    assert "oob" in result.evidence.lower()


def test_blind_oob_candidate_when_no_callback():
    class _Session:
        def poll_callbacks(self, token):
            return []

    result = xh.confirm_blind_oob(_Session(), token="tok123")
    assert result.verdict == "candidate"

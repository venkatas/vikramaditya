"""AuthSession.request must distinguish a TRANSPORT failure from an absent
endpoint.

friends full-tool review F14: request() collapsed every exception (TLS-verify
failure, timeout, connection reset) to ``{"status": 0}``. Consumers test
``status in (200, 201)``, so a systematic transport failure (e.g. a bad/expired
bearer, a proxy outage) made every request look like a benign non-hit and the
scan completed with 0 findings and NO signal that coverage was lost. A transport
error must be marked distinctly and counted so the lost coverage is visible.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import auth_utils  # noqa: E402


class _Boom:
    headers: dict = {}
    cookies: dict = {}

    def request(self, *a, **k):
        raise RuntimeError("TLSError: certificate verify failed")


class _Resp404:
    status_code = 404
    headers: dict = {}
    text = "not found"

    def json(self):
        raise ValueError("no json")


class _NotFound:
    headers: dict = {}
    cookies: dict = {}

    def request(self, *a, **k):
        return _Resp404()


def _session(fake):
    s = auth_utils.AuthSession("https://t.example.invalid")
    s._session = fake
    s._limiter.wait = lambda: None   # no rate-limit sleep in tests
    return s


def test_transport_error_is_marked_and_counted():
    s = _session(_Boom())
    r = s.request("GET", "/x")
    assert r["status"] == 0
    assert r.get("transport_error") is True, (
        "a transport failure must be distinguishable from an absent endpoint")
    assert s.transport_errors >= 1, "transport failures must be counted on the session"


def test_real_404_is_not_a_transport_error():
    s = _session(_NotFound())
    r = s.request("GET", "/x")
    assert r["status"] == 404
    assert not r.get("transport_error"), (
        "a real HTTP 404 is an absent endpoint, NOT a transport/coverage failure")
    assert s.transport_errors == 0

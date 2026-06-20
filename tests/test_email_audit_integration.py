"""Regression tests for v7.2.0 — email_audit integration.

Three invariants to pin:

1. **Pure functions** — the parsing primitives that ride the DNS/SMTP
   responses (``parse_kv_record``, ``normalize_target``,
   ``relaxed_aligns``, ``is_privateish_ip``, ``estimate_dkim_rsa_bits``)
   must behave correctly without any network access. These are the
   high-risk bits — DER parsing especially.
2. **Integration hook** — ``hunt.py::run_email_audit`` must be importable
   and respect the IP/CIDR bypass.
3. **No regressions** — rest of the test suite still green with the new
   module in place.
"""

from __future__ import annotations

import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import email_audit


# ---------------------------------------------------------------------------
# Pure parsers — no network
# ---------------------------------------------------------------------------


class TestParseKVRecord:
    """``parse_kv_record`` splits on ``;`` only — it's the DMARC/DKIM
    parser, not the SPF one. SPF's space-separated tokens collapse into
    a single ``v=...`` value (which is the correct behaviour — the SPF
    record is parsed elsewhere via ``estimate_spf_lookups``)."""

    def test_dmarc_record_splits_semicolons(self) -> None:
        out = email_audit.parse_kv_record("v=DMARC1; p=reject; rua=mailto:x@y.com; adkim=s")
        assert out["v"] == "DMARC1"
        assert out["p"] == "reject"
        assert out["rua"] == "mailto:x@y.com"
        assert out["adkim"] == "s"

    def test_dkim_record_splits_semicolons(self) -> None:
        out = email_audit.parse_kv_record("v=DKIM1; k=rsa; p=MIIBIjANBg...")
        assert out["v"] == "DKIM1"
        assert out["k"] == "rsa"

    def test_spf_stays_one_key(self) -> None:
        # parse_kv_record is not the SPF parser — the whole tail lands in ``v``.
        out = email_audit.parse_kv_record("v=spf1 ip4:1.2.3.4 ~all")
        assert out["v"] == "spf1 ip4:1.2.3.4 ~all"


class TestNormalizeTarget:
    def test_domain(self) -> None:
        kind, target, email_addr = email_audit.normalize_target("target.com")
        assert kind == "domain"
        assert target == "target.com"
        assert email_addr is None

    def test_email_address(self) -> None:
        # normalize_target returns (kind, dns_target_domain, local_part).
        # The local-part slot is named ``email`` in the source but carries
        # only the name-before-@, not the full address.
        kind, target, local_part = email_audit.normalize_target("alice@target.com")
        assert kind == "email"
        assert target == "target.com"
        assert local_part == "alice"

    def test_uppercase_normalised_to_lower(self) -> None:
        kind, target, _ = email_audit.normalize_target("TARGET.COM")
        assert target == "target.com"


class TestRelaxedAligns:
    def test_exact_match_aligns(self) -> None:
        assert email_audit.relaxed_aligns("a.target.com", "a.target.com") is True

    def test_subdomain_relaxed_alignment(self) -> None:
        assert email_audit.relaxed_aligns("sub.target.com", "target.com") is True

    def test_different_org_domains(self) -> None:
        assert email_audit.relaxed_aligns("target.com", "other.com") is False

    def test_none_inputs(self) -> None:
        assert email_audit.relaxed_aligns(None, "x") is False
        assert email_audit.relaxed_aligns("x", None) is False


class TestIsPrivateishIP:
    def test_rfc1918_private(self) -> None:
        assert email_audit.is_privateish_ip("10.0.0.5") is True
        assert email_audit.is_privateish_ip("192.168.1.1") is True
        assert email_audit.is_privateish_ip("172.16.5.5") is True

    def test_loopback(self) -> None:
        assert email_audit.is_privateish_ip("127.0.0.1") is True

    def test_public_ip(self) -> None:
        assert email_audit.is_privateish_ip("8.8.8.8") is False

    def test_garbage_string(self) -> None:
        assert email_audit.is_privateish_ip("not-an-ip") is False


class TestEstimateDKIMRSABits:
    """DER parsing for DKIM public-key length extraction.

    Generates a fake RSA-2048 pubkey structure, base64-wraps it, and
    verifies the bit-count is recovered. This pins the DER walker —
    the bit in subspace-sentinel most likely to silently misread on
    unusual key shapes.
    """

    @staticmethod
    def _fake_rsa_pubkey(modulus_bits: int) -> str:
        # ASN.1 DER for:
        #   SEQUENCE {
        #       SEQUENCE { OID rsaEncryption, NULL }
        #       BIT STRING {
        #           SEQUENCE { INTEGER modulus, INTEGER exponent }
        #       }
        #   }
        # The audit walker only needs the innermost SEQUENCE → INTEGER
        # modulus length in bits. We feed it a minimal valid shape.
        modulus = (b"\xff" * (modulus_bits // 8))
        # INTEGER <len><modulus>; prefix 0x00 if top bit set to keep it unsigned.
        integer_body = b"\x00" + modulus
        length_bytes = _der_length_bytes(len(integer_body))
        modulus_integer = b"\x02" + length_bytes + integer_body
        exp_integer = b"\x02\x03\x01\x00\x01"
        inner_seq = modulus_integer + exp_integer
        inner_seq_full = b"\x30" + _der_length_bytes(len(inner_seq)) + inner_seq
        # BIT STRING: 0x03 <len> 00 <payload>
        bitstr_body = b"\x00" + inner_seq_full
        bitstr = b"\x03" + _der_length_bytes(len(bitstr_body)) + bitstr_body
        # Algorithm identifier prefix
        alg = bytes.fromhex("30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00".replace(" ", ""))
        outer_body = alg + bitstr
        outer = b"\x30" + _der_length_bytes(len(outer_body)) + outer_body
        return base64.b64encode(outer).decode("ascii")

    def test_2048_bit_key_recovered(self) -> None:
        b64 = self._fake_rsa_pubkey(2048)
        bits = email_audit.estimate_dkim_rsa_bits(b64)
        assert bits == 2048

    def test_1024_bit_key_recovered(self) -> None:
        b64 = self._fake_rsa_pubkey(1024)
        bits = email_audit.estimate_dkim_rsa_bits(b64)
        assert bits == 1024

    def test_garbage_base64_returns_none(self) -> None:
        assert email_audit.estimate_dkim_rsa_bits("not valid base64 !@#") is None

    @staticmethod
    def _nested_recursion_der(levels: int) -> str:
        # v10.6.0 regression — build a maliciously deep SPKI-like structure
        # where each level is SEQUENCE { SEQUENCE(alg) , BIT STRING { <next> } }
        # so estimate_dkim_rsa_bits recurses on the BIT STRING payload at every
        # level. Without a depth bound this overflows Python's recursion limit
        # and raises an uncaught RecursionError that aborts the whole audit.
        alg = bytes.fromhex("300D06092A864886F70D0101010500")

        def wrap(inner: bytes) -> bytes:
            bitstr_body = b"\x00" + inner
            bitstr = b"\x03" + _der_length_bytes(len(bitstr_body)) + bitstr_body
            outer_body = alg + bitstr
            return b"\x30" + _der_length_bytes(len(outer_body)) + outer_body

        # Innermost payload: a small INTEGER so a (hypothetically) un-bounded
        # walk would terminate normally — proving the bound, not bad input.
        node = b"\x30\x06\x02\x01\x01\x02\x01\x01"
        for _ in range(levels):
            node = wrap(node)
        return base64.b64encode(node).decode("ascii")

    def test_deeply_nested_der_does_not_raise(self) -> None:
        # Far deeper than Python's recursion limit would tolerate unbounded.
        b64 = self._nested_recursion_der(2000)
        # Must return cleanly (None), never raise RecursionError.
        assert email_audit.estimate_dkim_rsa_bits(b64) is None

    def test_depth_bound_rejects_beyond_cap(self) -> None:
        # A structure nested past the cap degrades to None instead of crashing.
        b64 = self._nested_recursion_der(10)
        assert email_audit.estimate_dkim_rsa_bits(b64) is None


def _der_length_bytes(n: int) -> bytes:
    """Encode an ASN.1 DER length."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


class TestFetchUrlTextHardening:
    """v10.6.0 — MTA-STS policy fetch must bound the response body and refuse
    redirects, since the policy host (mta-sts.<domain>) is target-controlled."""

    class _FakeResp:
        def __init__(self, payload: bytes):
            self._payload = payload

        def read(self, n=-1):
            return self._payload[:n] if n is not None and n >= 0 else self._payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def test_oversized_body_rejected(self, monkeypatch) -> None:
        huge = b"a" * (email_audit.MTA_STS_MAX_BODY_BYTES + 100)
        monkeypatch.setattr(
            email_audit._NO_REDIRECT_OPENER, "open",
            lambda *a, **k: self._FakeResp(huge),
        )
        body, err = email_audit.fetch_url_text("https://mta-sts.acme.invalid/p", 5.0)
        assert body is None
        assert err == "policy body exceeds size limit"

    def test_normal_body_returned(self, monkeypatch) -> None:
        payload = b"version: STSv1\nmode: enforce\nmx: mail.acme.invalid\nmax_age: 86400\n"
        monkeypatch.setattr(
            email_audit._NO_REDIRECT_OPENER, "open",
            lambda *a, **k: self._FakeResp(payload),
        )
        body, err = email_audit.fetch_url_text("https://mta-sts.acme.invalid/p", 5.0)
        assert err is None
        assert "mode: enforce" in body

    def test_redirect_handler_rejects(self) -> None:
        import urllib.request
        handler = email_audit._RejectRedirectHandler()
        req = urllib.request.Request("https://mta-sts.acme.invalid/p")
        with pytest.raises(Exception):
            handler.redirect_request(
                req, None, 302, "Found", {}, "https://evil.invalid/elsewhere"
            )


# ---------------------------------------------------------------------------
# hunt.py integration hook
# ---------------------------------------------------------------------------


class TestHuntIntegration:
    def test_run_email_audit_importable(self) -> None:
        """The hook function should exist and be callable."""
        import hunt
        assert hasattr(hunt, "run_email_audit")
        assert callable(hunt.run_email_audit)

    def test_ip_target_skipped(self, tmp_path, monkeypatch) -> None:
        """IP/CIDR targets must short-circuit — SPF/DMARC are hostname-scoped."""
        import hunt
        monkeypatch.setattr(hunt, "_brain", None)
        calls = []
        orig_run_cmd = hunt.run_cmd
        def tracker(cmd, *a, **kw):
            calls.append(cmd)
            return orig_run_cmd(cmd, *a, **kw)
        monkeypatch.setattr(hunt, "run_cmd", tracker)
        ok = hunt.run_email_audit("203.0.113.10")
        assert ok is True
        # No subprocess invocations for an IP target.
        assert len(calls) == 0

    def test_cidr_target_skipped(self, monkeypatch) -> None:
        import hunt
        monkeypatch.setattr(hunt, "_brain", None)
        calls = []
        monkeypatch.setattr(hunt, "run_cmd",
                            lambda c, *a, **k: calls.append(c) or (True, ""))
        ok = hunt.run_email_audit("10.0.0.0/24")
        assert ok is True
        assert calls == []


# ---------------------------------------------------------------------------
# commands/email-audit.md present
# ---------------------------------------------------------------------------


class TestCommandDocShipped:
    def test_command_file_exists(self) -> None:
        path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "commands", "email-audit.md"))
        assert os.path.isfile(path), "commands/email-audit.md must ship with v7.2.0"

    def test_command_doc_has_required_sections(self) -> None:
        path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "commands", "email-audit.md"))
        body = open(path).read()
        for marker in ("SPF", "DMARC", "DKIM", "MTA-STS", "DNSSEC", "Usage"):
            assert marker in body, f"command doc missing required section: {marker}"

"""Tests for the llm_anon package — regex detector, surrogates, vault, anonymiser.

These tests enforce the key invariant of the anonymiser: **no string from
``must_leak_anonymized`` may survive anonymisation of a pentest-shaped
fixture**. Unit tests cover surrogate determinism and vault round-trips.
"""

from __future__ import annotations

import ipaddress
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from llm_anon import Anonymizer, RegexDetector, SurrogateGenerator, Vault
from llm_anon.regex_detector import (
    AWS_KEY, DOMAIN, EMAIL, HASH_MD5, HASH_NTLM, HASH_SHA256, IPV4, IPV4_CIDR,
    JWT, MAC,
)


# ---------------------------------------------------------------------------
# RegexDetector
# ---------------------------------------------------------------------------


class TestRegexDetector:
    def setup_method(self) -> None:
        self.d = RegexDetector()

    def test_detect_ipv4(self) -> None:
        hits = self.d.detect("scanning 10.20.0.10 and 192.168.1.1")
        values = {h.value for h in hits}
        assert "10.20.0.10" in values
        assert "192.168.1.1" in values
        assert all(h.entity == IPV4 for h in hits)

    def test_cidr_beats_ipv4(self) -> None:
        hits = self.d.detect("subnet 10.0.0.0/16 is interesting")
        assert len(hits) == 1
        assert hits[0].entity == IPV4_CIDR
        assert hits[0].value == "10.0.0.0/16"

    def test_detect_ntlm_hash(self) -> None:
        ntlm = "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        hits = self.d.detect(f"hash: {ntlm}")
        assert len(hits) == 1
        assert hits[0].entity == HASH_NTLM

    def test_ntlm_wins_over_two_md5s(self) -> None:
        """Order matters: NTLM is more specific than two adjacent MD5s."""
        ntlm = "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        hits = self.d.detect(ntlm)
        entities = [h.entity for h in hits]
        assert HASH_NTLM in entities
        assert HASH_MD5 not in entities

    def test_sha256_not_mistaken_for_md5(self) -> None:
        sha = "a" * 64
        hits = self.d.detect(sha)
        assert len(hits) == 1
        assert hits[0].entity == HASH_SHA256

    def test_detect_email_and_domain(self) -> None:
        hits = self.d.detect("contact john@contoso.local about DC01")
        entities = {h.entity for h in hits}
        assert EMAIL in entities
        # The bare "contoso.local" inside the email must not be double-matched
        # as a DOMAIN — offsets collide, regex resolves via overlap rules.
        email_hit = next(h for h in hits if h.entity == EMAIL)
        assert email_hit.value == "john@contoso.local"

    def test_detect_mac(self) -> None:
        hits = self.d.detect("device MAC aa:bb:cc:dd:ee:ff")
        assert any(h.entity == MAC and h.value == "aa:bb:cc:dd:ee:ff" for h in hits)

    def test_aws_key(self) -> None:
        hits = self.d.detect("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
        assert any(h.entity == AWS_KEY and h.value == "AKIAIOSFODNN7EXAMPLE" for h in hits)

    def test_jwt(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signaturePart123456"
        hits = self.d.detect(f"Authorization: Bearer {jwt}")
        assert any(h.entity == JWT and h.value == jwt for h in hits)

    def test_never_anonymize_list(self) -> None:
        hits = self.d.detect("see example.com and localhost")
        domains = {h.value for h in hits if h.entity == DOMAIN}
        assert "example.com" not in domains
        assert "localhost" not in domains


# ---------------------------------------------------------------------------
# SurrogateGenerator
# ---------------------------------------------------------------------------


class TestSurrogates:
    def setup_method(self) -> None:
        self.g = SurrogateGenerator()

    def test_ipv4_surrogate_is_in_test_net(self) -> None:
        out = self.g.generate(IPV4, "10.20.0.10")
        ip = ipaddress.IPv4Address(out)
        in_test_net = any(ip in net for net in (
            ipaddress.IPv4Network("192.0.2.0/24"),
            ipaddress.IPv4Network("198.51.100.0/24"),
            ipaddress.IPv4Network("203.0.113.0/24"),
        ))
        assert in_test_net, f"{out} must fall in RFC 5737 TEST-NET"

    def test_ipv4_surrogate_is_deterministic(self) -> None:
        a = self.g.generate(IPV4, "10.20.0.10")
        b = self.g.generate(IPV4, "10.20.0.10")
        assert a == b

    def test_ipv4_surrogates_differ_for_different_inputs(self) -> None:
        a = self.g.generate(IPV4, "10.20.0.10")
        b = self.g.generate(IPV4, "10.20.0.11")
        # Not a hard guarantee (254-host TEST-NET) but exceedingly unlikely.
        assert a != b

    def test_domain_surrogate_ends_in_pentest_local(self) -> None:
        out = self.g.generate(DOMAIN, "dc01.contoso.local")
        assert out.endswith(".pentest.local")

    def test_hash_surrogate_preserves_length(self) -> None:
        out = self.g.generate(HASH_SHA256, "a" * 64)
        assert len(out) == 64
        assert all(c in "0123456789abcdef" for c in out)

    def test_ntlm_surrogate_has_colon(self) -> None:
        out = self.g.generate(HASH_NTLM,
                              "aad3b435b51404eeaad3b435b51404ee:" + "a" * 32)
        assert ":" in out
        lm, nt = out.split(":")
        assert len(lm) == 32 and len(nt) == 32


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


@pytest.fixture
def vault(tmp_path) -> Vault:
    return Vault(tmp_path / "vault.db", engagement_id="test-eng")


class TestVault:
    def test_put_then_get(self, vault: Vault) -> None:
        vault.put(IPV4, "10.20.0.10", "203.0.113.42")
        assert vault.get_surrogate(IPV4, "10.20.0.10") == "203.0.113.42"

    def test_get_original_reverse_lookup(self, vault: Vault) -> None:
        vault.put(IPV4, "10.20.0.10", "203.0.113.42")
        assert vault.get_original("203.0.113.42") == "10.20.0.10"

    def test_put_is_idempotent(self, vault: Vault) -> None:
        vault.put(IPV4, "10.20.0.10", "203.0.113.42")
        vault.put(IPV4, "10.20.0.10", "198.51.100.1")  # should be ignored
        assert vault.get_surrogate(IPV4, "10.20.0.10") == "203.0.113.42"

    def test_engagement_isolation(self, tmp_path) -> None:
        v1 = Vault(tmp_path / "vault.db", engagement_id="client-a")
        v2 = Vault(tmp_path / "vault.db", engagement_id="client-b")
        v1.put(IPV4, "10.20.0.10", "203.0.113.42")
        assert v2.get_surrogate(IPV4, "10.20.0.10") is None

    def test_stats_histogram(self, vault: Vault) -> None:
        vault.put(IPV4, "10.20.0.10", "203.0.113.42")
        vault.put(IPV4, "10.20.0.11", "203.0.113.43")
        vault.put(DOMAIN, "x.y", "a.b.pentest.local")
        s = vault.stats()
        assert s == {IPV4: 2, DOMAIN: 1}

    def test_clear(self, vault: Vault) -> None:
        vault.put(IPV4, "10.20.0.10", "203.0.113.42")
        assert vault.clear() == 1
        assert vault.get_surrogate(IPV4, "10.20.0.10") is None


# ---------------------------------------------------------------------------
# Anonymizer — integration
# ---------------------------------------------------------------------------


@pytest.fixture
def anon(vault: Vault) -> Anonymizer:
    return Anonymizer(vault)


class TestAnonymizer:
    def test_roundtrip(self, anon: Anonymizer) -> None:
        text = "nmap scan of 10.20.0.10 on dc01.contoso.local returned OpenSSH 8.2"
        anonymized = anon.anonymize(text)
        assert "10.20.0.10" not in anonymized
        assert "contoso.local" not in anonymized
        restored = anon.deanonymize(anonymized)
        assert restored == text

    def test_repeated_entities_share_surrogate(self, anon: Anonymizer) -> None:
        text = "10.20.0.10 again 10.20.0.10 and 10.20.0.10"
        anonymized = anon.anonymize(text)
        # All three occurrences map to the same surrogate.
        parts = anonymized.split()
        ip_surrogates = [p for p in parts if "." in p and p.count(".") == 3]
        assert len(set(ip_surrogates)) == 1

    def test_must_not_leak_pentest_fixture(self, anon: Anonymizer) -> None:
        """Realistic output from crackmapexec-like scan must not leak originals."""
        fixture = """\
SMB         10.20.0.10    445    DC01             [*] Windows Server 2019
SMB         10.20.0.10    445    DC01             [+] CONTOSO\\admin:Summer2024!
NTLM hash: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
Contact:   john.smith@contoso.local
AWS key:   AKIAIOSFODNN7EXAMPLE
"""
        must_leak = [
            "10.20.0.10",
            "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "john.smith@contoso.local",
            "AKIAIOSFODNN7EXAMPLE",
        ]
        anonymized = anon.anonymize(fixture)
        for secret in must_leak:
            assert secret not in anonymized, f"LEAKED: {secret!r}"

    def test_safe_tokens_preserved(self, anon: Anonymizer) -> None:
        """Protocol / tool names / ports must survive anonymisation untouched."""
        text = "SMB 445 and HTTP 8080 via example.com"
        anonymized = anon.anonymize(text)
        assert "SMB" in anonymized and "445" in anonymized
        assert "HTTP" in anonymized and "8080" in anonymized
        assert "example.com" in anonymized  # documentation TLD

    def test_stats_after_anonymise(self, anon: Anonymizer) -> None:
        anon.anonymize("10.20.0.10 and 10.20.0.11 and dc01.contoso.local")
        s = anon.stats()
        assert s.get(IPV4, 0) >= 2
        assert s.get(DOMAIN, 0) >= 1

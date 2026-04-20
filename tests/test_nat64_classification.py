"""Regression tests for v7.4.2 — NAT64 false-positive fix.

Dogfooding the email_audit tool on ``gov.in`` produced 6 HIGH
"MX host resolves to a non-public IP" findings. Every one was a
false positive — the MX hosts (mx / mx2 / mx3 @ mgovcloud.in) were
reachable via the RFC 6052 NAT64 well-known prefix
``64:ff9b::/96``, which decodes to a publicly routable IPv4
address (``169.148.142.75``). Python's ``ipaddress.is_reserved``
flag is True for that prefix, but the addresses are reachable by
any IPv6 client on the internet — that's the entire point of NAT64.

Pre-v7.4.2 behaviour would have burned the engagement trust budget:
filing 6 HIGH findings against a prod mail server that's actually
configured correctly.

The fix decodes the embedded IPv4 from the low 32 bits and answers
based on *that* address's routability — the same semantics NAT64
gateways implement.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_audit import is_privateish_ip


class TestNAT64CarveOut:
    """RFC 6052 well-known prefix ``64:ff9b::/96``."""

    def test_nat64_public_ipv4_not_flagged(self) -> None:
        """The exact address that caused the gov.in FP."""
        # Embedded: 169.148.142.75 (public)
        assert is_privateish_ip("64:ff9b::a994:8e4b") is False

    def test_nat64_adjacent_public_ipv4_not_flagged(self) -> None:
        """Sibling of the gov.in MX host — same behaviour."""
        # Embedded: 169.148.142.74 (public)
        assert is_privateish_ip("64:ff9b::a994:8e4a") is False

    def test_nat64_public_cloudflare_dns_not_flagged(self) -> None:
        """Any publicly-routable IPv4 via NAT64 must pass."""
        # Embedded: 1.1.1.1 (Cloudflare public DNS)
        assert is_privateish_ip("64:ff9b::0101:0101") is False

    def test_nat64_public_google_dns_not_flagged(self) -> None:
        # Embedded: 8.8.8.8
        assert is_privateish_ip("64:ff9b::0808:0808") is False

    def test_nat64_rfc1918_private_still_flagged(self) -> None:
        """NAT64 with a PRIVATE embedded IPv4 IS non-public."""
        # Embedded: 10.0.0.1 (RFC1918)
        assert is_privateish_ip("64:ff9b::a00:1") is True

    def test_nat64_rfc1918_172_range_flagged(self) -> None:
        # Embedded: 172.16.5.10
        assert is_privateish_ip("64:ff9b::ac10:050a") is True

    def test_nat64_loopback_embedded_flagged(self) -> None:
        # Embedded: 127.0.0.1
        assert is_privateish_ip("64:ff9b::7f00:1") is True


class TestPrivateIPBehaviourUnchanged:
    """Standard classifications must survive the NAT64 carve-out."""

    def test_rfc1918_still_private(self) -> None:
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.5.5", "172.31.255.255"):
            assert is_privateish_ip(ip) is True, f"{ip} should be private"

    def test_public_ipv4_still_public(self) -> None:
        for ip in ("8.8.8.8", "1.1.1.1", "169.148.142.75"):
            assert is_privateish_ip(ip) is False, f"{ip} should be public"

    def test_loopback_flagged(self) -> None:
        assert is_privateish_ip("127.0.0.1") is True
        assert is_privateish_ip("::1") is True

    def test_link_local_flagged(self) -> None:
        assert is_privateish_ip("169.254.1.1") is True
        assert is_privateish_ip("fe80::1") is True

    def test_documentation_prefix_still_flagged(self) -> None:
        """RFC 3849 IPv6 documentation range — reserved AND non-routable."""
        assert is_privateish_ip("2001:db8::1") is True

    def test_public_ipv6_not_flagged(self) -> None:
        """Google DNS IPv6 — must pass as public."""
        assert is_privateish_ip("2001:4860:4860::8888") is False

    def test_multicast_flagged(self) -> None:
        assert is_privateish_ip("224.0.0.1") is True
        assert is_privateish_ip("ff02::1") is True

    def test_unspecified_flagged(self) -> None:
        assert is_privateish_ip("0.0.0.0") is True
        assert is_privateish_ip("::") is True

    def test_garbage_input_returns_false(self) -> None:
        # Backward-compat: unparseable strings are not "private" (they
        # just aren't IPs).
        assert is_privateish_ip("not-an-ip") is False
        assert is_privateish_ip("") is False

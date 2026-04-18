"""Surrogate generation — build non-routable stand-ins for real data.

Surrogates are:
- **Plausible** so they survive parsers downstream (valid IPv4 octets, valid
  FQDN labels, proper hash lengths).
- **Obviously non-routable** so a human reviewing LLM context instantly
  recognises them as synthetic (RFC 5737 TEST-NET ranges, ``.pentest.local``).
- **Deterministic within an engagement** so repeated mentions of the same
  original always resolve to the same surrogate — otherwise chat history
  becomes unreadable.

The generator is *stateless with respect to history* — the :class:`Vault`
is the source of truth for stable mappings. Surrogates use hash-of-value
so multiple runs pre-seeding the vault produce identical output.
"""

from __future__ import annotations

import hashlib
import ipaddress
import string
from typing import Callable

from .regex_detector import (
    AWS_KEY, API_TOKEN, DOMAIN, EMAIL, HASH_MD5, HASH_NTLM, HASH_SHA1,
    HASH_SHA256, IPV4, IPV4_CIDR, IPV6, JWT, MAC, URL,
)

# RFC 5737 TEST-NET-1/2/3 — documentation-only blocks, never routed on internet.
_TEST_NET_BASES = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
# RFC 3849 — IPv6 documentation prefix.
_IPV6_DOC = ipaddress.IPv6Network("2001:db8::/32")

# Surrogate FQDN root; all surrogate domains end in this suffix.
_PENTEST_SUFFIX = "pentest.local"


def _seeded_bytes(value: str, salt: str = "") -> bytes:
    """Stable bytes derived from an entity value — used for surrogate selection."""
    h = hashlib.sha256((salt + "::" + value).encode("utf-8")).digest()
    return h


def _ip_from_hash(value: str) -> str:
    b = _seeded_bytes(value, "ipv4")
    net = _TEST_NET_BASES[b[0] % len(_TEST_NET_BASES)]
    # Host portion — skip .0 (network) and .255 (broadcast); keep .1..254.
    host = 1 + (b[1] % 254)
    ip = ipaddress.IPv4Address(int(net.network_address) + host)
    return str(ip)


def _ipv6_from_hash(value: str) -> str:
    b = _seeded_bytes(value, "ipv6")
    # Use the last 10 bytes of the hash for the host portion.
    host = int.from_bytes(b[:10], "big") & ((1 << 80) - 1)
    ip = ipaddress.IPv6Address(int(_IPV6_DOC.network_address) + host)
    return str(ip)


def _cidr_from_hash(value: str) -> str:
    base = _ip_from_hash(value.split("/")[0])
    prefix = int(value.rsplit("/", 1)[1]) if "/" in value else 24
    # Snap surrogate to a /24 within the TEST-NET for cleanliness.
    prefix = max(8, min(32, prefix))
    net = ipaddress.ip_network(f"{base}/{prefix}", strict=False)
    return str(net)


def _label_from_hash(value: str, length: int = 6, alphabet: str = string.ascii_lowercase) -> str:
    b = _seeded_bytes(value, f"label{length}")
    return "".join(alphabet[x % len(alphabet)] for x in b[:length])


def _mac_from_hash(value: str) -> str:
    b = _seeded_bytes(value, "mac")
    # Locally-administered unicast MAC: set bit 1 of first octet, clear bit 0.
    first = (b[0] & 0xFE) | 0x02
    octets = [first] + list(b[1:6])
    return ":".join(f"{o:02x}" for o in octets)


def _email_from_hash(value: str) -> str:
    local = _label_from_hash(value, 6)
    return f"{local}@example.pentest"


def _domain_from_hash(value: str) -> str:
    # Preserve depth / label count of the original where possible.
    depth = max(1, value.count(".") - 1)  # "a.b.tld" → 1 intermediate
    labels = [_label_from_hash(f"{value}:{i}", 6) for i in range(depth)]
    return ".".join(labels) + "." + _PENTEST_SUFFIX


def _url_from_hash(value: str) -> str:
    # Strip scheme, keep host, rebuild with a surrogate host.
    scheme = "https" if value.lower().startswith("https://") else "http"
    tail_digest = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"{scheme}://{_label_from_hash(value, 6)}.{_PENTEST_SUFFIX}/ref/{tail_digest}"


def _hash_from_hash(value: str, length: int) -> str:
    return hashlib.sha256(f"surrogate::{value}".encode()).hexdigest()[:length]


def _ntlm_from_hash(value: str) -> str:
    return f"{_hash_from_hash(value, 32)}:{_hash_from_hash(value + 'nt', 32)}"


def _aws_key_from_hash(value: str) -> str:
    b = _seeded_bytes(value, "aws")
    tail = "".join(string.ascii_uppercase[x % 26] for x in b[:12]) + \
           "".join(string.digits[x % 10] for x in b[12:16])
    return "AKIA" + tail  # 4 + 16 = 20 chars


def _api_token_from_hash(value: str) -> str:
    return "sk_test_" + _label_from_hash(value, 24, alphabet=string.ascii_letters + string.digits)


def _jwt_from_hash(value: str) -> str:
    h = _label_from_hash(value + "h", 20, alphabet=string.ascii_letters + string.digits + "_-")
    p = _label_from_hash(value + "p", 30, alphabet=string.ascii_letters + string.digits + "_-")
    s = _label_from_hash(value + "s", 32, alphabet=string.ascii_letters + string.digits + "_-")
    return f"eyJ{h[:17]}.{p}.{s}"


_GENERATORS: dict[str, Callable[[str], str]] = {
    IPV4:        _ip_from_hash,
    IPV4_CIDR:   _cidr_from_hash,
    IPV6:        _ipv6_from_hash,
    MAC:         _mac_from_hash,
    EMAIL:       _email_from_hash,
    DOMAIN:      _domain_from_hash,
    URL:         _url_from_hash,
    AWS_KEY:     _aws_key_from_hash,
    API_TOKEN:   _api_token_from_hash,
    JWT:         _jwt_from_hash,
    HASH_MD5:    lambda v: _hash_from_hash(v, 32),
    HASH_SHA1:   lambda v: _hash_from_hash(v, 40),
    HASH_SHA256: lambda v: _hash_from_hash(v, 64),
    HASH_NTLM:   _ntlm_from_hash,
}


class SurrogateGenerator:
    """Deterministic surrogate factory keyed on (entity, value)."""

    def generate(self, entity: str, value: str) -> str:
        gen = _GENERATORS.get(entity)
        if gen is None:
            # Unknown entity — redact with a stable opaque token.
            return f"[REDACTED_{_label_from_hash(value, 8).upper()}]"
        return gen(value)

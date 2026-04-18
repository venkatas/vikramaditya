"""Regex detector — deterministic pass for obvious sensitive data.

Pattern priority: longer/more-specific patterns first so that an FQDN never
gets half-anonymized by a bare IPv4 rule. Overlap resolution is handled in
:meth:`RegexDetector.detect` by sorting matches by start offset and dropping
any whose span intersects an already-kept match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------

IPV4 = "ipv4"
IPV4_CIDR = "ipv4_cidr"
IPV6 = "ipv6"
MAC = "mac"
EMAIL = "email"
DOMAIN = "domain"
URL = "url"
AWS_KEY = "aws_key"
JWT = "jwt"
HASH_MD5 = "hash_md5"
HASH_SHA1 = "hash_sha1"
HASH_SHA256 = "hash_sha256"
HASH_NTLM = "hash_ntlm"
API_TOKEN = "api_token"


@dataclass(frozen=True)
class Detection:
    """A single regex hit."""
    entity: str
    value: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# Patterns. Order matters — the first to match a span wins.
# ---------------------------------------------------------------------------

# JWT: header.payload.signature (three base64url segments)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# AWS access key (AKIA / ASIA / AGPA etc., 20-char alnum)
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b")

# Generic bearer / secret tokens (sk_live_, sk_test_, xoxb-, ghp_, github_pat_)
_API_TOKEN_RE = re.compile(
    r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}\b"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}"
    r"|gh[pousr]_[A-Za-z0-9]{36,255}"
    r"|github_pat_[A-Za-z0-9_]{82}"
)

# Hashes — most specific first
_HASH_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_HASH_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
# NTLM hashes are 32 hex chars but often appear as LMhash:NThash
_HASH_NTLM_RE = re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b")
_HASH_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

# MAC address — colon or dash separated
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# IPv6 — simplified but covers common forms including :: compression
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{0,4}\b"
    r"|\bfe80::[0-9a-fA-F:]{1,30}\b"
)

# IPv4 CIDR must come before bare IPv4 to avoid half-consumption
_IPV4_CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}\b"
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Email — RFC-ish, permissive on local-part
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")

# URL — http(s) only; includes path/query/fragment
_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\\]+", re.IGNORECASE)

# Domain / FQDN — at least one label plus TLD, not all-numeric (avoids IPv4)
_DOMAIN_RE = re.compile(
    r"\b(?=[a-zA-Z])"                # must start with a letter (skip all-digit)
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)

# (entity_type, pattern) in resolution order. Longest/most-specific first.
_RULES: list[tuple[str, re.Pattern[str]]] = [
    (JWT, _JWT_RE),
    (AWS_KEY, _AWS_KEY_RE),
    (API_TOKEN, _API_TOKEN_RE),
    (HASH_NTLM, _HASH_NTLM_RE),
    (HASH_SHA256, _HASH_SHA256_RE),
    (HASH_SHA1, _HASH_SHA1_RE),
    (HASH_MD5, _HASH_MD5_RE),
    (MAC, _MAC_RE),
    (IPV6, _IPV6_RE),
    (IPV4_CIDR, _IPV4_CIDR_RE),
    (IPV4, _IPV4_RE),
    (URL, _URL_RE),
    (EMAIL, _EMAIL_RE),
    (DOMAIN, _DOMAIN_RE),
]

# Tool / protocol / keyword allowlist — never treated as sensitive even if
# they look like FQDN fragments (e.g. "localhost", "example.com").
_NEVER_ANONYMIZE: frozenset[str] = frozenset({
    # RFC-reserved test zones (already surrogate-safe)
    "example.com", "example.net", "example.org",
    "pentest.local", "test-net.local",
    # Loopback / link-local
    "localhost", "localdomain", "local",
    # Common public services Claude legitimately discusses
    "github.com", "anthropic.com", "openai.com", "google.com",
    "python.org", "pypi.org", "npmjs.com",
    # Protocol / scheme keywords mis-tokenised as "domain"
    "tcp.udp", "http.https", "smb.local",
})


class RegexDetector:
    """Detect sensitive entities via deterministic regex.

    Usage:
        detector = RegexDetector()
        for d in detector.detect("scan 10.0.0.1 and DC01"):
            print(d.entity, d.value, d.start, d.end)
    """

    def __init__(self, extra_safe: Iterable[str] | None = None) -> None:
        self._safe = set(_NEVER_ANONYMIZE)
        if extra_safe:
            self._safe.update(s.lower() for s in extra_safe)

    def detect(self, text: str) -> list[Detection]:
        """Return non-overlapping detections in source order.

        When two patterns match overlapping spans, the higher-priority
        rule (declared earlier in ``_RULES``) wins. This matters for:
        - NTLM (``hash:hash``) vs two adjacent MD5 hashes.
        - IPv4 CIDR vs bare IPv4.
        - FQDNs vs the emails that contain them.
        """
        hits: list[Detection] = []
        for entity, pattern in _RULES:
            for m in pattern.finditer(text):
                value = m.group(0)
                if value.lower() in self._safe:
                    continue
                hits.append(Detection(entity=entity, value=value, start=m.start(), end=m.end()))

        # Resolve overlaps: sort by (start, -length) so longer spans win,
        # then drop any hit whose span intersects an already-accepted one.
        hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
        accepted: list[Detection] = []
        last_end = -1
        for h in hits:
            if h.start >= last_end:
                accepted.append(h)
                last_end = h.end
        return accepted

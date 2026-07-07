#!/usr/bin/env python3
"""springboot_actuator_probe.py — SpEL injection oracle, Jolokia reachability,
actuator/env secret parsing.

Extends recon.sh Phase 9, which already probes /actuator/env, /actuator/heapdump,
/actuator/mappings, /h2-console/ as bare path hits — this module adds the active
depth that was missing: proving real code-execution capability (not just
arithmetic evaluation, which reads as theoretical), confirming Jolokia RCE
PRECONDITIONS without executing anything, and pulling real credential material
out of an exposed /actuator/env response using whitebox/secrets/detectors.py's
existing regex set (pii_detector.py is Indian-PII-only and not applicable here).

A bare /actuator/health 200 is NEVER treated as a finding by this module.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from whitebox.secrets.detectors import DETECTORS

_ARITHMETIC_MARKER = re.compile(r"result:\s*49\b")
_SYSTEM_METADATA_MARKER = re.compile(r"java\.version=\S+")

# SpEL expression that both proves arithmetic evaluation (7*7) and, on a
# vulnerable sink, additionally leaks a benign system property — a single
# probe covers both proof tiers so we don't need two round trips.
SPEL_PROOF_PAYLOAD = "#{7*7}#{T(java.lang.System).getProperty('java.version')}"


@dataclass
class SpelResult:
    verdict: str  # "confirmed" | "candidate" | "clean"
    detail: str = ""
    # The raw HTTP response the verdict was derived from. Lets callers check
    # for a bot-management/WAF block without a second round-trip.
    response: object = None


def check_spel_injection(client, url: str) -> SpelResult:
    response = client.get(url, params={"expr": SPEL_PROOF_PAYLOAD})
    text = getattr(response, "text", "") or ""
    if response.status_code != 200:
        return SpelResult(verdict="clean", detail="no evaluation signal", response=response)
    arithmetic_proven = bool(_ARITHMETIC_MARKER.search(text))
    metadata_proven = bool(_SYSTEM_METADATA_MARKER.search(text))
    if arithmetic_proven and metadata_proven:
        return SpelResult(verdict="confirmed", detail="SpEL evaluated arithmetic AND leaked java.version — real code execution proven", response=response)
    if arithmetic_proven:
        return SpelResult(verdict="candidate", detail="arithmetic evaluated but no system-metadata proof yet — theoretical until deepened", response=response)
    return SpelResult(verdict="clean", detail="no evaluation signal", response=response)


@dataclass
class JolokiaResult:
    reachable: bool
    mbean_count: int = 0
    # The raw HTTP response check_jolokia_reachability examined. Lets callers
    # check for a bot-management/WAF block without a second round-trip.
    response: object = None


def check_jolokia_reachability(client, url: str) -> JolokiaResult:
    """Lists MBeans if reachable — proves the RCE precondition (Jolokia
    exposed) without executing anything (no write/exec calls made)."""
    response = client.get(url)
    if response.status_code != 200:
        return JolokiaResult(reachable=False, response=response)
    try:
        body = response.json()
    except Exception:
        return JolokiaResult(reachable=False, response=response)
    mbeans = body.get("value", {})
    return JolokiaResult(reachable=True, mbean_count=len(mbeans), response=response)


def parse_actuator_env_secrets(json_body: dict) -> list[dict]:
    """Scan every property value in an /actuator/env response against
    whitebox/secrets/detectors.py's DETECTORS regex set. Returns one dict per
    match: {detector, property_name, source}.

    For detectors that require keyword context (e.g., aws_secret_access_key),
    we construct a synthetic "KEY=VALUE" string using the property name and value
    so the detector's regex can match.

    Two invariants enforced here (both keyed on (source_name, prop_name)):
    - a property is reported AT MOST ONCE, no matter how many detectors (or
      which of the two loops below) would otherwise match it — the same
      leaked secret should not surface as two "different" findings just
      because two regexes both happened to match it;
    - that "at most once" scoping is per property SOURCE, not just per
      property name, because Spring's own property-source precedence means
      the exact same name legitimately carries different values across
      systemEnvironment / applicationConfig / commandLineArgs / etc., and a
      real secret in one source must not be dropped because a same-named
      property in another source was already reported.
    """
    hits: list[dict] = []
    # (source_name, prop_name) pairs that already produced a hit, from either
    # loop below. Once a property is reported, we stop looking at it.
    reported: set[tuple[str, str]] = set()

    # generic_password_assignment is deliberately excluded from the synthetic
    # "KEY=VALUE" matching path. That regex only requires the property NAME to
    # end in password/passwd/pwd plus ANY 8+ char value — true of huge numbers
    # of totally benign Spring Boot config keys (spring.datasource.password,
    # db_password, spring.mail.password, ...) regardless of whether the value
    # is a real secret or a benign toggle/placeholder (Spring's own Sanitizer
    # masks genuinely sensitive values to `******` by default anyway, so a real
    # leak here usually has actual entropy/shape). Once we manufacture
    # "prop_name=value" ourselves, that keyword adjacency exists for nearly
    # every such property, so the detector can no longer discriminate a real
    # secret from a config toggle — it is structurally the wrong detector to
    # run against a reconstructed string. It stays wired into the raw-value
    # loop below, where a bare secret VALUE practically never itself contains
    # the literal word "password", so it is effectively inert there (which is
    # fine — it isn't doing useful work in this module either way).
    SYNTHETIC_EXCLUDED_DETECTORS = {"generic_password_assignment"}

    for source in json_body.get("propertySources", []):
        source_name = source.get("name", "unknown")
        for prop_name, prop_value in source.get("properties", {}).items():
            key = (source_name, prop_name)
            if key in reported:
                continue
            value = str(prop_value.get("value", ""))

            # Try matching on raw value first (covers detectors whose pattern
            # needs nothing but the secret's own shape: AWS access key ID,
            # JWT, PEM header, provider token prefixes, and
            # generic_password_assignment when the VALUE itself happens to
            # contain "password="/"pwd=" etc.).
            for detector_name, pattern in DETECTORS.items():
                if pattern.search(value):
                    hits.append({"detector": detector_name, "property_name": prop_name, "source": source_name})
                    reported.add(key)
                    break  # one finding per property is enough

            if key in reported:
                continue

            # For keyword-context detectors (e.g. aws_secret_access_key,
            # whose pattern requires a "secret_key="-style keyword immediately
            # before the value and therefore can never fire on a bare secret
            # VALUE alone), also try with property-name context. This never
            # runs generic_password_assignment — see comment above.
            synthetic = f"{prop_name}={value}"
            for detector_name, pattern in DETECTORS.items():
                if detector_name in SYNTHETIC_EXCLUDED_DETECTORS:
                    continue
                if pattern.search(synthetic):
                    hits.append({"detector": detector_name, "property_name": prop_name, "source": source_name})
                    reported.add(key)
                    break
    return hits

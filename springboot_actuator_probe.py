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
SPEL_PROOF_PAYLOAD = "#{7*7}{T(java.lang.System).getProperty('java.version')}"


@dataclass
class SpelResult:
    verdict: str  # "confirmed" | "candidate" | "clean"
    detail: str = ""


def check_spel_injection(client, url: str) -> SpelResult:
    response = client.get(url, params={"expr": SPEL_PROOF_PAYLOAD})
    text = getattr(response, "text", "") or ""
    if response.status_code != 200:
        return SpelResult(verdict="clean", detail="no evaluation signal")
    arithmetic_proven = bool(_ARITHMETIC_MARKER.search(text))
    metadata_proven = bool(_SYSTEM_METADATA_MARKER.search(text))
    if arithmetic_proven and metadata_proven:
        return SpelResult(verdict="confirmed", detail="SpEL evaluated arithmetic AND leaked java.version — real code execution proven")
    if arithmetic_proven:
        return SpelResult(verdict="candidate", detail="arithmetic evaluated but no system-metadata proof yet — theoretical until deepened")
    return SpelResult(verdict="clean", detail="no evaluation signal")


@dataclass
class JolokiaResult:
    reachable: bool
    mbean_count: int = 0


def check_jolokia_reachability(client, url: str) -> JolokiaResult:
    """Lists MBeans if reachable — proves the RCE precondition (Jolokia
    exposed) without executing anything (no write/exec calls made)."""
    response = client.get(url)
    if response.status_code != 200:
        return JolokiaResult(reachable=False)
    try:
        body = response.json()
    except Exception:
        return JolokiaResult(reachable=False)
    mbeans = body.get("value", {})
    return JolokiaResult(reachable=True, mbean_count=len(mbeans))


def parse_actuator_env_secrets(json_body: dict) -> list[dict]:
    """Scan every property value in an /actuator/env response against
    whitebox/secrets/detectors.py's DETECTORS regex set. Returns one dict per
    match: {detector, property_name, source}.

    For detectors that require keyword context (e.g., aws_secret_access_key),
    we construct a synthetic "KEY=VALUE" string using the property name and value
    so the detector's regex can match."""
    hits = []
    for source in json_body.get("propertySources", []):
        source_name = source.get("name", "unknown")
        for prop_name, prop_value in source.get("properties", {}).items():
            value = str(prop_value.get("value", ""))
            # Try matching on raw value first
            for detector_name, pattern in DETECTORS.items():
                if pattern.search(value):
                    hits.append({"detector": detector_name, "property_name": prop_name, "source": source_name})
                    break  # Only report first match per property to avoid duplicates
            # For keyword-context detectors, also try with property name context
            # (e.g., aws_secret_access_key detector expects "aws_secret_access_key=...")
            synthetic = f"{prop_name}={value}"
            for detector_name, pattern in DETECTORS.items():
                if pattern.search(synthetic):
                    # Check if we already reported this property with this detector
                    if not any(h["detector"] == detector_name and h["property_name"] == prop_name for h in hits):
                        hits.append({"detector": detector_name, "property_name": prop_name, "source": source_name})
    return hits

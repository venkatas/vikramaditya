"""springboot_actuator_probe — extends recon.sh Phase 9 (which already probes
/actuator/env, /actuator/heapdump, /actuator/mappings, /h2-console/ as bare path
hits). This module adds active depth: a SpEL injection oracle, Jolokia
reachability, and structured /actuator/env secret parsing.

FP gate: arithmetic-only SpEL evaluation is a [SPEL-CANDIDATE] lead, not a
finding — only a benign system-metadata read (proving real Java code execution
capability) escalates further. A bare /actuator/health 200 is never a finding.
"""
import springboot_actuator_probe as sap


class _FakeResponse:
    def __init__(self, status_code=200, text="", json_body=None):
        self.status_code = status_code
        self.text = text
        self._json = json_body or {}

    def json(self):
        return self._json


class _FakeClient:
    def __init__(self, response):
        self._response = response
        self.last_url = None

    def get(self, url, **kwargs):
        self.last_url = url
        return self._response


def test_spel_arithmetic_only_is_candidate_not_confirmed():
    # 7 * 7 evaluated to 49 in the response, but no system-metadata proof
    client = _FakeClient(_FakeResponse(200, text="result: 49"))
    result = sap.check_spel_injection(client, "https://example.com/actuator/env")
    assert result.verdict == "candidate"


def test_spel_with_system_metadata_proof_is_confirmed():
    client = _FakeClient(_FakeResponse(200, text="result: 49 | java.version=17.0.9"))
    result = sap.check_spel_injection(client, "https://example.com/actuator/env")
    assert result.verdict == "confirmed"


def test_spel_no_evaluation_signal_is_clean():
    client = _FakeClient(_FakeResponse(400, text="bad request"))
    result = sap.check_spel_injection(client, "https://example.com/actuator/env")
    assert result.verdict == "clean"


def test_jolokia_reachable_lists_mbeans_without_executing():
    body = {"value": {"java.lang:type=Memory": {}, "java.lang:type=Runtime": {}}}
    client = _FakeClient(_FakeResponse(200, json_body=body))
    result = sap.check_jolokia_reachability(client, "https://example.com/jolokia/list")
    assert result.reachable is True
    assert result.mbean_count == 2


def test_jolokia_unreachable_on_404():
    client = _FakeClient(_FakeResponse(404))
    result = sap.check_jolokia_reachability(client, "https://example.com/jolokia/list")
    assert result.reachable is False


def test_parse_actuator_env_secrets_finds_aws_key():
    body = {"propertySources": [
        {"name": "systemEnvironment",
         "properties": {"AWS_SECRET_ACCESS_KEY": {"value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}}
    ]}
    hits = sap.parse_actuator_env_secrets(body)
    assert any(h["detector"] == "aws_secret_access_key" for h in hits)


def test_parse_actuator_env_secrets_empty_when_no_matches():
    body = {"propertySources": [{"name": "systemEnvironment", "properties": {"PATH": {"value": "/usr/bin"}}}]}
    assert sap.parse_actuator_env_secrets(body) == []


def test_bare_health_check_never_reported_as_finding():
    client = _FakeClient(_FakeResponse(200, text='{"status":"UP"}'))
    result = sap.check_spel_injection(client, "https://example.com/actuator/health")
    assert result.verdict in ("clean", "candidate")
    assert result.verdict != "confirmed"


def test_parse_actuator_env_secrets_benign_password_key_not_flagged():
    # spring.datasource.password / db_password / etc. are extremely common
    # benign Spring Boot config keys. A short, boring value must NOT be
    # flagged just because the property NAME ends in "password" — the
    # synthetic "KEY=VALUE" string used for keyword-context detectors must
    # never be handed to generic_password_assignment (Important #1).
    body = {"propertySources": [
        {"name": "systemEnvironment",
         "properties": {
             "spring.datasource.password": {"value": "disabled"},
             "db_password": {"value": "letmein12"},
         }},
    ]}
    hits = sap.parse_actuator_env_secrets(body)
    assert hits == []


def test_parse_actuator_env_secrets_same_property_name_different_sources_both_reported():
    # The same property name can legitimately carry DIFFERENT real values
    # across different property sources (systemEnvironment vs
    # applicationConfig, per Spring's property-source precedence). A real
    # secret in a later source must not be silently dropped just because the
    # same-named property in an earlier source was already reported
    # (Important #2).
    secret_a = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40 chars
    secret_b = "zZ9yY8xX7wW6vV5uU4tT3sS2rR1qQ0pP+oO/nN=="  # 40 chars, different
    assert len(secret_a) == 40 and len(secret_b) == 40 and secret_a != secret_b
    body = {"propertySources": [
        {"name": "systemEnvironment",
         "properties": {"AWS_SECRET_ACCESS_KEY": {"value": secret_a}}},
        {"name": "applicationConfig: [classpath:/application.yml]",
         "properties": {"AWS_SECRET_ACCESS_KEY": {"value": secret_b}}},
    ]}
    hits = sap.parse_actuator_env_secrets(body)
    aws_hits = [h for h in hits if h["detector"] == "aws_secret_access_key"]
    assert len(aws_hits) == 2
    assert {h["source"] for h in aws_hits} == {
        "systemEnvironment",
        "applicationConfig: [classpath:/application.yml]",
    }
    assert all(h["property_name"] == "AWS_SECRET_ACCESS_KEY" for h in aws_hits)


def test_parse_actuator_env_secrets_double_detector_match_reports_once():
    # A single leaked property whose value happens to match generic_password_
    # assignment on the raw value AND would also match aws_secret_access_key
    # via the synthetic "KEY=VALUE" string (property name ends in
    # "secret_key") must be reported ONCE, not twice — one property, one
    # underlying secret, one finding (Important #3).
    value = "pwd=" + "A" * 44
    body = {"propertySources": [
        {"name": "systemEnvironment",
         "properties": {"app.super.secret_key": {"value": value}}},
    ]}
    hits = sap.parse_actuator_env_secrets(body)
    assert len(hits) == 1
    assert hits[0]["detector"] == "generic_password_assignment"
    assert hits[0]["property_name"] == "app.super.secret_key"

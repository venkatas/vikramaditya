"""Verifies the new phases (xxe_hunt, open_redirect_hunt, saml_xsw,
actuator_probe, ldap_injection) are correctly wired in hunt.py: the run_*()
functions exist, and hunt_target()'s source registers each phase's key in
its _phase_requested gating dict (a phase with only an appended run_*()
function but no _phase_requested entry silently misreports its dashboard
status). Also verifies run_jwt_audit() was extended in place to call
jwt_kid_injection.

NOTE: the sequential Phase 7.x phase-call pattern (the _phase_tool_map /
_phase_requested dicts and the "if <gate> and not skip_has(...): try: ...
result[key] = run_xxx(domain)" call sites) live inside hunt_target(), the
default (non --autonomous) orchestrator invoked from main() — NOT inside
run_autonomous_hunt(), which is a separate, --autonomous-only step-based
orchestrator with its own independent phase list. Verified directly against
the live hunt.py source before writing this test.

Fix Round 1: the tests above only ever checked that a function/call-site NAME
existed in the source — they could not tell the difference between a phase
that genuinely calls a module's full public surface and one that only calls a
fraction of it (exactly how run_xxe_hunt calling only probe_content_type_swap,
run_saml_xsw's ACS-selection bug, and run_actuator_probe never calling
check_jolokia_reachability all went undetected). The tests below close that
gap: they assert the missing call sites now exist in the relevant phase
function's OWN source (not just somewhere in hunt.py), AND they mock the
underlying HTTP client / interactsh session and assert the real module
function is invoked with the right arguments and its result is honoured."""
import inspect

import hunt


def test_new_phase_functions_exist():
    for name in ("run_xxe_hunt", "run_open_redirect_hunt", "run_saml_xsw",
                 "run_actuator_probe", "run_ldap_injection"):
        assert hasattr(hunt, name), f"hunt.py is missing {name}"
        assert callable(getattr(hunt, name))


def test_new_phases_registered_in_phase_requested_source():
    source = inspect.getsource(hunt.hunt_target)
    for key in ("xxe_hunt", "open_redirect_hunt", "saml_xsw", "actuator_probe", "ldap_injection"):
        assert f'"{key}"' in source, f"_phase_requested missing entry for {key}"
        # each phase must actually be CALLED (result["<key>"] = run_...), not just
        # declared in the dashboard dict — otherwise it's dead code.
        assert f'result["{key}"]' in source, f"{key} is registered but never assigned in result[...]"


def test_new_phases_actually_called():
    source = inspect.getsource(hunt.hunt_target)
    assert "run_xxe_hunt(domain)" in source
    assert "run_open_redirect_hunt(domain)" in source
    assert "run_saml_xsw(domain)" in source
    assert "run_actuator_probe(domain)" in source
    assert "run_ldap_injection(domain)" in source


def test_run_jwt_audit_source_calls_kid_injection_module():
    source = inspect.getsource(hunt.run_jwt_audit)
    assert "jwt_kid_injection" in source


# ════════════════════════════════════════════════════════════════════════════
# Fix Round 1 — source-level regression guards
#
# Cheap, fast checks that the specific call sites the reviewer flagged as
# missing now exist in the OWNING function's source. These alone would not
# have caught the original gaps (the reviewer's whole point was that
# presence-of-name checks are insufficient) but they DO catch a naive future
# revert/removal, and are a useful first line of defense alongside the
# behavioral tests below.
# ════════════════════════════════════════════════════════════════════════════

def test_run_xxe_hunt_source_calls_confirm_blind_oob():
    source = inspect.getsource(hunt.run_xxe_hunt)
    assert "xxe_hunt.confirm_blind_oob(session, session.token)" in source
    assert "session.url" in source, "OOB payload must reference the real interactsh session URL"


def test_run_xxe_hunt_source_calls_probe_upload_xxe():
    source = inspect.getsource(hunt.run_xxe_hunt)
    assert "xxe_hunt.probe_upload_xxe(" in source


def test_run_saml_xsw_source_filters_acs_or_login_before_selecting():
    source = inspect.getsource(hunt.run_saml_xsw)
    assert "saml/acs" in source and "saml/login" in source
    # the old bug (`.read().split()[1]`) must be gone
    assert ".read().split()[1]" not in source


def test_run_actuator_probe_source_calls_check_jolokia_reachability():
    source = inspect.getsource(hunt.run_actuator_probe)
    assert "check_jolokia_reachability(" in source


def test_run_ldap_injection_source_calls_brain_phase_complete_on_skip_path():
    source = inspect.getsource(hunt.run_ldap_injection)
    # the skip branch (stack fingerprint doesn't look LDAP-backed) must call
    # _brain_phase_complete for dashboard consistency, same as run_saml_xsw's
    # analogous "no captured assertion" skip path already does.
    skip_branch = source.split("looks_like_ldap_backed_auth")[1].split("if _brain and _brain.enabled")[0]
    assert "_brain_phase_complete(" in skip_branch


# ════════════════════════════════════════════════════════════════════════════
# Fix Round 1 — behavioral tests (mock the HTTP client / interactsh session,
# assert the real module function is actually invoked with real arguments,
# and that its result is honoured in findings.txt / _brain_phase_complete).
# ════════════════════════════════════════════════════════════════════════════

class _FakeHttpResponse:
    def __init__(self, status_code=200, text="", json_body=None, headers=None):
        self.status_code = status_code
        self.text = text
        self._json = json_body if json_body is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._json


class _FakeHttpClient:
    """Stand-in for tls_impersonation's client: records every .post()/.get()
    call and always returns a clean (no-signal) response unless overridden."""
    def __init__(self, response=None):
        self._response = response or _FakeHttpResponse()
        self.posts = []
        self.gets = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return self._response

    def get(self, url, **kwargs):
        self.gets.append((url, kwargs))
        return self._response


def _patch_common(monkeypatch, recon_dir, findings_dir):
    monkeypatch.setattr(hunt, "_brain", None, raising=False)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda d, session_id=None: str(recon_dir))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda d, session_id=None, create=False: str(findings_dir))


# ── Critical #1: blind-OOB confirmation ────────────────────────────────────

def test_xxe_hunt_calls_confirm_blind_oob_with_real_session_and_token(monkeypatch, tmp_path):
    import interactsh_client
    import tls_impersonation
    import xxe_hunt

    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "urls" / "with_params.txt").write_text("https://victim.example/api?id=1\n")
    findings_dir.mkdir(parents=True)
    _patch_common(monkeypatch, recon_dir, findings_dir)

    fake_session = interactsh_client.InteractshSession(
        url="https://tok123abc.oast.pro",
        log_path=str(tmp_path / "interactsh_log.jsonl"),
        token="tok123abc",
        proc=None,
    )
    monkeypatch.setattr(interactsh_client, "spawn", lambda log_dir: fake_session)
    monkeypatch.setattr(hunt.time, "sleep", lambda seconds: None)

    monkeypatch.setattr(xxe_hunt, "probe_content_type_swap",
                        lambda client, url, body: xxe_hunt.XxeResult(verdict="clean", evidence="no XXE signal"))

    confirm_calls = []

    def fake_confirm_blind_oob(session, token):
        confirm_calls.append((session, token))
        return xxe_hunt.XxeResult(verdict="confirmed", evidence="OOB callback received (1 hit)")

    monkeypatch.setattr(xxe_hunt, "confirm_blind_oob", fake_confirm_blind_oob)

    fake_client = _FakeHttpClient()
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)

    ok = hunt.run_xxe_hunt("victim.example")

    assert ok is True
    assert confirm_calls == [(fake_session, "tok123abc")], (
        "confirm_blind_oob must be called with the REAL spawned session and its token"
    )
    # the OOB-variant request must reference the session's real canary domain,
    # not a fabricated one
    assert any(fake_session.url in kwargs.get("data", "") for _url, kwargs in fake_client.posts), (
        "the blind-OOB payload sent over the wire must reference session.url"
    )
    findings_txt = (findings_dir / "xxe" / "findings.txt").read_text()
    assert "[XXE-OOB-CONFIRMED]" in findings_txt


def test_xxe_hunt_does_not_call_confirm_blind_oob_when_session_has_no_token(monkeypatch, tmp_path):
    """interactsh-client failing to announce a correlation domain within its
    startup deadline must not be treated as 'confirm everything' — session.token
    == "" must gate the whole OOB path off, per interactsh_client.spawn's own
    documented contract."""
    import interactsh_client
    import tls_impersonation
    import xxe_hunt

    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "urls" / "with_params.txt").write_text("https://victim.example/api?id=1\n")
    findings_dir.mkdir(parents=True)
    _patch_common(monkeypatch, recon_dir, findings_dir)

    fake_session = interactsh_client.InteractshSession(
        url="", log_path=str(tmp_path / "interactsh_log.jsonl"), token="", proc=None,
    )
    monkeypatch.setattr(interactsh_client, "spawn", lambda log_dir: fake_session)
    monkeypatch.setattr(hunt.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(xxe_hunt, "probe_content_type_swap",
                        lambda client, url, body: xxe_hunt.XxeResult(verdict="clean", evidence="no XXE signal"))

    confirm_calls = []
    monkeypatch.setattr(xxe_hunt, "confirm_blind_oob",
                        lambda session, token: confirm_calls.append((session, token)))

    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: _FakeHttpClient())

    ok = hunt.run_xxe_hunt("victim.example")
    assert ok is True
    assert confirm_calls == [], "an empty session.token must never be polled as if it were real"


# ── Critical #3: upload-vector XXE ─────────────────────────────────────────

def test_xxe_hunt_calls_probe_upload_xxe_against_scanner_discovered_upload_candidates(monkeypatch, tmp_path):
    import interactsh_client
    import tls_impersonation
    import xxe_hunt

    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "urls" / "with_params.txt").write_text("https://victim.example/api?id=1\n")
    (findings_dir / "upload").mkdir(parents=True)
    (findings_dir / "upload" / "active_upload_probe.txt").write_text(
        "[UPLOAD-CANDIDATE] https://victim.example/upload\n"
        "[UPLOAD-CANDIDATE-POST] https://victim.example/api/upload (GET=404 -> POST=200)\n"
    )
    _patch_common(monkeypatch, recon_dir, findings_dir)

    monkeypatch.setattr(interactsh_client, "spawn", lambda log_dir: None)
    monkeypatch.setattr(xxe_hunt, "probe_content_type_swap",
                        lambda client, url, body: xxe_hunt.XxeResult(verdict="clean", evidence="no XXE signal"))

    upload_calls = []

    def fake_probe_upload_xxe(client, endpoint, doc_type="svg"):
        upload_calls.append((endpoint, doc_type))
        return xxe_hunt.XxeResult(verdict="confirmed", evidence="in-band /etc/passwd content in upload response")

    monkeypatch.setattr(xxe_hunt, "probe_upload_xxe", fake_probe_upload_xxe)
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: _FakeHttpClient())

    ok = hunt.run_xxe_hunt("victim.example")

    assert ok is True
    assert upload_calls == [
        ("https://victim.example/upload", "svg"),
        ("https://victim.example/api/upload", "svg"),
    ], "probe_upload_xxe must be called once per discovered upload-candidate URL"
    findings_txt = (findings_dir / "xxe" / "findings.txt").read_text()
    assert "[XXE-UPLOAD-CONFIRMED]" in findings_txt


def test_xxe_hunt_skips_upload_vector_honestly_when_no_upload_candidates_found(monkeypatch, tmp_path):
    """No findings/upload/active_upload_probe.txt (scanner.sh's upload check
    never ran or found nothing) must degrade gracefully — never fabricate an
    upload endpoint, and never call probe_upload_xxe at all."""
    import interactsh_client
    import tls_impersonation
    import xxe_hunt

    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "urls" / "with_params.txt").write_text("https://victim.example/api?id=1\n")
    findings_dir.mkdir(parents=True)
    _patch_common(monkeypatch, recon_dir, findings_dir)

    monkeypatch.setattr(interactsh_client, "spawn", lambda log_dir: None)
    monkeypatch.setattr(xxe_hunt, "probe_content_type_swap",
                        lambda client, url, body: xxe_hunt.XxeResult(verdict="clean", evidence="no XXE signal"))

    upload_calls = []
    monkeypatch.setattr(xxe_hunt, "probe_upload_xxe", lambda *a, **k: upload_calls.append(a))
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: _FakeHttpClient())

    ok = hunt.run_xxe_hunt("victim.example")
    assert ok is True
    assert upload_calls == []


# ── Critical #2: SAML ACS-URL selection ────────────────────────────────────

_SAMPLE_SAML_RESPONSE = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">
  <saml:Assertion ID="_assertion1">
    <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo/><ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>"""


def test_saml_xsw_selects_acs_shaped_endpoint_not_first_discovered_line(monkeypatch, tmp_path):
    import saml_xsw_tester
    import tls_impersonation

    findings_dir = tmp_path / "findings"
    saml_dir = findings_dir / "saml"
    saml_dir.mkdir(parents=True)
    # scanner.sh's Check 7 discovers /saml/metadata FIRST, the real ACS endpoint
    # second — the old `.read().split()[1]` bug would have picked /saml/metadata.
    (saml_dir / "endpoints.txt").write_text(
        "[SAML-ENDPOINT] https://victim.example/saml/metadata | HTTP 200\n"
        "[SAML-ENDPOINT] https://victim.example/saml/acs | HTTP 200\n"
    )
    captured = tmp_path / "captured.xml"
    captured.write_text(_SAMPLE_SAML_RESPONSE)
    monkeypatch.setenv("VAPT_SAML_CAPTURED_RESPONSE", str(captured))

    monkeypatch.setattr(hunt, "_brain", None, raising=False)
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda d, session_id=None, create=False: str(findings_dir))

    acs_calls = []

    def fake_confirm_new_session(client, acs_url, forged_response_b64, protected_resource_url):
        acs_calls.append(acs_url)
        return saml_xsw_tester.XswResult(confirmed=False, detail="test stub")

    monkeypatch.setattr(saml_xsw_tester, "confirm_new_session", fake_confirm_new_session)
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: _FakeHttpClient())

    ok = hunt.run_saml_xsw("victim.example")

    assert ok is True
    assert acs_calls, "confirm_new_session must have been called at least once"
    assert all(url == "https://victim.example/saml/acs" for url in acs_calls), (
        f"expected every call to use the real ACS endpoint, got {set(acs_calls)}"
    )


def test_saml_xsw_skips_gracefully_when_no_acs_or_login_endpoint_discovered(monkeypatch, tmp_path):
    import saml_xsw_tester
    import tls_impersonation

    findings_dir = tmp_path / "findings"
    saml_dir = findings_dir / "saml"
    saml_dir.mkdir(parents=True)
    # only metadata/sso-init endpoints were discovered — no saml/acs or
    # saml/login shaped endpoint anywhere.
    (saml_dir / "endpoints.txt").write_text(
        "[SAML-ENDPOINT] https://victim.example/saml/metadata | HTTP 200\n"
        "[SAML-ENDPOINT] https://victim.example/sso/init | HTTP 200\n"
    )
    captured = tmp_path / "captured.xml"
    captured.write_text(_SAMPLE_SAML_RESPONSE)
    monkeypatch.setenv("VAPT_SAML_CAPTURED_RESPONSE", str(captured))

    monkeypatch.setattr(hunt, "_brain", None, raising=False)
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda d, session_id=None, create=False: str(findings_dir))

    def _must_not_be_called(*a, **k):
        raise AssertionError("confirm_new_session must not be called against an unresolved ACS URL")

    monkeypatch.setattr(saml_xsw_tester, "confirm_new_session", _must_not_be_called)
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: _FakeHttpClient())

    phase_calls = []
    monkeypatch.setattr(hunt, "_brain_phase_complete",
                        lambda phase, ok, detail="", artifacts=None: phase_calls.append((phase, ok, detail)))

    ok = hunt.run_saml_xsw("victim.example")

    assert ok is True, "a no-ACS-found skip must report success (like the no-captured-assertion skip), not crash"
    assert phase_calls, "_brain_phase_complete must be called on the skip path"
    assert phase_calls[-1][0] == "SAML XSW"
    assert phase_calls[-1][1] is True
    assert "no ACS/login endpoint" in phase_calls[-1][2]


# ── Critical #4: Jolokia reachability ──────────────────────────────────────

def test_actuator_probe_calls_check_jolokia_reachability_for_jolokia_urls_not_spel(monkeypatch, tmp_path):
    import springboot_actuator_probe
    import tls_impersonation

    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "urls" / "sensitive_paths.txt").write_text(
        "https://victim.example/actuator/jolokia/list\n"
    )
    findings_dir.mkdir(parents=True)
    _patch_common(monkeypatch, recon_dir, findings_dir)

    spel_calls = []
    monkeypatch.setattr(
        springboot_actuator_probe, "check_spel_injection",
        lambda client, url: spel_calls.append(url) or springboot_actuator_probe.SpelResult(verdict="clean"),
    )

    jolokia_calls = []

    def fake_check_jolokia_reachability(client, url):
        jolokia_calls.append(url)
        return springboot_actuator_probe.JolokiaResult(reachable=True, mbean_count=3)

    monkeypatch.setattr(springboot_actuator_probe, "check_jolokia_reachability", fake_check_jolokia_reachability)
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: _FakeHttpClient())

    ok = hunt.run_actuator_probe("victim.example")

    assert ok is True
    assert jolokia_calls == ["https://victim.example/actuator/jolokia/list"]
    assert spel_calls == [], "a Jolokia MBean-listing endpoint must never be probed as a SpEL sink"

    findings_txt = (findings_dir / "actuator" / "findings.txt").read_text()
    assert "[JOLOKIA-REACHABLE]" in findings_txt
    assert "mbean_count=3" in findings_txt


def test_actuator_probe_jolokia_unreachable_is_not_logged_as_finding(monkeypatch, tmp_path):
    import springboot_actuator_probe
    import tls_impersonation

    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "urls" / "sensitive_paths.txt").write_text(
        "https://victim.example/actuator/jolokia/list\n"
    )
    findings_dir.mkdir(parents=True)
    _patch_common(monkeypatch, recon_dir, findings_dir)

    monkeypatch.setattr(
        springboot_actuator_probe, "check_jolokia_reachability",
        lambda client, url: springboot_actuator_probe.JolokiaResult(reachable=False),
    )
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: _FakeHttpClient())

    ok = hunt.run_actuator_probe("victim.example")
    assert ok is True
    findings_file = findings_dir / "actuator" / "findings.txt"
    if findings_file.is_file():
        assert "[JOLOKIA-REACHABLE]" not in findings_file.read_text()


# ── Important: LDAP injection skip path dashboard consistency ─────────────

def test_ldap_injection_skip_path_calls_brain_phase_complete(monkeypatch, tmp_path):
    import cve as cve_module

    monkeypatch.setattr(hunt, "_brain", None, raising=False)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda d, session_id=None: str(tmp_path))
    monkeypatch.setattr(cve_module, "detect_technologies", lambda domain, recon_dir=None: {"php": {}})

    phase_calls = []
    monkeypatch.setattr(hunt, "_brain_phase_complete",
                        lambda phase, ok, detail="", artifacts=None: phase_calls.append((phase, ok, detail)))

    result = hunt.run_ldap_injection("victim.example")

    assert result is True
    assert phase_calls, "the stack-fingerprint skip path must call _brain_phase_complete for dashboard consistency"
    assert phase_calls[0][0] == "LDAP INJECTION"
    assert phase_calls[0][1] is True
    assert "ldap" in phase_calls[0][2].lower() or "LDAP" in phase_calls[0][2]

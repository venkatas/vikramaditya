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


# ════════════════════════════════════════════════════════════════════════════
# Fix Round 2 — LDAP builder functions were fully implemented and unit-tested
# (build_rfc4515_fuzz_payloads, build_always_true_bypass_payloads) but
# run_ldap_injection never called either — it only called
# looks_like_ldap_backed_auth (the gate) and run_blind_oracle (which has its
# own hardcoded payload). An entire attack class (LDAP always-true
# auth-bypass) was never exercised. Fixed by wiring both builders into
# run_ldap_injection with real proof-tier discipline: a single differing
# response to an RFC 4515 fuzz payload is a lead only ([LDAP-FUZZ-CANDIDATE]);
# an always-true bypass payload additionally requires the response to look
# like a genuine auth SUCCESS against a baseline that looked like a FAILURE,
# tiered confirmed/candidate via hunt._ldap_bypass_verdict.
# ════════════════════════════════════════════════════════════════════════════

def test_run_ldap_injection_source_calls_both_builder_functions():
    """Source-level regression guard: catches a future revert that deletes
    the call sites while leaving the rest of the function intact."""
    source = inspect.getsource(hunt.run_ldap_injection)
    assert "ldap_injection_tester.build_rfc4515_fuzz_payloads()" in source
    assert "ldap_injection_tester.build_always_true_bypass_payloads(" in source
    # both must feed the SAME baseline run_blind_oracle already establishes --
    # no second baseline fetch inside the per-payload loops.
    assert source.count('client.get(url, params={param: "baseline_probe_value"})') == 1


class _ParamAwareFakeHttpClient:
    """Like _FakeHttpClient, but returns a different canned response keyed by
    the actual query-param VALUE sent -- needed to exercise the fuzz/bypass
    tiering logic, which depends on what payload was actually transmitted,
    not just which URL was hit.

    Fix Round 3: also answers the new _ldap_bypass_verdict verification
    follow-up (a `client.get(url, cookies=...)` call with no `params`) with a
    separately-configurable `followup_response`, so tests can exercise the
    strong-proof tier's re-fetch-with-cookie discipline."""
    def __init__(self, responses_by_value, default_response=None, followup_response=None):
        self._responses_by_value = responses_by_value
        self._default = default_response if default_response is not None else _FakeHttpResponse()
        self._followup_response = followup_response
        self.gets = []

    def get(self, url, params=None, **kwargs):
        self.gets.append((url, {"params": params, **kwargs}))
        if params is None and "cookies" in kwargs:
            return self._followup_response if self._followup_response is not None else self._default
        value = (params or {}).get("q")
        return self._responses_by_value.get(value, self._default)

    def post(self, url, **kwargs):
        raise AssertionError("run_ldap_injection must never POST")


def _setup_ldap_env(monkeypatch, tmp_path, fingerprint_tags):
    import cve as cve_module

    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "urls" / "all.txt").write_text("https://victim.example/login\n")
    findings_dir.mkdir(parents=True)

    monkeypatch.setattr(hunt, "_brain", None, raising=False)
    monkeypatch.setattr(hunt, "_resolve_recon_dir", lambda d, session_id=None: str(recon_dir))
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda d, session_id=None, create=False: str(findings_dir))
    monkeypatch.setattr(cve_module, "detect_technologies",
                        lambda domain, recon_dir=None: {tag: {} for tag in fingerprint_tags})
    return recon_dir, findings_dir


def test_ldap_injection_calls_both_builders_and_sends_every_payload_over_the_wire(monkeypatch, tmp_path):
    """Behavioral test (not source-presence): spies on the REAL module builder
    functions, asserts each is called with real arguments (no args for the
    fuzz builder, the real query-param name for the bypass builder), and
    that every single payload either builder produced was actually
    transmitted as the 'q' query-param value."""
    import ldap_injection_tester
    import tls_impersonation

    _setup_ldap_env(monkeypatch, tmp_path, {"active-directory"})

    real_build_fuzz = ldap_injection_tester.build_rfc4515_fuzz_payloads
    real_build_bypass = ldap_injection_tester.build_always_true_bypass_payloads
    fuzz_calls = []
    bypass_calls = []

    def spy_build_fuzz():
        fuzz_calls.append(())
        return real_build_fuzz()

    def spy_build_bypass(username_field):
        bypass_calls.append(username_field)
        return real_build_bypass(username_field)

    monkeypatch.setattr(ldap_injection_tester, "build_rfc4515_fuzz_payloads", spy_build_fuzz)
    monkeypatch.setattr(ldap_injection_tester, "build_always_true_bypass_payloads", spy_build_bypass)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    fake_client = _FakeHttpClient()  # identical canned response everywhere -> everything "clean"
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True

    assert fuzz_calls == [()], "build_rfc4515_fuzz_payloads must be called exactly once, with no arguments"
    assert bypass_calls == ["q"], (
        "build_always_true_bypass_payloads must be called with the SAME query-param name "
        "run_blind_oracle already uses ('q')"
    )

    sent_values = {kwargs["params"]["q"] for _url, kwargs in fake_client.gets if kwargs.get("params")}
    for payload in real_build_fuzz():
        assert payload in sent_values, f"RFC 4515 fuzz payload {payload!r} was never sent over the wire"
    for payload in real_build_bypass("q"):
        assert payload in sent_values, f"always-true bypass payload {payload!r} was never sent over the wire"


def test_ldap_injection_fuzz_payload_diverging_from_baseline_is_a_candidate_lead(monkeypatch, tmp_path):
    """A single RFC 4515 fuzz payload producing a response that differs from
    baseline is a LEAD (unescaped special char reached the filter), never an
    auto-confirmed finding -- exploitability isn't proven by one divergence."""
    import ldap_injection_tester
    import tls_impersonation

    _, findings_dir = _setup_ldap_env(monkeypatch, tmp_path, {"openldap"})

    baseline_response = _FakeHttpResponse(status_code=200, text="login form")
    fuzz_payload = ldap_injection_tester.build_rfc4515_fuzz_payloads()[0]
    diverging_response = _FakeHttpResponse(status_code=500, text="ldap search filter error")

    fake_client = _ParamAwareFakeHttpClient(
        {"baseline_probe_value": baseline_response, fuzz_payload: diverging_response},
        default_response=baseline_response,
    )
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True

    findings_txt = (findings_dir / "ldap" / "findings.txt").read_text()
    assert "[LDAP-FUZZ-CANDIDATE]" in findings_txt
    assert f"payload={fuzz_payload!r}" in findings_txt
    assert "[LDAP-INJECTION-CONFIRMED]" not in findings_txt
    assert "[LDAP-BYPASS-CONFIRMED]" not in findings_txt
    assert "[LDAP-BYPASS-CANDIDATE]" not in findings_txt


def test_ldap_injection_always_true_payload_success_without_new_session_is_candidate_only(monkeypatch, tmp_path):
    """An always-true payload flipping a failed (401) baseline to a clean 200
    is a real lead, but WITHOUT a fresh session cookie it is only a
    candidate -- never auto-confirmed on a weak signal alone."""
    import ldap_injection_tester
    import tls_impersonation

    _, findings_dir = _setup_ldap_env(monkeypatch, tmp_path, {"ldap-realm"})

    baseline_response = _FakeHttpResponse(status_code=401, text="unauthorized")
    bypass_payload = ldap_injection_tester.build_always_true_bypass_payloads("q")[0]
    success_response = _FakeHttpResponse(status_code=200, text="search results")

    fake_client = _ParamAwareFakeHttpClient(
        {"baseline_probe_value": baseline_response, bypass_payload: success_response},
        default_response=baseline_response,
    )
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True

    findings_txt = (findings_dir / "ldap" / "findings.txt").read_text()
    assert "[LDAP-BYPASS-CANDIDATE]" in findings_txt
    assert f"payload={bypass_payload!r}" in findings_txt
    assert "[LDAP-BYPASS-CONFIRMED]" not in findings_txt


def test_ldap_injection_always_true_payload_with_fresh_session_cookie_is_confirmed(monkeypatch, tmp_path):
    """The strong-proof tier (Fix Round 3): a failed baseline, a payload
    response that looks un-failed AND issues a session-shaped cookie the
    baseline never had, AND a verification re-fetch of the same login url
    with that cookie attached that no longer looks like the failed baseline
    -- the same 'a new session was actually established, verified via a real
    follow-up request' proof saml_xsw_tester.confirm_new_session requires."""
    import ldap_injection_tester
    import tls_impersonation

    _, findings_dir = _setup_ldap_env(monkeypatch, tmp_path, {"adfs"})

    baseline_response = _FakeHttpResponse(status_code=401, text="unauthorized", headers={})
    bypass_payload = ldap_injection_tester.build_always_true_bypass_payloads("q")[1]
    success_response = _FakeHttpResponse(
        status_code=200, text="welcome back",
        headers={"Set-Cookie": "sessionid=abc123; Path=/; HttpOnly"},
    )
    # The verification re-fetch (with the new cookie attached) must itself
    # look genuinely authenticated, not merely "not 401" -- a real target
    # would render distinct authenticated content here.
    verified_followup_response = _FakeHttpResponse(status_code=200, text="welcome back, admin dashboard")

    fake_client = _ParamAwareFakeHttpClient(
        {"baseline_probe_value": baseline_response, bypass_payload: success_response},
        default_response=baseline_response,
        followup_response=verified_followup_response,
    )
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True

    findings_txt = (findings_dir / "ldap" / "findings.txt").read_text()
    assert "[LDAP-BYPASS-CONFIRMED]" in findings_txt
    assert f"payload={bypass_payload!r}" in findings_txt
    # the verification re-fetch must have actually been issued, with the new
    # cookie attached, against the SAME login url (not a fabricated resource).
    followup_calls = [c for c in fake_client.gets if c[1].get("params") is None and "cookies" in c[1]]
    assert followup_calls, "the strong-proof tier must re-fetch the login url with the new cookie attached"
    assert followup_calls[0][0] == "https://victim.example/login"
    # The real cookie NAME/VALUE must be split apart -- a dict keyed "raw"
    # would send a cookie literally named "raw", not "sessionid".
    assert followup_calls[0][1]["cookies"] == {"sessionid": "abc123"}


def test_ldap_injection_always_true_payload_with_analytics_cookie_is_not_confirmed(monkeypatch, tmp_path):
    """Critical #1 adversarial regression: an unrelated Google Analytics
    cookie appearing on the bypass response (but not the baseline) must NEVER
    be treated as session evidence, even though the response itself looks
    un-failed -- this is the exact scenario the reviewer reproduced empirically
    (a mundane analytics cookie previously satisfied the old 'any new
    Set-Cookie' check and produced a fabricated [LDAP-BYPASS-CONFIRMED])."""
    import ldap_injection_tester
    import tls_impersonation

    _, findings_dir = _setup_ldap_env(monkeypatch, tmp_path, {"openldap"})

    baseline_response = _FakeHttpResponse(status_code=200, text="Login failed: invalid credentials", headers={})
    bypass_payload = ldap_injection_tester.build_always_true_bypass_payloads("q")[0]
    analytics_cookie_response = _FakeHttpResponse(
        status_code=200, text="unrelated page content, nothing to do with auth",
        headers={"Set-Cookie": "_ga=GA1.2.123456789.987654321; Path=/"},
    )

    def _must_not_verify(*a, **k):
        raise AssertionError(
            "a known non-auth (analytics) cookie must never trigger the verification re-fetch at all"
        )

    fake_client = _ParamAwareFakeHttpClient(
        {"baseline_probe_value": baseline_response, bypass_payload: analytics_cookie_response},
        default_response=baseline_response,
    )
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True

    findings_txt_path = findings_dir / "ldap" / "findings.txt"
    text = findings_txt_path.read_text() if findings_txt_path.is_file() else ""
    assert "[LDAP-BYPASS-CONFIRMED]" not in text, (
        "an unrelated analytics cookie must never be promoted to LDAP-BYPASS-CONFIRMED"
    )
    # it's still a real lead (response looked un-failed) -- just not verified proof.
    assert "[LDAP-BYPASS-CANDIDATE]" in text
    # no verification re-fetch (cookies=...) call should have been made at all --
    # the reject-list check must short-circuit before ever considering a follow-up.
    followup_calls = [c for c in fake_client.gets if c[1].get("params") is None and "cookies" in c[1]]
    assert followup_calls == []


def test_ldap_injection_always_true_payload_with_csrf_cookie_is_not_confirmed(monkeypatch, tmp_path):
    """Same adversarial case with a CSRF-token-shaped cookie name instead of
    an analytics one -- a CSRF token is minted on every page load (including
    a failed login), so its mere presence on the bypass response proves
    nothing about a new authenticated session."""
    import ldap_injection_tester
    import tls_impersonation

    _, findings_dir = _setup_ldap_env(monkeypatch, tmp_path, {"389-ds"})

    baseline_response = _FakeHttpResponse(status_code=401, text="unauthorized", headers={})
    bypass_payload = ldap_injection_tester.build_always_true_bypass_payloads("q")[0]
    csrf_cookie_response = _FakeHttpResponse(
        status_code=200, text="search results",
        headers={"Set-Cookie": "XSRF-TOKEN=eyJpdiI6IkFCQyJ9; Path=/"},
    )

    fake_client = _ParamAwareFakeHttpClient(
        {"baseline_probe_value": baseline_response, bypass_payload: csrf_cookie_response},
        default_response=baseline_response,
    )
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True

    findings_txt = (findings_dir / "ldap" / "findings.txt").read_text()
    assert "[LDAP-BYPASS-CONFIRMED]" not in findings_txt
    assert "[LDAP-BYPASS-CANDIDATE]" in findings_txt


def test_ldap_injection_session_shaped_cookie_whose_followup_still_fails_is_candidate_only(monkeypatch, tmp_path):
    """A cookie whose NAME looks session-shaped (passes the heuristic) is
    still not proof on its own -- if the verification re-fetch (with that
    cookie attached) still looks like the failure-shaped baseline, this must
    downgrade to candidate, not confirm."""
    import ldap_injection_tester
    import tls_impersonation

    _, findings_dir = _setup_ldap_env(monkeypatch, tmp_path, {"samba-ad"})

    baseline_response = _FakeHttpResponse(status_code=401, text="unauthorized", headers={})
    bypass_payload = ldap_injection_tester.build_always_true_bypass_payloads("q")[1]
    success_response = _FakeHttpResponse(
        status_code=200, text="welcome",
        headers={"Set-Cookie": "JSESSIONID=abc123; Path=/"},
    )
    # the cookie LOOKS real, but replaying it doesn't actually grant access --
    # a stale/rotating cookie, or a cookie that was never bound to a real
    # session server-side.
    still_failed_followup = _FakeHttpResponse(status_code=401, text="unauthorized")

    fake_client = _ParamAwareFakeHttpClient(
        {"baseline_probe_value": baseline_response, bypass_payload: success_response},
        default_response=baseline_response,
        followup_response=still_failed_followup,
    )
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True

    findings_txt = (findings_dir / "ldap" / "findings.txt").read_text()
    assert "[LDAP-BYPASS-CONFIRMED]" not in findings_txt
    assert "[LDAP-BYPASS-CANDIDATE]" in findings_txt


def test_ldap_injection_bypass_payload_still_looking_like_failure_is_clean(monkeypatch, tmp_path):
    """A response that merely DIFFERS from baseline but still carries an
    explicit auth-failure marker (e.g. a differently-worded error page) must
    not be flagged as any tier of bypass -- 'different' is not 'succeeded'."""
    import ldap_injection_tester
    import tls_impersonation

    _, findings_dir = _setup_ldap_env(monkeypatch, tmp_path, {"samba-ad"})

    baseline_response = _FakeHttpResponse(status_code=401, text="unauthorized")
    bypass_payload = ldap_injection_tester.build_always_true_bypass_payloads("q")[2]
    still_failed_response = _FakeHttpResponse(status_code=200, text="Access Denied: invalid credentials")

    fake_client = _ParamAwareFakeHttpClient(
        {"baseline_probe_value": baseline_response, bypass_payload: still_failed_response},
        default_response=baseline_response,
    )
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True

    findings_file = findings_dir / "ldap" / "findings.txt"
    if findings_file.is_file():
        text = findings_file.read_text()
        assert "[LDAP-BYPASS-CONFIRMED]" not in text
        assert "[LDAP-BYPASS-CANDIDATE]" not in text


def test_ldap_injection_phase_complete_detail_reports_all_four_counters(monkeypatch, tmp_path):
    """The dashboard detail string must surface all four independent
    counters (blind-oracle confirmed, fuzz candidates, bypass confirmed,
    bypass candidates) -- not just the original blind-oracle count, or the
    two new attack classes stay invisible on the phase dashboard even when
    they DO find something."""
    import ldap_injection_tester
    import tls_impersonation

    _, findings_dir = _setup_ldap_env(monkeypatch, tmp_path, {"389-ds"})

    baseline_response = _FakeHttpResponse(status_code=401, text="unauthorized")
    fuzz_payload = ldap_injection_tester.build_rfc4515_fuzz_payloads()[0]
    bypass_payload = ldap_injection_tester.build_always_true_bypass_payloads("q")[0]
    fuzz_diverging = _FakeHttpResponse(status_code=500, text="ldap error")
    bypass_success = _FakeHttpResponse(status_code=200, text="results")

    fake_client = _ParamAwareFakeHttpClient(
        {
            "baseline_probe_value": baseline_response,
            fuzz_payload: fuzz_diverging,
            bypass_payload: bypass_success,
        },
        default_response=baseline_response,
    )
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    phase_calls = []
    monkeypatch.setattr(hunt, "_brain_phase_complete",
                        lambda phase, ok, detail="", artifacts=None: phase_calls.append((phase, ok, detail)))

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True
    assert phase_calls
    detail = phase_calls[-1][2]
    assert "fuzz_candidates=1" in detail
    assert "bypass_candidates=1" in detail
    assert "bypass_confirmed=0" in detail
    assert "confirmed=0" in detail


# ════════════════════════════════════════════════════════════════════════════
# Fix Round 3 — Critical #1: _ldap_bypass_verdict's "confirmed" tier was
# gameable by ANY unrelated cookie (analytics/CSRF), because its only "new
# session" test was `response_cookie and not baseline_cookie` with zero check
# that the cookie was actually a session/auth cookie, and zero attempt to
# verify the cookie actually granted authenticated access to anything. Fixed
# by requiring BOTH: (1) the new cookie's NAME looks session/auth-shaped and
# is not a known analytics/CSRF cookie, and (2) re-fetching the same login
# `url` with that cookie attached produces a response that no longer looks
# like the failure-shaped baseline -- this is the real "mirrors
# confirm_new_session" discipline the old docstring only claimed to have.
# The signature changed from (response, baseline) to (client, url, response,
# baseline) to support that verification re-fetch.
# ════════════════════════════════════════════════════════════════════════════

class _FollowupFakeClient:
    """Minimal client double for hunt._ldap_bypass_verdict's unit tests: only
    ever expects the verification re-fetch call (`client.get(url,
    cookies=...)`) -- raises if called any other way, so a test that expects
    NO verification call (e.g. the reject-listed-cookie case) can assert
    on `calls == []` and a test that expects one can assert on its args."""
    def __init__(self, followup_response=None):
        self._followup_response = followup_response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if "cookies" not in kwargs:
            raise AssertionError("_ldap_bypass_verdict must only re-fetch WITH the new cookie attached")
        return self._followup_response


_LOGIN_URL = "https://victim.example/login"


def test_ldap_bypass_verdict_clean_when_baseline_does_not_look_failed():
    baseline = _FakeHttpResponse(status_code=200, text="search page")
    response = _FakeHttpResponse(status_code=200, text="something else entirely")
    client = _FollowupFakeClient()
    assert hunt._ldap_bypass_verdict(client, _LOGIN_URL, response, baseline) == "clean"
    assert client.calls == [], "must never issue a verification request when the baseline never looked failed"


def test_ldap_bypass_verdict_clean_when_response_is_a_redirect():
    baseline = _FakeHttpResponse(status_code=401, text="unauthorized")
    response = _FakeHttpResponse(status_code=302, text="", headers={"Location": "/login"})
    client = _FollowupFakeClient()
    assert hunt._ldap_bypass_verdict(client, _LOGIN_URL, response, baseline) == "clean"
    assert client.calls == []


def test_ldap_bypass_verdict_clean_when_response_still_carries_a_failure_marker():
    baseline = _FakeHttpResponse(status_code=403, text="access denied")
    response = _FakeHttpResponse(status_code=200, text="Please log in to continue")
    client = _FollowupFakeClient()
    assert hunt._ldap_bypass_verdict(client, _LOGIN_URL, response, baseline) == "clean"
    assert client.calls == []


def test_ldap_bypass_verdict_candidate_on_clean_success_without_cookie():
    baseline = _FakeHttpResponse(status_code=401, text="unauthorized")
    response = _FakeHttpResponse(status_code=200, text="welcome")
    client = _FollowupFakeClient()
    assert hunt._ldap_bypass_verdict(client, _LOGIN_URL, response, baseline) == "candidate"
    assert client.calls == [], "no new cookie at all -- nothing to verify"


def test_ldap_bypass_verdict_confirmed_on_fresh_session_cookie_with_verified_followup():
    """The strong-proof tier: a session-shaped new cookie AND a verification
    re-fetch (with that cookie attached) that no longer looks like the failed
    baseline."""
    baseline = _FakeHttpResponse(status_code=401, text="unauthorized", headers={})
    response = _FakeHttpResponse(status_code=200, text="welcome",
                                  headers={"Set-Cookie": "sessionid=xyz; Path=/"})
    followup = _FakeHttpResponse(status_code=200, text="welcome back, authenticated dashboard")
    client = _FollowupFakeClient(followup_response=followup)
    assert hunt._ldap_bypass_verdict(client, _LOGIN_URL, response, baseline) == "confirmed"
    assert client.calls == [(_LOGIN_URL, {"cookies": {"sessionid": "xyz"}})], (
        "must re-fetch the SAME login url with the real cookie NAME/VALUE split apart -- "
        "a dict keyed 'raw' would send a cookie literally named 'raw', not 'sessionid'"
    )


def test_ldap_bypass_verdict_candidate_when_session_cookie_followup_still_looks_failed():
    """Session-shaped cookie NAME is necessary but not sufficient -- if the
    verification re-fetch still looks like the failure-shaped baseline (the
    cookie didn't actually grant anything), this must downgrade to candidate,
    never confirm on the cookie's mere presence."""
    baseline = _FakeHttpResponse(status_code=401, text="unauthorized", headers={})
    response = _FakeHttpResponse(status_code=200, text="welcome",
                                  headers={"Set-Cookie": "sessionid=xyz; Path=/"})
    followup = _FakeHttpResponse(status_code=401, text="unauthorized")
    client = _FollowupFakeClient(followup_response=followup)
    assert hunt._ldap_bypass_verdict(client, _LOGIN_URL, response, baseline) == "candidate"


def test_ldap_bypass_verdict_candidate_not_confirmed_when_baseline_already_had_a_cookie():
    """If the baseline probe ALSO got a Set-Cookie (e.g. a generic
    tracking/session cookie issued to every visitor), that is not evidence
    of a NEW authenticated session -- must not over-claim 'confirmed'."""
    baseline = _FakeHttpResponse(status_code=401, text="unauthorized",
                                  headers={"Set-Cookie": "trackingid=anon; Path=/"})
    response = _FakeHttpResponse(status_code=200, text="welcome",
                                  headers={"Set-Cookie": "trackingid=anon; Path=/"})
    client = _FollowupFakeClient()
    assert hunt._ldap_bypass_verdict(client, _LOGIN_URL, response, baseline) == "candidate"
    assert client.calls == [], "an unchanged cookie is not a NEW session -- nothing to verify"


# ── Adversarial regressions: the reviewer's empirically-reproduced case ────

def test_ldap_bypass_verdict_analytics_cookie_is_never_confirmed_and_never_verified():
    """The reviewer's exact empirical repro: a baseline failed-login response
    (200, 'Login failed: invalid credentials', no cookie) vs. a bypass
    response that is ALSO just 200 with unrelated content but sets an
    unrelated Google Analytics _ga cookie. Must NOT be 'confirmed' -- and
    must not even trigger a verification re-fetch, since an explicitly
    reject-listed cookie name is not counted as any signal at all."""
    baseline = _FakeHttpResponse(status_code=200, text="Login failed: invalid credentials", headers={})
    response = _FakeHttpResponse(
        status_code=200, text="unrelated marketing page content",
        headers={"Set-Cookie": "_ga=GA1.2.111111111.222222222; Path=/; Domain=.victim.example"},
    )
    client = _FollowupFakeClient()
    assert hunt._ldap_bypass_verdict(client, _LOGIN_URL, response, baseline) == "candidate"
    assert client.calls == []


def test_ldap_bypass_verdict_csrf_token_cookie_is_never_confirmed():
    """A CSRF token cookie is minted on every page load, including a failed
    one -- its mere presence on the bypass response (but not baseline) must
    never be treated as new-session proof, even though its name contains
    'token' (a session-shaped marker) -- the reject-list must take priority."""
    baseline = _FakeHttpResponse(status_code=401, text="unauthorized", headers={})
    response = _FakeHttpResponse(
        status_code=200, text="search results",
        headers={"Set-Cookie": "csrftoken=abcdef0123456789; Path=/"},
    )
    client = _FollowupFakeClient()
    assert hunt._ldap_bypass_verdict(client, _LOGIN_URL, response, baseline) == "candidate"
    assert client.calls == []


def test_ldap_looks_like_session_cookie_rejects_analytics_and_csrf_names():
    assert hunt._ldap_looks_like_session_cookie("_ga") is False
    assert hunt._ldap_looks_like_session_cookie("_gid") is False
    assert hunt._ldap_looks_like_session_cookie("_fbp") is False
    assert hunt._ldap_looks_like_session_cookie("csrftoken") is False
    assert hunt._ldap_looks_like_session_cookie("XSRF-TOKEN") is False


def test_ldap_looks_like_session_cookie_accepts_real_session_cookie_shapes():
    assert hunt._ldap_looks_like_session_cookie("JSESSIONID") is True
    assert hunt._ldap_looks_like_session_cookie("PHPSESSID") is True
    assert hunt._ldap_looks_like_session_cookie("ASP.NET_SessionId") is True
    assert hunt._ldap_looks_like_session_cookie("sessionid") is True
    assert hunt._ldap_looks_like_session_cookie("sid") is True
    assert hunt._ldap_looks_like_session_cookie("auth_token") is True


# ════════════════════════════════════════════════════════════════════════════
# Fix Round 3 — Critical #2: tls_impersonation.detect_bot_management() /
# record_waf_block() were fully implemented and unit-tested (Task 2) but never
# called from any of hunt.py's 6 live-HTTP-issuing Task-9 call sites (xxe_hunt,
# open_redirect_hunt, saml_xsw, actuator_probe, ldap_injection, and the
# jwt_kid_injection extension). A 403/429/503 bot-management block mid-scan
# was silently indistinguishable from a genuinely clean target. These tests
# exercise the REAL tls_impersonation functions (not mocked) against a
# Cloudflare-shaped blocked response and confirm the coverage note actually
# lands in <findings_dir>/misconfig/waf_fingerprint.txt, recorded at most
# once per phase.
# ════════════════════════════════════════════════════════════════════════════

def _cloudflare_block_response(status_code=403):
    return _FakeHttpResponse(
        status_code=status_code, text="Attention Required! | Cloudflare",
        headers={"cf-ray": "89abcdef1234-DEL", "Server": "cloudflare"},
    )


def test_ldap_injection_records_waf_block_on_cloudflare_baseline_via_real_tls_impersonation(monkeypatch, tmp_path):
    """run_ldap_injection's baseline probe is a real, direct client.get -- a
    bot-management block on it must be recorded via the REAL (unmocked)
    tls_impersonation.detect_bot_management/record_waf_block, exactly once
    per phase even though many further requests hit the same blocked client."""
    import ldap_injection_tester
    import tls_impersonation

    _, findings_dir = _setup_ldap_env(monkeypatch, tmp_path, {"openldap"})

    blocked = _cloudflare_block_response()
    fake_client = _FakeHttpClient(response=blocked)  # every .get/.post returns the SAME blocked response
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)
    monkeypatch.setattr(ldap_injection_tester, "run_blind_oracle",
                        lambda client, url, param, baseline: ldap_injection_tester.OracleResult(confirmed=False))

    ok = hunt.run_ldap_injection("victim.example")
    assert ok is True

    waf_path = findings_dir / "misconfig" / "waf_fingerprint.txt"
    assert waf_path.is_file(), "a WAF-blocked phase must write a coverage note via tls_impersonation.record_waf_block"
    text = waf_path.read_text()
    assert "[WAF-BLOCK-DETECTED]" in text
    assert "product=cloudflare" in text
    assert "https://victim.example/login" in text
    assert text.count("[WAF-BLOCK-DETECTED]") == 1, "must be recorded once per phase, not once per request"


def test_xxe_hunt_records_waf_block_on_blocked_oob_post_via_real_tls_impersonation(monkeypatch, tmp_path):
    """The blind-OOB variant POST inside run_xxe_hunt is a real, direct
    client.post -- a bot-management block on it must be recorded via the
    REAL (unmocked) tls_impersonation functions."""
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
    monkeypatch.setattr(xxe_hunt, "confirm_blind_oob",
                        lambda session, token: xxe_hunt.XxeResult(verdict="candidate", evidence="no callback yet"))
    # content-type-swap probe itself is clean/unblocked -- only the OOB POST
    # (a raw client.post hunt.py issues directly) is blocked.
    monkeypatch.setattr(
        xxe_hunt, "probe_content_type_swap",
        lambda client, url, body: xxe_hunt.XxeResult(
            verdict="clean", evidence="no XXE signal", response=_FakeHttpResponse(status_code=200)),
    )

    blocked = _cloudflare_block_response()
    fake_client = _FakeHttpClient(response=blocked)
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)

    ok = hunt.run_xxe_hunt("victim.example")
    assert ok is True

    waf_path = findings_dir / "misconfig" / "waf_fingerprint.txt"
    assert waf_path.is_file()
    text = waf_path.read_text()
    assert "[WAF-BLOCK-DETECTED]" in text
    assert "product=cloudflare" in text


def test_actuator_probe_records_waf_block_on_blocked_env_fetch_via_real_tls_impersonation(monkeypatch, tmp_path):
    """The /actuator/env branch inside run_actuator_probe is a real, direct
    client.get -- a bot-management block on it must be recorded via the REAL
    (unmocked) tls_impersonation functions."""
    import springboot_actuator_probe
    import tls_impersonation

    recon_dir = tmp_path / "recon"
    findings_dir = tmp_path / "findings"
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "urls" / "sensitive_paths.txt").write_text("https://victim.example/actuator/env\n")
    findings_dir.mkdir(parents=True)
    _patch_common(monkeypatch, recon_dir, findings_dir)

    blocked = _cloudflare_block_response()
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: _FakeHttpClient(response=blocked))

    ok = hunt.run_actuator_probe("victim.example")
    assert ok is True

    waf_path = findings_dir / "misconfig" / "waf_fingerprint.txt"
    assert waf_path.is_file()
    text = waf_path.read_text()
    assert "[WAF-BLOCK-DETECTED]" in text
    assert "product=cloudflare" in text


def test_saml_xsw_records_waf_block_on_blocked_acs_response_via_real_tls_impersonation(monkeypatch, tmp_path):
    """confirm_new_session itself is NOT mocked here -- the ACS POST is a
    real, direct client.post issued by the real saml_xsw_tester module. A
    bot-management block on it (403, no Set-Cookie) must be recorded via the
    REAL (unmocked) tls_impersonation functions."""
    import saml_xsw_tester
    import tls_impersonation

    findings_dir = tmp_path / "findings"
    saml_dir = findings_dir / "saml"
    saml_dir.mkdir(parents=True)
    (saml_dir / "endpoints.txt").write_text(
        "[SAML-ENDPOINT] https://victim.example/saml/acs | HTTP 200\n"
    )
    captured = tmp_path / "captured.xml"
    captured.write_text(_SAMPLE_SAML_RESPONSE)
    monkeypatch.setenv("VAPT_SAML_CAPTURED_RESPONSE", str(captured))

    monkeypatch.setattr(hunt, "_brain", None, raising=False)
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda d, session_id=None, create=False: str(findings_dir))

    blocked = _cloudflare_block_response()
    fake_client = _FakeHttpClient(response=blocked)  # ACS POST returns a 403 cloudflare block, no Set-Cookie
    monkeypatch.setattr(tls_impersonation, "get_client", lambda **kw: fake_client)

    ok = hunt.run_saml_xsw("victim.example")
    assert ok is True

    waf_path = findings_dir / "misconfig" / "waf_fingerprint.txt"
    assert waf_path.is_file()
    text = waf_path.read_text()
    assert "[WAF-BLOCK-DETECTED]" in text
    assert "product=cloudflare" in text

"""ldap_injection_tester — RFC 4515 fuzz + blind true/false-oracle, gated on a
stack-fingerprint check so it never wastes cycles/FPs on non-LDAP-backed logins.

FP discipline: detection uses BASELINE-DIFF (compare against a captured baseline
response), not raw error-string matching, and the blind oracle requires a stable
control (a query engineered to always evaluate false) plus a 3x-repeat before
confirming — a single anomalous response is not enough.
"""
import ldap_injection_tester as lit


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self._responses.pop(0) if self._responses else _FakeResponse(200, "")


def test_looks_like_ldap_backed_auth_true_for_ad_fingerprint():
    assert lit.looks_like_ldap_backed_auth({"active-directory", "adfs"}) is True


def test_looks_like_ldap_backed_auth_true_for_java_enterprise():
    assert lit.looks_like_ldap_backed_auth({"spring-security", "ldap-realm"}) is True


def test_looks_like_ldap_backed_auth_false_for_unrelated_stack():
    assert lit.looks_like_ldap_backed_auth({"wordpress", "php"}) is False


def test_build_rfc4515_fuzz_payloads_includes_special_chars():
    payloads = lit.build_rfc4515_fuzz_payloads()
    assert any("*" in p for p in payloads)
    assert any("(" in p and ")" in p for p in payloads)
    assert any("\\" in p for p in payloads)


def test_build_always_true_bypass_payloads_are_paren_balanced():
    payloads = lit.build_always_true_bypass_payloads("username")
    for p in payloads:
        assert p.count("(") == p.count(")")
    assert any("*)(uid=*" in p or "*)(|(uid=*" in p for p in payloads)


def test_blind_oracle_confirms_only_after_stable_false_control_and_repeat():
    # Baseline (control-false) always returns short/clean; true-condition query
    # returns a distinguishably longer/different response, repeated 3x consistently.
    baseline = _FakeResponse(200, "no results")
    responses = [
        _FakeResponse(200, "no results"),   # stable-FALSE control check 1
        _FakeResponse(200, "1 result found"),  # true-condition attempt 1
        _FakeResponse(200, "no results"),   # stable-FALSE control check 2
        _FakeResponse(200, "1 result found"),  # true-condition attempt 2
        _FakeResponse(200, "no results"),   # stable-FALSE control check 3
        _FakeResponse(200, "1 result found"),  # true-condition attempt 3
    ]
    client = _FakeClient(responses)
    result = lit.run_blind_oracle(client, "https://example.com/search?q=X", "q", baseline)
    assert result.confirmed is True


def test_blind_oracle_not_confirmed_when_inconsistent_across_repeats():
    baseline = _FakeResponse(200, "no results")
    responses = [
        _FakeResponse(200, "no results"),
        _FakeResponse(200, "1 result found"),
        _FakeResponse(200, "no results"),
        _FakeResponse(200, "no results"),  # inconsistent — should have differed
        _FakeResponse(200, "no results"),
        _FakeResponse(200, "1 result found"),
    ]
    client = _FakeClient(responses)
    result = lit.run_blind_oracle(client, "https://example.com/search?q=X", "q", baseline)
    assert result.confirmed is False


def test_blind_oracle_not_confirmed_when_control_diverges_in_final_round():
    # This is the module's central anti-false-positive guarantee: a
    # stable-FALSE control is required in EVERY round, including the last.
    # Rounds 1-2 look perfect (control matches baseline, true-condition
    # diverges). Round 3's CONTROL query unexpectedly diverges from the
    # baseline — simulating transient server flakiness, NOT an injection
    # signal — while round 3's true-condition query ALSO happens to diverge
    # from baseline, coincidentally, for unrelated reasons. Because the
    # control's stability was violated in round 3, the whole oracle must
    # abort with confirmed=False — two good earlier rounds do not excuse a
    # late-round control failure, and "3 rounds ran" alone is not sufficient.
    baseline = _FakeResponse(200, "no results")
    responses = [
        _FakeResponse(200, "no results"),        # round 1 control: stable
        _FakeResponse(200, "1 result found"),    # round 1 true-condition: diverges
        _FakeResponse(200, "no results"),        # round 2 control: stable
        _FakeResponse(200, "1 result found"),    # round 2 true-condition: diverges
        _FakeResponse(200, "transient error"),   # round 3 control: UNEXPECTEDLY diverges (flakiness)
        _FakeResponse(200, "unrelated result"),  # round 3 true-condition: also diverges (coincidence)
    ]
    client = _FakeClient(responses)
    result = lit.run_blind_oracle(client, "https://example.com/search?q=X", "q", baseline)
    assert result.confirmed is False
    # Exactly 5 client calls should have happened: round1 (control+true),
    # round2 (control+true), round3 (control only — the true-condition probe
    # for round 3 is never reached because the control check aborts first).
    assert len(client.calls) == 5

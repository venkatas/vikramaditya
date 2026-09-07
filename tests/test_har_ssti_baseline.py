"""har_vapt_engine SSTI detection must require EVALUATION, not a bare substring.

friends full-tool review F4: SSTI was declared CRITICAL whenever the response
contained the substring ``49`` after injecting ``{{7*7}}`` — no baseline, no
distinctive canary, no reflection guard. Any page with ``49`` in it (a price, an
id, "49 results") was a fabricated CRITICAL. The probe must use a distinctive
arithmetic canary, confirm the product is ABSENT from a baseline response, and
require the raw expression NOT to be reflected verbatim.

All test data is SYNTHETIC (example.invalid).
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import har_vapt_engine as hve  # noqa: E402


class _Resp:
    def __init__(self, text):
        self.text = text
        self.status_code = 200


class _ReflectSession:
    """Echoes the injected value verbatim (reflection) and always contains '49'
    naturally. A correct probe must NOT flag this as SSTI."""
    def _render(self, params):
        return "search: 49 results found — " + " ".join(str(v) for v in (params or {}).values())

    def post(self, url, data=None, timeout=None, **k):
        return _Resp(self._render(data))

    def get(self, url, params=None, timeout=None, **k):
        return _Resp(self._render(params))


class _EvalSession:
    """Actually evaluates a ``{{a*b}}`` / ``${a*b}`` template to its product."""
    _rx = re.compile(r'^\$?\{\{?(\d+)\s*\*\s*(\d+)\}?\}$')

    def _render(self, params):
        out = ["page"]
        for v in (params or {}).values():
            m = self._rx.match(str(v))
            out.append(str(int(m.group(1)) * int(m.group(2))) if m else str(v))
        return " ".join(out)

    def post(self, url, data=None, timeout=None, **k):
        return _Resp(self._render(data))

    def get(self, url, params=None, timeout=None, **k):
        return _Resp(self._render(params))


def _engine(session):
    eng = hve.HARVAPTEngine({"config": {"target_domain": "t.example.invalid"}})
    eng.session = session
    return eng


def test_ssti_reflection_with_incidental_49_not_flagged():
    eng = _engine(_ReflectSession())
    eng._probe_ssti("https://t.example.invalid/x", "GET", {}, "q")
    assert not any(str(v["type"]).startswith("SSTI") for v in eng.vulnerabilities), (
        "a reflected (un-evaluated) template on a page that merely contains '49' "
        "must not be flagged as SSTI")


def test_ssti_real_evaluation_is_flagged():
    eng = _engine(_EvalSession())
    eng._probe_ssti("https://t.example.invalid/x", "GET", {}, "q")
    assert any(str(v["type"]).startswith("SSTI") for v in eng.vulnerabilities), (
        "a genuinely evaluated template expression must be flagged as SSTI")

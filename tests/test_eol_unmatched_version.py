"""
Regression test for the EOL false-negative where a supplied version that fails
numeric-prefix matching against any cycle was silently classified against the
newest cycle and reported "supported".

All data here is SYNTHETIC.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import eol_check


# Synthetic cycles, newest-first (as endoflife.date returns them). The newest
# cycle is "supported", an older cycle is long EOL.
_FAKE_CYCLES = [
    {"cycle": "8.3", "latest": "8.3.1", "eol": False},
    {"cycle": "8.2", "latest": "8.2.5", "eol": "2030-12-31"},
    {"cycle": "5.6", "latest": "5.6.40", "eol": True},   # long EOL
]


def _patch(monkeypatch, slug_key="php"):
    monkeypatch.setattr(eol_check, "fetch_product_cycles",
                        lambda slug, refresh=False: list(_FAKE_CYCLES))
    # Ensure the term resolves to a slug.
    assert slug_key in eol_check.PRODUCT_MAP


def test_unmatched_version_does_not_fabricate_supported(monkeypatch):
    """`php=5` matches no cycle ((5,) != (5,6)); must NOT report 'supported'."""
    _patch(monkeypatch)
    r = eol_check.lookup("php", "5")
    assert r["status"] == "unknown", r
    assert r["matched_cycle"] is None
    assert r["cycle_inferred"] is False


def test_matched_version_reports_eol_truthfully(monkeypatch):
    """`php=5.6` cleanly prefix-matches the EOL cycle -> expired."""
    _patch(monkeypatch)
    r = eol_check.lookup("php", "5.6.40")
    assert r["status"] == "expired", r
    assert r["matched_cycle"]["cycle"] == "5.6"
    assert r["cycle_inferred"] is False


def test_matched_supported_version(monkeypatch):
    _patch(monkeypatch)
    r = eol_check.lookup("php", "8.3.1")
    assert r["status"] == "supported", r
    assert r["matched_cycle"]["cycle"] == "8.3"
    assert r["cycle_inferred"] is False


def test_no_version_infers_newest_cycle_flagged(monkeypatch):
    """No version supplied: newest cycle is a hint, must be flagged inferred."""
    _patch(monkeypatch)
    r = eol_check.lookup("php")
    assert r["matched_cycle"]["cycle"] == "8.3"
    assert r["cycle_inferred"] is True


if __name__ == "__main__":
    import sys
    import types

    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, val):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, val)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)
            self._undo.clear()

    for fn in [test_unmatched_version_does_not_fabricate_supported,
               test_matched_version_reports_eol_truthfully,
               test_matched_supported_version,
               test_no_version_infers_newest_cycle_flagged]:
        mp = _MP()
        try:
            fn(mp)
            print(f"PASS {fn.__name__}")
        finally:
            mp.undo()
    print("all passed")

#!/usr/bin/env python3
"""Regression: test_negative_values must fuzz EVERY numeric field, not just the
first 3 (previously `numeric_fields[:3]` silently dropped 4th+ numeric keys).

Synthetic data only — no real targets.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import business_logic_tester as blt


class _StubSession:
    """Records every field that gets mutated in a POST body."""

    def __init__(self):
        self.fuzzed_fields = set()

    def request(self, method, path, token=None, json_body=None):
        body = json_body or {}
        # Whichever numeric field differs from a sentinel baseline got fuzzed.
        for k, v in body.items():
            if isinstance(v, (int, float)) and v in (-1, -999, -2147483648, 0):
                self.fuzzed_fields.add(k)
        return {"status": 400, "body": {}, "url": path}


def test_all_numeric_fields_are_fuzzed():
    # 5 numeric fields => 4th and 5th must NOT be silently skipped.
    endpoints = [{
        "path": "submit/",
        "body": {
            "a": 10,
            "b": 20,
            "c": 30,
            "amount": 40,      # 4th numeric field — was dropped by [:3]
            "total_score": 50,  # 5th numeric field — was dropped by [:3]
            "name": "acme",    # non-numeric, must be ignored
        },
    }]
    session = _StubSession()
    blt.test_negative_values(session, token="placeholder-token", endpoints=endpoints)

    assert session.fuzzed_fields == {"a", "b", "c", "amount", "total_score"}, (
        f"expected all 5 numeric fields fuzzed, got {sorted(session.fuzzed_fields)}"
    )


if __name__ == "__main__":
    test_all_numeric_fields_are_fuzzed()
    print("PASS")

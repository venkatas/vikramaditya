#!/usr/bin/env python3
"""Regression tests for idor_mutator.py safety gates.

Covers two confirmed audit findings:
  1. make_ctx() must VERIFY TLS by default (cert validation on) and only
     disable verification behind the explicit --insecure path.
  2. Destructive Phase 2/5 mutations must be FAIL-CLOSED: skipped unless
     --confirm-mutations is supplied AND the operator confirms.

All data here is SYNTHETIC.
"""
import argparse
import ssl
import types

import idor_mutator


# -- Finding 1: TLS verification -------------------------------------------

def test_make_ctx_verifies_by_default():
    ctx = idor_mutator.make_ctx()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_make_ctx_insecure_opt_in_only():
    ctx = idor_mutator.make_ctx(insecure=True)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE


# -- Finding 2: mutation gate is fail-closed -------------------------------

def _args(**over):
    base = dict(confirm_mutations=False, dry_run=False)
    base.update(over)
    return argparse.Namespace(**base)


def test_mutations_skipped_by_default():
    # No flags -> must NOT fire.
    assert idor_mutator._confirm_mutations(
        _args(), "1234", "gid://placeholder") is False


def test_dry_run_never_fires():
    assert idor_mutator._confirm_mutations(
        _args(dry_run=True, confirm_mutations=True),
        "1234", "gid://placeholder") is False


def test_confirm_requires_interactive_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "no")
    assert idor_mutator._confirm_mutations(
        _args(confirm_mutations=True), "1234", "gid://placeholder") is False

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "yes")
    assert idor_mutator._confirm_mutations(
        _args(confirm_mutations=True), "1234", "gid://placeholder") is True


def test_confirm_eof_fails_closed(monkeypatch):
    def _raise(*_a, **_k):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise)
    assert idor_mutator._confirm_mutations(
        _args(confirm_mutations=True), "1234", "gid://placeholder") is False


if __name__ == "__main__":
    import sys
    import pytest

    sys.exit(pytest.main([__file__, "-v"]))

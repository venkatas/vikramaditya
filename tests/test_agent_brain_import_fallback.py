"""agent.py — OLLAMA_HOST / MODEL_PRIORITY / BRAIN_SYSTEM must ALWAYS be bound at
module scope, even when brain.py fails to import. Previously the fallback definitions
lived under the (independent) coverage_gate import-except, so a brain import failure
left these names undefined -> NameError in ReActAgent.__init__ on every agent run.

This test reloads agent with brain import forced to fail and asserts the three
constants are still defined.

Offline test. Synthetic data only.
"""
import builtins
import importlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_real_import = builtins.__import__


def _make_failing_import(blocked):
    def _fake_import(name, *a, **kw):
        if name == blocked or name.startswith(blocked + "."):
            raise ImportError(f"forced failure importing {name}")
        return _real_import(name, *a, **kw)
    return _fake_import


def test_constants_defined_even_when_brain_import_fails(monkeypatch):
    # Force `from brain import ...` to raise while coverage_gate imports fine.
    monkeypatch.setattr(builtins, "__import__", _make_failing_import("brain"))
    sys.modules.pop("agent", None)
    sys.modules.pop("brain", None)
    try:
        mod = importlib.import_module("agent")
    finally:
        # Restore real import for any subsequent reloads.
        monkeypatch.setattr(builtins, "__import__", _real_import)

    assert mod._BRAIN_OK is False, "brain import was forced to fail"
    assert hasattr(mod, "OLLAMA_HOST"), "OLLAMA_HOST must be defined as a brain fallback"
    assert hasattr(mod, "MODEL_PRIORITY"), "MODEL_PRIORITY must be defined as a brain fallback"
    assert hasattr(mod, "BRAIN_SYSTEM"), "BRAIN_SYSTEM must be defined as a brain fallback"
    assert isinstance(mod.OLLAMA_HOST, str) and mod.OLLAMA_HOST
    assert isinstance(mod.MODEL_PRIORITY, list) and mod.MODEL_PRIORITY

    # Clean reload so other tests get the normally-imported module.
    sys.modules.pop("agent", None)
    sys.modules.pop("brain", None)
    importlib.import_module("agent")

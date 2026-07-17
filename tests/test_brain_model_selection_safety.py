"""Model-selection must NOT silently substitute a different model for an explicit pin.

ROOT CAUSE (friends review, 2026-07-16): if BRAIN_MODEL / TRIAGE_MODEL is set but the pinned
tag is NOT installed, `_pick_model` / `_pick_triage_model` silently fell through to the priority
list (and ultimately `available[0]`). For a client-facing vuln-triage gate that silently means
"you pinned OpenMythos but you're actually running baron-llm and were never told." A pinned model
that is missing must be LOUD, and — under BRAIN_REQUIRE_PIN=1 (client/autonomous runs) — FATAL.
Selection provenance (which model + why) is recorded so a report can be audited later.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import brain  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("BRAIN_MODEL", "TRIAGE_MODEL", "BRAIN_REQUIRE_PIN"):
        monkeypatch.delenv(k, raising=False)
    brain.MODEL_SELECTION_LOG.clear()
    yield


def _avail(monkeypatch, models):
    monkeypatch.setattr(brain, "_get_available_models", lambda: list(models))


# ── pin present & installed ─────────────────────────────────────────────────
def test_pin_installed_is_used_and_recorded(monkeypatch):
    _avail(monkeypatch, ["openmythos-27b:latest", "qwen3:14b"])
    monkeypatch.setenv("BRAIN_MODEL", "openmythos-27b:latest")
    assert brain._pick_model() == "openmythos-27b:latest"
    assert brain.MODEL_SELECTION_LOG["narrator"]["source"] == "pinned"


# ── pin set but NOT installed → must NOT silently substitute ─────────────────
def test_narrator_pin_missing_warns_and_records_fallback(monkeypatch, capsys):
    _avail(monkeypatch, ["qwen3:14b", "baron-llm:latest"])  # pinned model absent
    monkeypatch.setenv("BRAIN_MODEL", "openmythos-27b:latest")
    picked = brain._pick_model()
    assert picked != "openmythos-27b:latest"          # it fell back
    err = capsys.readouterr().err
    assert "openmythos-27b:latest" in err and "NOT installed" in err  # LOUD warning
    prov = brain.MODEL_SELECTION_LOG["narrator"]
    assert prov["requested_pin"] == "openmythos-27b:latest"
    assert prov["source"] in ("pin-missing-fallback", "pin-missing-priority", "pin-missing-last-resort")
    assert prov["model"] == picked


def test_triage_pin_missing_warns(monkeypatch, capsys):
    _avail(monkeypatch, ["qwen3:14b", "baron-llm:latest"])
    monkeypatch.setenv("TRIAGE_MODEL", "openmythos-27b:latest")
    picked = brain._pick_triage_model()
    assert picked != "openmythos-27b:latest"
    assert "NOT installed" in capsys.readouterr().err
    assert brain.MODEL_SELECTION_LOG["triage"]["requested_pin"] == "openmythos-27b:latest"


# ── strict mode: pin missing is FATAL ───────────────────────────────────────
def test_strict_narrator_pin_missing_raises(monkeypatch):
    _avail(monkeypatch, ["qwen3:14b"])
    monkeypatch.setenv("BRAIN_MODEL", "openmythos-27b:latest")
    monkeypatch.setenv("BRAIN_REQUIRE_PIN", "1")
    with pytest.raises(RuntimeError, match="openmythos-27b:latest"):
        brain._pick_model()


def test_strict_triage_pin_missing_raises(monkeypatch):
    _avail(monkeypatch, ["qwen3:14b"])
    monkeypatch.setenv("TRIAGE_MODEL", "openmythos-27b:latest")
    monkeypatch.setenv("BRAIN_REQUIRE_PIN", "1")
    with pytest.raises(RuntimeError, match="openmythos-27b:latest"):
        brain._pick_triage_model()


# ── no pin → priority list, provenance recorded, no false warning ───────────
def test_no_pin_uses_priority_and_records(monkeypatch, capsys):
    _avail(monkeypatch, ["qwen3:14b", "baron-llm:latest"])
    picked = brain._pick_model()
    assert picked in ("qwen3:14b", "baron-llm:latest")
    assert "NOT installed" not in capsys.readouterr().err   # no spurious warning when no pin set
    assert brain.MODEL_SELECTION_LOG["narrator"]["source"] in ("priority", "last-resort")


# ── review fix: :latest alias must match (grok#2 / codex#5) ──────────────────
def test_pin_untagged_matches_installed_latest(monkeypatch, capsys):
    _avail(monkeypatch, ["openmythos-27b:latest", "qwen3:14b"])
    monkeypatch.setenv("BRAIN_MODEL", "openmythos-27b")          # pinned WITHOUT :latest
    assert brain._pick_model() == "openmythos-27b:latest"        # must resolve, not fall back
    assert "NOT installed" not in capsys.readouterr().err
    assert brain.MODEL_SELECTION_LOG["narrator"]["source"] == "pinned"


def test_pin_untagged_alias_not_wrongly_raised_in_strict(monkeypatch):
    _avail(monkeypatch, ["openmythos-27b:latest"])
    monkeypatch.setenv("BRAIN_MODEL", "openmythos-27b")
    monkeypatch.setenv("BRAIN_REQUIRE_PIN", "1")
    assert brain._pick_model() == "openmythos-27b:latest"        # alias present → no raise


# ── review fix: empty/unreachable inventory must not bypass pin/strict (grok#1 / codex#4) ──
def test_empty_inventory_strict_raises(monkeypatch):
    _avail(monkeypatch, [])
    monkeypatch.setenv("BRAIN_MODEL", "openmythos-27b:latest")
    monkeypatch.setenv("BRAIN_REQUIRE_PIN", "1")
    with pytest.raises(RuntimeError):
        brain._pick_model()


def test_empty_inventory_warns_and_returns_none(monkeypatch, capsys):
    _avail(monkeypatch, [])
    monkeypatch.setenv("TRIAGE_MODEL", "openmythos-27b:latest")
    assert brain._pick_triage_model() is None
    assert "could NOT be verified" in capsys.readouterr().err


# ── review fix: triage fallback must NOT re-introduce excluded/assert-biased models (codex#1) ──
def test_triage_fallback_never_uses_xploiter(monkeypatch):
    _avail(monkeypatch, ["xploiter/the-xploiter:latest"])       # only an assert-biased model installed
    assert brain._pick_triage_model() is None                   # disable triage, do NOT use xploiter


def test_triage_fallback_uses_safe_available(monkeypatch):
    _avail(monkeypatch, ["xploiter/the-xploiter:latest", "some-generic:latest"])
    assert brain._pick_triage_model() == "some-generic:latest"  # skips excluded, uses safe one


# ── review fix: triage fallback must NOT overwrite narrator provenance (grok#5 / codex#7) ──
def test_triage_fallback_preserves_narrator_provenance(monkeypatch):
    _avail(monkeypatch, ["custom-narrator:latest", "some-generic:latest"])
    monkeypatch.setenv("BRAIN_MODEL", "custom-narrator:latest")
    assert brain._pick_model() == "custom-narrator:latest"      # narrator recorded
    brain._pick_triage_model()                                  # triage falls back
    assert brain.MODEL_SELECTION_LOG["narrator"]["model"] == "custom-narrator:latest"  # NOT clobbered


# ── review fix: scanner pin safety (grok#3/#8, codex#6) ─────────────────────
import types


def _fake_ollama(installed):
    fake = types.ModuleType("ollama")

    class _NotFound(Exception):
        status_code = 404

    def show(m):
        if m in installed:
            return {}
        raise _NotFound(f"model '{m}' not found, try pulling it first")

    def show_neterr(m):
        raise ConnectionError("connection refused")   # daemon down, NOT a missing model

    fake.show = show
    fake._show_neterr = show_neterr
    return fake


def test_scanner_pin_missing_warns_and_falls_to_coder(monkeypatch, capsys):
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "ollama", _fake_ollama({"qwen2.5-coder:14b"}))
    monkeypatch.setenv("BRAIN_ENV_NOLOAD", "1")
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("BRAIN_REQUIRE_PIN", raising=False)
    monkeypatch.setenv("BRAIN_SCANNER_MODEL", "ghost:latest")
    import brain_scanner
    assert brain_scanner.pick_model() == "qwen2.5-coder:14b"     # fell to a real coder, not silent
    assert "NOT installed" in capsys.readouterr().err


def test_scanner_pin_missing_strict_raises(monkeypatch):
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "ollama", _fake_ollama({"qwen2.5-coder:14b"}))
    monkeypatch.setenv("BRAIN_ENV_NOLOAD", "1")
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.setenv("BRAIN_SCANNER_MODEL", "ghost:latest")
    monkeypatch.setenv("BRAIN_REQUIRE_PIN", "1")
    import brain_scanner
    with pytest.raises(RuntimeError, match="ghost:latest"):
        brain_scanner.pick_model()


def test_scanner_network_error_is_cannot_verify_not_not_installed(monkeypatch, capsys):
    import sys as _sys
    fake = _fake_ollama({"qwen2.5-coder:14b"})
    fake.show = fake._show_neterr        # every show() = ConnectionError (daemon down)
    monkeypatch.setitem(_sys.modules, "ollama", fake)
    monkeypatch.setenv("BRAIN_ENV_NOLOAD", "1")
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("BRAIN_REQUIRE_PIN", raising=False)
    monkeypatch.setenv("BRAIN_SCANNER_MODEL", "qwen2.5-coder:14b")   # actually installed, but unreachable
    import brain_scanner
    brain_scanner.pick_model()
    assert "could NOT be verified" in capsys.readouterr().err       # not the misleading "pull the model"

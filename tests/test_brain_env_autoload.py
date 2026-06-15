"""brain.env must AUTO-LOAD so the documented local-LLM settings actually apply.

ROOT CAUSE (real engagement, 2026-06-10): `~/.config/vikramaditya/brain.env` (which pins
BRAIN_PROVIDER=ollama + qwen3-coder:30b for all three roles) was NEVER referenced in code —
it was a doc-only file the user had to `source` by hand. A scan launched without sourcing it
inherited a STALE `BRAIN_PROVIDER=gemini` + a dead `GEMINI_API_KEY` from the launching shell,
so the brain wasted a Gemini round-trip every call and fell back to the WRONG local models
(qwen3:14b / bugtraceai-apex) instead of the pinned qwen3-coder:30b.

FIX: `brain._load_brain_env()` parses the `export KEY=VALUE` file at import and applies the
brain-relevant keys with FILE-WINS precedence — because the file is the user's canonical
config and the offending env was accidental cruft, not a deliberate override. An allowlist
keeps it from clobbering unrelated env (PATH, HOME). Escape hatch: BRAIN_ENV_NOLOAD=1.
Path override: BRAIN_ENV_FILE.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import brain  # noqa: E402


def _write_env(tmp_path, body):
    p = tmp_path / "brain.env"
    p.write_text(body)
    return str(p)


def test_loads_values_into_environ_when_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("BRAIN_PROVIDER", raising=False)
    monkeypatch.delenv("BRAIN_MODEL", raising=False)
    path = _write_env(tmp_path, "export BRAIN_PROVIDER=ollama\nexport BRAIN_MODEL=qwen3-coder:30b\n")
    applied = brain._load_brain_env(path)
    import os
    assert os.environ["BRAIN_PROVIDER"] == "ollama"
    assert os.environ["BRAIN_MODEL"] == "qwen3-coder:30b"
    assert applied.get("BRAIN_MODEL") == "qwen3-coder:30b"


def test_file_wins_over_stale_inherited_env(tmp_path, monkeypatch):
    """THE BUG: inherited env has the wrong provider; the canonical file must win."""
    monkeypatch.setenv("BRAIN_PROVIDER", "gemini")        # stale cruft from launching shell
    monkeypatch.setenv("TRIAGE_MODEL", "bugtraceai-apex:latest")
    path = _write_env(tmp_path, "export BRAIN_PROVIDER=ollama\nexport TRIAGE_MODEL=qwen3-coder:30b\n")
    brain._load_brain_env(path)
    import os
    assert os.environ["BRAIN_PROVIDER"] == "ollama", "file must override stale inherited provider"
    assert os.environ["TRIAGE_MODEL"] == "qwen3-coder:30b"


def test_ignores_comments_blanks_export_prefix_and_quotes(tmp_path, monkeypatch):
    monkeypatch.delenv("BRAIN_MODEL", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    body = (
        "# Vikramaditya brain config\n"
        "\n"
        "   # export GEMINI_API_KEY=should-stay-commented\n"
        'export BRAIN_MODEL="qwen3-coder:30b"   # inline comment ignored\n'
        "OLLAMA_HOST='http://localhost:11434'\n"   # no export prefix, single quotes
    )
    path = _write_env(tmp_path, body)
    brain._load_brain_env(path)
    import os
    assert os.environ["BRAIN_MODEL"] == "qwen3-coder:30b"
    assert os.environ["OLLAMA_HOST"] == "http://localhost:11434"
    assert "GEMINI_API_KEY" not in os.environ or os.environ.get("GEMINI_API_KEY") != "should-stay-commented"


def test_missing_file_is_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("BRAIN_PROVIDER", "ollama")
    applied = brain._load_brain_env(str(tmp_path / "does_not_exist.env"))
    assert applied == {}
    import os
    assert os.environ["BRAIN_PROVIDER"] == "ollama"  # untouched


def test_allowlist_blocks_unrelated_keys(tmp_path, monkeypatch):
    """A brain.env must never be able to hijack PATH/HOME or other unrelated env."""
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    path = _write_env(tmp_path, "export PATH=/evil/bin\nexport BRAIN_MODEL=qwen3-coder:30b\n")
    brain._load_brain_env(path)
    import os
    assert os.environ["PATH"] == "/usr/bin:/bin", "PATH must NOT be overridable from brain.env"
    assert os.environ["BRAIN_MODEL"] == "qwen3-coder:30b"


def test_noload_escape_hatch(tmp_path, monkeypatch):
    monkeypatch.setenv("BRAIN_ENV_NOLOAD", "1")
    monkeypatch.delenv("BRAIN_MODEL", raising=False)
    path = _write_env(tmp_path, "export BRAIN_MODEL=qwen3-coder:30b\n")
    applied = brain._load_brain_env(path)
    assert applied == {}
    import os
    assert "BRAIN_MODEL" not in os.environ


def test_api_key_is_allowlisted(tmp_path, monkeypatch):
    """If the user uncomments a real provider key in brain.env, it should load."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    path = _write_env(tmp_path, "export GEMINI_API_KEY=AIza-real-key\n")
    brain._load_brain_env(path)
    import os
    assert os.environ["GEMINI_API_KEY"] == "AIza-real-key"


def test_unrelated_api_key_not_applied(tmp_path, monkeypatch):
    """Only the brain PROVIDER keys are allowlisted — brain.env must not file-win an arbitrary
    *_API_KEY belonging to another tool in the same process (Codex LOW)."""
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    path = _write_env(tmp_path, "export STRIPE_API_KEY=sk_live_should_not_apply\n")
    brain._load_brain_env(path)
    import os
    assert "STRIPE_API_KEY" not in os.environ

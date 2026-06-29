"""brain.py --phase chat — interactive REPL.

Drives a scripted session against a Brain whose LLM + command exec are mocked, so
the REPL control flow (slash commands, history, gated /run, exit) is verified without
needing Ollama. The chat phase reuses the existing guard_command gate for /run.
"""
import builtins
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import brain  # noqa: E402


def _bare_brain():
    """A Brain instance bypassing the Ollama-connecting __init__."""
    b = brain.Brain.__new__(brain.Brain)
    b.enabled = True
    b.model = "test-model"
    b.allow_exploit = False

    class _LLM:
        provider = "mock"
    b._llm = _LLM()
    b.client = None
    return b


def test_chat_phase_registered():
    src = open(os.path.join(os.path.dirname(__file__), "..", "brain.py"), encoding="utf-8").read()
    assert '"chat",' in src, "chat not in --phase choices"
    assert "def interactive_chat" in src and "def _chat_reply" in src


def test_chat_system_prompt_present():
    assert "authorized VAPT" in brain.Brain.CHAT_SYSTEM
    assert "/run" in brain.Brain.CHAT_SYSTEM


def test_repl_run_routes_through_guard(monkeypatch):
    """/run must go through self.run_command (the guard_command gate), and its output
    must be fed back to the conversation for analysis."""
    b = _bare_brain()
    ran = {}

    def fake_run(cmd, timeout=120, cwd=None):
        ran["cmd"] = cmd
        return 0, "OUTPUT-LINE", ""
    monkeypatch.setattr(b, "run_command", fake_run)

    replies = []
    monkeypatch.setattr(b, "_chat_reply", lambda messages: replies.append(list(messages)) or "ack")

    script = iter(["/run curl -s http://x", "what did that show?", "/exit"])
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(script))

    b.interactive_chat()
    assert ran.get("cmd") == "curl -s http://x", "/run did not invoke run_command with the command"
    # the command output was fed into the message history the LLM saw
    blob = "\n".join(m["content"] for conv in replies for m in conv)
    assert "OUTPUT-LINE" in blob, "/run output was not fed back into the conversation"


def test_repl_reset_and_exit(monkeypatch):
    b = _bare_brain()
    monkeypatch.setattr(b, "_chat_reply", lambda messages: "ok")
    seen = []
    script = iter(["hello", "/reset", "/exit"])
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(script))
    # should not raise, should terminate on /exit
    b.interactive_chat()


def test_repl_normal_turn_appends_history(monkeypatch):
    b = _bare_brain()
    captured = {}

    def fake_reply(messages):
        captured["messages"] = list(messages)
        return "assistant-answer"
    monkeypatch.setattr(b, "_chat_reply", fake_reply)
    script = iter(["explain XSS", "/exit"])
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(script))
    b.interactive_chat()
    roles = [m["role"] for m in captured["messages"]]
    assert roles[0] == "system" and "explain XSS" in captured["messages"][-1]["content"]

"""Brain talks to Ollama over HTTP (no `ollama` python package), so it works on ANY interpreter.

Three runs had the brain OFF only because the launched python (system /usr/bin/python3) lacked the
`ollama` package, even though the daemon + .venv had it. brain.py now uses the REST API directly.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import brain  # noqa: E402


class _Resp:
    def __init__(self, json_data=None, lines=None):
        self._json = json_data
        self._lines = lines or []

    def raise_for_status(self):
        pass

    def json(self):
        return self._json

    def iter_lines(self, decode_unicode=True):
        for ln in self._lines:
            yield ln


def test_attrdict_dual_access():
    d = brain._wrap({"message": {"content": "hi", "thinking": "t"}})
    assert d["message"]["content"] == "hi"      # dict access
    assert d.message.content == "hi"            # attribute access
    assert d.message.get("thinking") == "t"     # .get still works


def test_list_parses_tags(monkeypatch):
    monkeypatch.setattr("requests.get",
                        lambda *a, **k: _Resp(json_data={"models": [
                            {"model": "qwen3-coder:30b", "name": "qwen3-coder:30b"}]}))
    r = brain._OllamaHTTP("http://x:11434").list()
    assert [m.model for m in r.models] == ["qwen3-coder:30b"]   # attribute style (used by brain)
    assert r["models"][0]["model"] == "qwen3-coder:30b"          # dict style


def test_chat_nonstream(monkeypatch):
    monkeypatch.setattr("requests.post",
                        lambda *a, **k: _Resp(json_data={"message": {"content": "hello"}}))
    r = brain._OllamaHTTP("http://x").chat(model="m", messages=[], stream=False)
    assert r["message"]["content"] == "hello" and r.message.content == "hello"


def test_chat_stream_yields_chunks(monkeypatch):
    lines = [
        json.dumps({"message": {"content": "hel", "thinking": ""}, "done": False}),
        json.dumps({"message": {"content": "lo", "thinking": ""}, "done": True}),
    ]
    monkeypatch.setattr("requests.post", lambda *a, **k: _Resp(lines=lines))
    chunks = list(brain._OllamaHTTP("http://x").chat(model="m", messages=[], stream=True))
    assert chunks[0]["message"]["content"] == "hel"     # dict access (brain._stream uses this)
    assert chunks[1].message.content == "lo"            # attribute access


def test_llmclient_ollama_available_via_http_without_package(monkeypatch):
    """The whole point: ollama provider initializes purely from the HTTP probe — no `ollama` pkg."""
    monkeypatch.setattr("requests.get",
                        lambda *a, **k: _Resp(json_data={"models": [{"model": "phi4:14b"}]}))
    c = brain.LLMClient("ollama")
    assert c.available is True
    assert c.provider == "ollama"


def test_llmclient_ollama_unavailable_when_daemon_down(monkeypatch):
    monkeypatch.setattr("requests.get",
                        lambda *a, **k: (_ for _ in ()).throw(ConnectionError("no daemon")))
    c = brain.LLMClient.__new__(brain.LLMClient)
    c.provider = "ollama"; c._ollama = None; c.available = False; c.description = ""
    c._init_provider("ollama")
    assert c.available is False

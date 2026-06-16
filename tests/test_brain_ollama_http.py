"""Brain talks to Ollama over HTTP using ONLY stdlib urllib (no `ollama` or `requests`), so it
works on ANY interpreter (system python included) whenever the daemon is up.

Several runs had the brain OFF only because the launched python lacked the `ollama` package, even
though the daemon was running. brain.py now uses the REST API via urllib — zero third-party deps.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import brain  # noqa: E402


class _UResp:
    """Stand-in for a urllib HTTPResponse: .read() for bodies, iteration for NDJSON streams."""
    def __init__(self, data=None, lines=None):
        self._data = data if data is None else json.dumps(data).encode()
        self._lines = lines

    def read(self):
        return self._data or b"{}"

    def __iter__(self):
        for ln in (self._lines or []):
            yield (ln + "\n").encode()


def _patch_urlopen(monkeypatch, fn):
    monkeypatch.setattr("urllib.request.urlopen", fn)


def test_attrdict_dual_access():
    d = brain._wrap({"message": {"content": "hi", "thinking": "t"}})
    assert d["message"]["content"] == "hi"      # dict access
    assert d.message.content == "hi"            # attribute access
    assert d.message.get("thinking") == "t"


def test_list_parses_tags(monkeypatch):
    _patch_urlopen(monkeypatch, lambda req, timeout=None: _UResp(
        data={"models": [{"model": "qwen3-coder:30b", "name": "qwen3-coder:30b"}]}))
    r = brain._OllamaHTTP("http://x:11434").list()
    assert [m.model for m in r.models] == ["qwen3-coder:30b"]
    assert r["models"][0]["model"] == "qwen3-coder:30b"


def test_chat_nonstream(monkeypatch):
    _patch_urlopen(monkeypatch, lambda req, timeout=None: _UResp(data={"message": {"content": "hello"}}))
    r = brain._OllamaHTTP("http://x").chat(model="m", messages=[], stream=False)
    assert r["message"]["content"] == "hello" and r.message.content == "hello"


def test_chat_stream_yields_chunks(monkeypatch):
    lines = [
        json.dumps({"message": {"content": "hel", "thinking": ""}, "done": False}),
        json.dumps({"message": {"content": "lo", "thinking": ""}, "done": True}),
    ]
    _patch_urlopen(monkeypatch, lambda req, timeout=None: _UResp(lines=lines))
    chunks = list(brain._OllamaHTTP("http://x").chat(model="m", messages=[], stream=True))
    assert chunks[0]["message"]["content"] == "hel"     # dict access (brain._stream uses this)
    assert chunks[1].message.content == "lo"            # attribute access


def test_llmclient_ollama_available_via_http_without_package(monkeypatch):
    """The whole point: ollama provider initializes from the urllib HTTP probe — no `ollama` pkg."""
    _patch_urlopen(monkeypatch, lambda req, timeout=None: _UResp(data={"models": [{"model": "phi4:14b"}]}))
    c = brain.LLMClient("ollama")
    assert c.available is True
    assert c.provider == "ollama"


def test_llmclient_ollama_unavailable_when_daemon_down(monkeypatch):
    import urllib.error

    def _down(req, timeout=None):
        raise urllib.error.URLError("connection refused")
    _patch_urlopen(monkeypatch, _down)
    c = brain.LLMClient.__new__(brain.LLMClient)
    c.provider = "ollama"; c._ollama = None; c.available = False; c.description = ""
    c._init_provider("ollama")
    assert c.available is False

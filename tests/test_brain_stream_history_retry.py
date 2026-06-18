"""
_stream_history empty-response resilience (v10.6.0).

A single transient EMPTY stream silently aborted the SQLi->RCE exploit loop
before run_command ever ran (observed on target.example.invalid: exploit round 1 was
blank). _stream_history must retry on empty, and the authorized exploit path
must be able to disable the refusal-truncation stop sequences.
"""
import brain


def _bare_brain(fake_client):
    b = brain.Brain.__new__(brain.Brain)   # bypass __init__ (no Ollama contact)
    b.enabled = True
    b.model = "test-model"
    b.client = fake_client
    return b


class _Stream(list):
    """An iterable of ollama-style chat chunks."""
    @classmethod
    def of(cls, text):
        return cls([{"message": {"content": text}}]) if text else cls([])


def test_stream_history_retries_on_empty_then_succeeds():
    calls = {"n": 0}

    class FakeClient:
        def chat(self, **kw):
            calls["n"] += 1
            return _Stream.of("" if calls["n"] == 1 else "```bash\necho hi\n```")

    b = _bare_brain(FakeClient())
    out = b._stream_history([{"role": "user", "content": "x"}], "T")
    assert "echo hi" in out
    assert calls["n"] == 2, "must retry exactly once after the first empty stream"


def test_stream_history_gives_up_after_retries():
    calls = {"n": 0}

    class FakeClient:
        def chat(self, **kw):
            calls["n"] += 1
            return _Stream.of("")  # always empty

    b = _bare_brain(FakeClient())
    out = b._stream_history([{"role": "user", "content": "x"}], "T", empty_retries=2)
    assert out == ""
    assert calls["n"] == 3, "1 initial + 2 retries"


def test_exploit_path_disables_refusal_stops_default_keeps_them():
    seen = {}

    class FakeClient:
        def chat(self, **kw):
            seen["options"] = kw["options"]
            return _Stream.of("ok")

    b = _bare_brain(FakeClient())
    b._stream_history([{"role": "user", "content": "x"}], "T", stop=[])
    assert "stop" not in seen["options"], "exploit path (stop=[]) must not truncate on refusals"

    b._stream_history([{"role": "user", "content": "x"}], "T")  # default
    assert "stop" in seen["options"], "default path keeps refusal-truncation stops"

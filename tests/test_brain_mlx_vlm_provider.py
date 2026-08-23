import json

import brain_scanner
from brain import LLMClient


class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.text)


class _FakeSession:
    def __init__(self):
        self.headers = {}
        self.posts = []

    def get(self, url, timeout=None):
        if url == "http://127.0.0.1:8080/health":
            return _FakeResp({"loaded_model": "/tmp/qwen-mlx-vlm"})
        if url == "http://127.0.0.1:8080/v1/models":
            return _FakeResp({"object": "list", "data": []})
        return _FakeResp({}, status_code=404)

    def post(self, url, data=None, timeout=None):
        body = json.loads(data)
        self.posts.append({"url": url, "body": body, "timeout": timeout})
        return _FakeResp({"choices": [{"message": {"content": "OK"}}]})


def test_mlx_vlm_provider_discovers_loaded_model_and_caps_tokens(monkeypatch):
    session = _FakeSession()
    monkeypatch.setattr("requests.Session", lambda: session)
    monkeypatch.setenv("BRAIN_PROVIDER", "mlx_vlm")
    monkeypatch.setenv("MLX_VLM_BASE_URL", "http://127.0.0.1:8080")
    monkeypatch.delenv("MLX_VLM_MODEL", raising=False)
    monkeypatch.delenv("MLX_VLM_MAX_TOKENS", raising=False)

    client = LLMClient("mlx_vlm")

    assert client.available is True
    assert client.default_model() == "/tmp/qwen-mlx-vlm"
    assert client.description == "MLX-VLM server @ http://127.0.0.1:8080/v1"

    assert client.chat(None, "system", "Say OK", max_tokens=4000) == "OK"

    request = session.posts[-1]
    assert request["url"] == "http://127.0.0.1:8080/v1/chat/completions"
    assert request["body"]["model"] == "/tmp/qwen-mlx-vlm"
    assert request["body"]["max_tokens"] == 128
    assert request["body"]["enable_thinking"] is False
    assert request["body"]["thinking_budget"] == 0


def test_brain_scanner_pick_model_uses_mlx_vlm_env(monkeypatch):
    monkeypatch.setenv("BRAIN_PROVIDER", "mlx_vlm")
    monkeypatch.setenv("MLX_VLM_MODEL", "/tmp/qwen-mlx-vlm")
    monkeypatch.delenv("BRAIN_SCANNER_MODEL", raising=False)

    assert brain_scanner.pick_model() == "/tmp/qwen-mlx-vlm"

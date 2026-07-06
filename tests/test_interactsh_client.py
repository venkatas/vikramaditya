"""interactsh_client — shared OOB spawn/poll helper used by xxe_hunt and (optionally)
hunt.py's existing Log4Shell OOB step. Extracted so both callers share one
implementation instead of hunt.py's inline copy."""
import json
import os

import interactsh_client as ic


def test_find_interactsh_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(ic.shutil, "which", lambda name: None)
    monkeypatch.setattr(ic.os.path, "isfile", lambda x: False)
    assert ic.find_interactsh_binary() is None


def test_find_interactsh_binary_found_in_path(monkeypatch):
    monkeypatch.setattr(ic.shutil, "which", lambda name: "/usr/local/bin/interactsh-client")
    assert ic.find_interactsh_binary() == "/usr/local/bin/interactsh-client"


def test_poll_callbacks_reads_jsonl_log(tmp_path):
    log_path = tmp_path / "interactsh_log.jsonl"
    token = "abc123tok"
    lines = [
        json.dumps({"full-id": f"{token}.interact.sh", "protocol": "http", "raw-request": "GET /xxe"}),
        json.dumps({"full-id": f"other.interact.sh", "protocol": "dns"}),
        json.dumps({"full-id": f"{token}.interact.sh", "protocol": "dns", "raw-request": ""}),
    ]
    log_path.write_text("\n".join(lines) + "\n")

    session = ic.InteractshSession(url=f"https://{token}.interact.sh", log_path=str(log_path),
                                    token=token, proc=None)
    callbacks = session.poll_callbacks(token)
    assert len(callbacks) == 2
    assert all(cb["full-id"].startswith(token) for cb in callbacks)


def test_poll_callbacks_missing_log_returns_empty(tmp_path):
    session = ic.InteractshSession(url="https://tok.interact.sh",
                                    log_path=str(tmp_path / "missing.jsonl"),
                                    token="tok", proc=None)
    assert session.poll_callbacks("tok") == []


def test_spawn_returns_none_without_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(ic, "find_interactsh_binary", lambda: None)
    assert ic.spawn(log_dir=str(tmp_path)) is None

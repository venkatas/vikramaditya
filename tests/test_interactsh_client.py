"""interactsh_client — shared OOB spawn/poll helper used by xxe_hunt and (optionally)
hunt.py's existing Log4Shell OOB step. Extracted so both callers share one
implementation instead of hunt.py's inline copy."""
import json
import os
import subprocess
from unittest.mock import MagicMock

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


def test_poll_callbacks_skips_blank_lines(tmp_path):
    """Blank / whitespace-only lines interleaved with valid JSONL must be skipped,
    not raise, and must not prevent later valid records from being read."""
    log_path = tmp_path / "interactsh_log.jsonl"
    token = "abc123tok"
    content = (
        json.dumps({"full-id": f"{token}xyz.oast.pro", "protocol": "dns"}) + "\n"
        "\n"
        "   \n"
        + json.dumps({"full-id": f"{token}xyz.oast.pro", "protocol": "http"}) + "\n"
    )
    log_path.write_text(content)

    session = ic.InteractshSession(url=f"https://{token}xyz.oast.pro", log_path=str(log_path),
                                    token=token, proc=None)
    callbacks = session.poll_callbacks(token)
    assert len(callbacks) == 2
    assert {cb["protocol"] for cb in callbacks} == {"dns", "http"}


def test_poll_callbacks_skips_malformed_json(tmp_path):
    """A malformed JSON line mixed into otherwise-valid JSONL must be skipped (not
    raise), and must not prevent valid records before/after it from being read."""
    log_path = tmp_path / "interactsh_log.jsonl"
    token = "abc123tok"
    lines = [
        json.dumps({"full-id": f"{token}xyz.oast.pro", "protocol": "dns"}),
        "{not valid json,,,",
        json.dumps({"full-id": f"{token}xyz.oast.pro", "protocol": "smtp"}),
    ]
    log_path.write_text("\n".join(lines) + "\n")

    session = ic.InteractshSession(url=f"https://{token}xyz.oast.pro", log_path=str(log_path),
                                    token=token, proc=None)
    callbacks = session.poll_callbacks(token)
    assert len(callbacks) == 2
    assert all(cb["full-id"].startswith(token) for cb in callbacks)


def test_spawn_returns_none_without_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(ic, "find_interactsh_binary", lambda: None)
    assert ic.spawn(log_dir=str(tmp_path)) is None


def test_spawn_captures_real_domain_from_banner(monkeypatch, tmp_path):
    """The success path must use the REAL domain interactsh-client announces on
    its stdout banner — not a client-fabricated uuid/suffix guess."""
    r, w = os.pipe()
    os.write(w, b"projectdiscovery.io\n[INF] Listing 1 payload for OOB Testing\nabc123def456.oast.pro\n")
    os.close(w)
    fake_proc = MagicMock()
    fake_proc.stdout = os.fdopen(r, "rb")

    monkeypatch.setattr(ic, "find_interactsh_binary", lambda: "/usr/local/bin/interactsh-client")
    monkeypatch.setattr(ic, "_fork_safe_spawn", lambda *a, **k: fake_proc)

    session = ic.spawn(log_dir=str(tmp_path), timeout_s=2)

    assert session is not None
    assert session.url == "https://abc123def456.oast.pro"
    assert session.token == "abc123def456"
    assert session.proc is fake_proc
    fake_proc.stdout.close()


def test_spawn_matches_legacy_interact_sh_domain(monkeypatch, tmp_path):
    """Must still recognize the legacy .interact.sh domain family, not just oast.*."""
    r, w = os.pipe()
    os.write(w, b"some banner text\nabc123def456.interact.sh\n")
    os.close(w)
    fake_proc = MagicMock()
    fake_proc.stdout = os.fdopen(r, "rb")

    monkeypatch.setattr(ic, "find_interactsh_binary", lambda: "/usr/local/bin/interactsh-client")
    monkeypatch.setattr(ic, "_fork_safe_spawn", lambda *a, **k: fake_proc)

    session = ic.spawn(log_dir=str(tmp_path), timeout_s=2)

    assert session.url == "https://abc123def456.interact.sh"
    assert session.token == "abc123def456"
    fake_proc.stdout.close()


def test_spawn_no_banner_within_deadline_returns_empty_url_and_token(monkeypatch, tmp_path):
    """If the startup banner never appears, spawn() must NOT fabricate a token/URL —
    it must return a session whose url/token make it obvious no confirmed domain
    was captured, so a caller can't accidentally poll_callbacks() with a fake token."""
    r, w = os.pipe()  # keep w open: no data, no EOF, select() never reports ready
    fake_proc = MagicMock()
    fake_proc.stdout = os.fdopen(r, "rb")

    monkeypatch.setattr(ic, "find_interactsh_binary", lambda: "/usr/local/bin/interactsh-client")
    monkeypatch.setattr(ic, "_fork_safe_spawn", lambda *a, **k: fake_proc)

    session = ic.spawn(log_dir=str(tmp_path), timeout_s=0.3)

    assert session is not None
    assert session.proc is fake_proc
    assert session.url == ""
    assert session.token == ""
    fake_proc.stdout.close()
    os.close(w)


def test_spawn_does_not_leak_log_file_handle(monkeypatch, tmp_path):
    """spawn() must not itself open() the JSONL log file and leak the handle — the
    interactsh-client child process owns writing to it via `-o log_path`."""
    r, w = os.pipe()
    os.write(w, b"abc123def456.oast.pro\n")
    os.close(w)
    fake_proc = MagicMock()
    fake_proc.stdout = os.fdopen(r, "rb")

    monkeypatch.setattr(ic, "find_interactsh_binary", lambda: "/usr/local/bin/interactsh-client")
    monkeypatch.setattr(ic, "_fork_safe_spawn", lambda *a, **k: fake_proc)

    opened = []
    real_open = open

    def _tracking_open(*a, **k):
        f = real_open(*a, **k)
        opened.append(f)
        return f

    monkeypatch.setattr(ic, "open", _tracking_open, raising=False)
    session = ic.spawn(log_dir=str(tmp_path), timeout_s=2)
    assert session is not None
    # spawn() itself should not have opened the log file at all (no builtins.open
    # call inside interactsh_client's own module namespace during spawn()).
    assert opened == []
    fake_proc.stdout.close()


def test_stop_sends_terminate_and_waits():
    proc = MagicMock()
    session = ic.InteractshSession(url="https://abc123.oast.pro", log_path="/nonexistent",
                                    token="abc123", proc=proc)
    session.stop()
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once_with(timeout=5)
    proc.kill.assert_not_called()


def test_stop_escalates_to_kill_when_wait_times_out():
    proc = MagicMock()
    proc.wait.side_effect = subprocess.TimeoutExpired(cmd="interactsh-client", timeout=5)
    session = ic.InteractshSession(url="https://abc123.oast.pro", log_path="/nonexistent",
                                    token="abc123", proc=proc)
    session.stop()
    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()


def test_stop_swallows_kill_failure_too():
    """Even if the SIGKILL escalation itself raises, stop() must not propagate."""
    proc = MagicMock()
    proc.wait.side_effect = subprocess.TimeoutExpired(cmd="interactsh-client", timeout=5)
    proc.kill.side_effect = OSError("no such process")
    session = ic.InteractshSession(url="https://abc123.oast.pro", log_path="/nonexistent",
                                    token="abc123", proc=proc)
    session.stop()  # must not raise


def test_stop_noop_when_proc_is_none():
    session = ic.InteractshSession(url="", log_path="/nonexistent", token="", proc=None)
    session.stop()  # must not raise, no-op

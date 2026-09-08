"""Session tool cache: key, scope, secrets, disk location. No network."""

from __future__ import annotations

import os
import stat

import session_tool_cache as cache


def _reset(monkeypatch):
    cache.clear_binding()
    monkeypatch.delenv("VIK_SESSION_TOOL_CACHE", raising=False)


def _session(tmp_path, mode=0o700):
    session = tmp_path / "sess"
    session.mkdir()
    os.chmod(session, mode)
    return session


def test_disabled_by_default_does_not_store_or_short_circuit(tmp_path, monkeypatch):
    _reset(monkeypatch)
    session = _session(tmp_path)
    cache.bind_session("app.example.invalid", str(session), scope_domains=["app.example.invalid"])
    assert cache.store(
        "app.example.invalid", "httpx",
        ["httpx", "-u", "https://app.example.invalid"],
        True, "ok", str(session),
    ) is None
    assert cache.lookup_for_runner(["httpx", "-u", "https://app.example.invalid"]) is None
    assert not (session / "tool_cache").exists()
    cache.clear_binding()


def test_key_includes_target_tool_args_and_replays_once(tmp_path, monkeypatch):
    cache.clear_binding()
    monkeypatch.setenv("VIK_SESSION_TOOL_CACHE", "1")
    session = _session(tmp_path)
    args = ["httpx", "-u", "https://app.example.invalid"]
    cache.bind_session(
        "app.example.invalid", str(session),
        scope_domains=["app.example.invalid"],
    )
    path = cache.store(
        "app.example.invalid", "httpx", args, True, "body-1", str(session),
        scope_domains=["app.example.invalid"],
    )
    assert path
    assert str(path).startswith(str(session))
    assert os.stat(path).st_mode & 0o077 == 0
    cache_dir = session / "tool_cache"
    assert cache_dir.is_dir()
    assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700

    other = cache.make_key("other.example.invalid", "httpx", args)
    same = cache.make_key("app.example.invalid", "httpx", args)
    assert other != same

    hit = cache.lookup_for_runner(args)
    assert hit == (True, "[session-tool-cache hit] body-1")
    assert cache.lookup_for_runner(["httpx", "-u", "https://app.example.invalid/other"]) is None
    cache.clear_binding()


def test_out_of_scope_not_cached(tmp_path, monkeypatch):
    cache.clear_binding()
    monkeypatch.setenv("VIK_SESSION_TOOL_CACHE", "1")
    session = _session(tmp_path)
    allow = session / "scope"
    allow.mkdir()
    (allow / "allow.txt").write_text("app.example.invalid\n", encoding="utf-8")
    args = ["httpx", "-u", "https://evil.example.net"]
    stored = cache.store(
        "app.example.invalid", "httpx", args, True, "nope", str(session),
        scope_domains=["app.example.invalid"],
    )
    assert stored is None
    assert cache.lookup("app.example.invalid", "httpx", args, str(session)) is None
    cache.clear_binding()


def test_secrets_never_cached(tmp_path, monkeypatch):
    cache.clear_binding()
    monkeypatch.setenv("VIK_SESSION_TOOL_CACHE", "1")
    session = _session(tmp_path)
    args = ["httpx", "-H", "Authorization: Bearer supertokenvalue"]
    assert cache.store(
        "app.example.invalid", "httpx", args, True, "secret-body", str(session),
        scope_domains=["app.example.invalid"],
    ) is None
    clean = ["httpx", "-u", "https://app.example.invalid"]
    assert cache.store(
        "app.example.invalid", "httpx", clean, True,
        "password=hunter2 found", str(session),
        scope_domains=["app.example.invalid"],
    ) is None
    cache_dir = session / "tool_cache"
    assert (not cache_dir.exists()) or list(cache_dir.glob("*.json")) == []
    cache.clear_binding()


def test_world_writable_session_refused(tmp_path, monkeypatch):
    cache.clear_binding()
    monkeypatch.setenv("VIK_SESSION_TOOL_CACHE", "1")
    session = _session(tmp_path, mode=0o777)
    stored = cache.store(
        "app.example.invalid", "httpx",
        ["httpx", "-u", "https://app.example.invalid"],
        True, "ok", str(session),
        scope_domains=["app.example.invalid"],
    )
    assert stored is None
    cache.clear_binding()


def test_watch_file_and_sqlmap_not_replayed(tmp_path, monkeypatch):
    cache.clear_binding()
    monkeypatch.setenv("VIK_SESSION_TOOL_CACHE", "1")
    session = _session(tmp_path)
    cache.bind_session("app.example.invalid", str(session), scope_domains=["app.example.invalid"])
    assert cache.lookup_for_runner(
        ["httpx", "-u", "https://app.example.invalid"],
        watch_file=str(session / "out.txt"),
    ) is None
    assert cache.store_for_runner(
        ["sqlmap", "-u", "https://app.example.invalid"],
        True, "dumped",
    ) is None
    cache.clear_binding()

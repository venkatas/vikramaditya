"""
PTY-stdin fork-safe spawn (v10.6.0).

WHY: sqlmap's `-r`/`-m`/`-l` modes silently fall into "using 'STDIN' for parsing
targets list" whenever stdin is NOT a tty (nohup, cron, subprocess, agent.py) —
sqlmap's `_setStdinPipeTargets()` only early-returns on `conf.url`, never on
`conf.requestFile`. So `hunt.py --request-file` tested NOTHING in every
non-interactive run (0.6s, "no injections detected"), and the brain SQLi->RCE
escalation never fired.

The fix gives the spawned child a PTY on fd 0 (os.openpty + posix_spawn dup2 —
NO fork(), so the macOS Network.framework atfork SIGSEGV class is untouched) so
`os.isatty(0)` is True and sqlmap honours `-r`.
"""
import os

from procutil import _fork_safe_spawn, run_capture, sqlmap_needs_pty


def test_sqlmap_needs_pty_for_file_flags():
    assert sqlmap_needs_pty('sqlmap -r /tmp/req.txt --batch --level=5') is True
    assert sqlmap_needs_pty('sqlmap -r "/a b/req" --dbms=postgresql --os-shell') is True
    assert sqlmap_needs_pty('sqlmap.py -m targets.txt --batch') is True
    assert sqlmap_needs_pty('sqlmap --bulk=urls.txt') is True
    assert sqlmap_needs_pty(['sqlmap', '-l', 'burp.log']) is True


def test_sqlmap_needs_pty_false_for_url_mode():
    # -u/--data mode early-returns on conf.url in sqlmap, so no pty needed.
    assert sqlmap_needs_pty('sqlmap -u https://x/y?id=1 --batch') is False
    assert sqlmap_needs_pty('curl -r 0-100 https://x') is False  # not sqlmap

_ISATTY = (
    'python3 -c "import os,sys; '
    "sys.stdout.write('TTY' if os.isatty(0) else 'NOTTY')\""
)


def test_default_stdin_is_devnull_not_a_tty():
    # Regression guard: the DEFAULT must stay /dev/null (non-tty) — unchanged behaviour.
    r = run_capture(_ISATTY)
    assert r["returncode"] == 0
    assert r["stdout"].strip() == "NOTTY"


def test_pty_stdin_makes_child_stdin_a_tty():
    r = run_capture(_ISATTY, pty_stdin=True)
    assert r["returncode"] == 0
    assert r["stdout"].strip() == "TTY"


def test_pty_stdin_still_captures_stdout_and_returncode():
    r = run_capture('python3 -c "print(\'hello-pty\'); raise SystemExit(7)"',
                    pty_stdin=True)
    assert "hello-pty" in r["stdout"]
    assert r["returncode"] == 7


def test_pty_stdin_does_not_leak_master_fds():
    # Spawn several pty-stdin children; the parent must not accumulate open fds
    # (the brain runs many commands per session — a per-call leak exhausts the table).
    before = len(os.listdir("/dev/fd"))
    for _ in range(8):
        r = run_capture(_ISATTY, pty_stdin=True)
        assert r["stdout"].strip() == "TTY"
    after = len(os.listdir("/dev/fd"))
    assert after <= before + 2, f"fd leak: {before} -> {after}"

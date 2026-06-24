"""ProcessWatchdog must DETECT a target-side IP-block and abort, not grind silently.

ROOT CAUSE THIS GUARDS AGAINST
------------------------------
When a WAF/firewall null-routes the scanner's source IP mid-scan (e.g. a Palo Alto
threat-prevention block — typically a FIXED-duration block triggered by a malicious
payload), the scanner keeps sending SYNs that get no SYN-ACK. lsof shows SYN_SENT with
zero ESTABLISHED. The retry churn made the watchdog's heuristics read "busy" forever, so
the run ground on for hours and banked a FALSE-NEGATIVE "0 findings" against a host it
could no longer reach. The watchdog now detects sustained SYN_SENT-with-no-ESTABLISHED
(output stalled), marks coverage degraded ("TARGET BLOCKED ... UNRELIABLE"), and kills
the stuck phase. See hunt.py ProcessWatchdog._run + WATCHDOG_BLOCK_TICKS.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hunt  # noqa: E402

_LSOF_BLOCKED = (
    "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
    "ffuf     1234  u      7u  IPv4    0t0      TCP 10.0.0.1:54321->1.2.3.4:443 (SYN_SENT)\n"
    "ffuf     1234  u      8u  IPv4    0t0      TCP 10.0.0.1:54322->1.2.3.4:443 (SYN_SENT)\n"
)
_LSOF_HEALTHY = (
    "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
    "ffuf     1234  u      7u  IPv4    0t0      TCP 10.0.0.1:54321->1.2.3.4:443 (ESTABLISHED)\n"
)


def _bare_watchdog():
    wd = object.__new__(hunt.ProcessWatchdog)
    wd._last_socket_signature = ""
    wd._last_socket_summary = ""
    wd._last_syn_sent = 0
    wd._last_established = 0
    return wd


def test_socket_status_exposes_block_signature(monkeypatch):
    # SYN_SENT with zero ESTABLISHED is the block signature.
    monkeypatch.setattr(hunt, "run_capture",
                        lambda *a, **k: {"stdout": _LSOF_BLOCKED, "stderr": "", "returncode": 0, "timed_out": False})
    wd = _bare_watchdog()
    wd._socket_status({1234})
    assert wd._last_syn_sent == 2 and wd._last_established == 0


def test_socket_status_healthy_is_not_a_block(monkeypatch):
    monkeypatch.setattr(hunt, "run_capture",
                        lambda *a, **k: {"stdout": _LSOF_HEALTHY, "stderr": "", "returncode": 0, "timed_out": False})
    wd = _bare_watchdog()
    wd._socket_status({1234})
    assert wd._last_established == 1 and wd._last_syn_sent == 0


def test_watchdog_aborts_and_flags_when_target_blocks(monkeypatch, tmp_path):
    """End-to-end: a stalled phase with sustained SYN_SENT/0-ESTABLISHED is killed and
    recorded as TARGET BLOCKED (degraded), instead of grinding forever."""
    degraded = []
    monkeypatch.setattr(hunt, "_mark_degraded", lambda tool, reason: degraded.append((tool, reason)))
    monkeypatch.setattr(hunt, "WATCHDOG_BLOCK_TICKS", 2)

    # Simulate the blocked state every tick: no growth, not busy, SYN_SENT>0, ESTABLISHED=0.
    def fake_desc(self):
        self._last_syn_sent = 3
        self._last_established = 0
        # (busy, proc_changed, summary, cpu_advanced, socket_active, socket_changed, socket_summary)
        return (False, False, "(blocked)", False, True, False, "SYN_SENT=3")
    monkeypatch.setattr(hunt.ProcessWatchdog, "_descendant_status", fake_desc)

    watch_file = tmp_path / "out.txt"
    watch_file.write_text("")  # exists, never grows

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                            start_new_session=True)
    wd = hunt.ProcessWatchdog(proc, str(watch_file), phase="VULN SCAN", interval=0.1)
    try:
        deadline = time.time() + 6
        while time.time() < deadline and not wd.blocked:
            time.sleep(0.1)
        assert wd.blocked is True, "watchdog did not detect the target block"
        assert wd.killed is True
        # the stuck phase was actually killed
        assert proc.wait(timeout=5) is not None
        # and it was recorded as a TARGET BLOCKED degradation for the report
        assert any("TARGET BLOCKED" in reason and "UNRELIABLE" in reason
                   for _tool, reason in degraded), degraded
    finally:
        wd.stop()
        if proc.poll() is None:
            proc.kill()

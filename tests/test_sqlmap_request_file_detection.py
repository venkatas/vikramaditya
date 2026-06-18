"""
Request-file SQLi detection + SQLi->RCE escalation wiring (v10.6.0).

Bug B: sqlmap's CONFIRMED output (esp. resumed from session) lacks the word
"injectable", so the old parser reported "no injections detected" while sqlmap
had enumerated 21 tables -> the brain never escalated.
Gap C: a confirmed injection must drive the active exploit loop (run_command),
not just the narration hook.
"""
import hunt

REAL_CONFIRMED = """
Parameter: prefixText ((custom) POST)
    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: {"prefixText":"s%';SELECT PG_SLEEP(5)--","count":1}

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: {"prefixText":"s%' AND 7473=(SELECT 7473 FROM PG_SLEEP(5)) AND 'x'='x","count":1}
[11:56:41] [INFO] the back-end DBMS is PostgreSQL
back-end DBMS: PostgreSQL
[11:57:06] [INFO] fetching tables for database: 'public'
Database: public
[21 tables]
+-----------------------+
| tblClients            |
| tblemployees          |
| tblPaymentDetails     |
+-----------------------+
"""

STDIN_BROKEN = """
[11:45:50] [INFO] using 'STDIN' for parsing targets list
[11:45:50] [INFO] you can find results of scanning in multiple targets mode inside the CSV file
[*] ending @ 11:45:50 /2026-06-18/
"""

CLEAN = """
[INFO] testing connection to the target URL
[WARNING] (custom) POST parameter 'JSON prefixText' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable.
"""


# ── parser ──────────────────────────────────────────────────────────────────

def test_parse_confirms_resumed_session():
    c = hunt._parse_sqlmap_confirmation(REAL_CONFIRMED)
    assert c["confirmed"] is True
    assert "PostgreSQL" in c["dbms"]
    assert any("stacked queries" in t.lower() for t in c["types"])
    assert "prefixText" in c["params"]
    assert "tblClients" in c["tables"] and "tblemployees" in c["tables"]
    assert any("PG_SLEEP" in p for p in c["payloads"])


def test_parse_negative_on_stdin_mode():
    assert hunt._parse_sqlmap_confirmation(STDIN_BROKEN)["confirmed"] is False


def test_parse_negative_on_clean_target():
    assert hunt._parse_sqlmap_confirmation(CLEAN)["confirmed"] is False


# ── escalation wiring ───────────────────────────────────────────────────────

class _FakeBrain:
    enabled = True

    def __init__(self):
        self.exploit_calls = []

    def phase_complete(self, phase, success, summary=""):
        return ""

    def exploit_finding(self, target_url, vuln_type, evidence, findings_dir="", extra_context=""):
        self.exploit_calls.append(
            dict(target_url=target_url, vuln_type=vuln_type, evidence=evidence,
                 extra=extra_context, findings_dir=findings_dir))
        return "transcript"


def _wire(monkeypatch, tmp_path, run_cmd_ret):
    monkeypatch.setattr(hunt, "_which",
                        lambda n: "/usr/bin/sqlmap" if n == "sqlmap" else None)
    monkeypatch.setattr(hunt, "_resolve_findings_dir",
                        lambda *a, **k: str(tmp_path / "findings"))
    monkeypatch.setattr(hunt, "run_cmd", lambda *a, **k: run_cmd_ret)
    fake = _FakeBrain()
    monkeypatch.setattr(hunt, "_brain", fake)
    return fake


def test_confirmed_injection_drives_exploit_loop(tmp_path, monkeypatch):
    req = tmp_path / "req.txt"
    req.write_text("POST https://the-target.example.invalid/TT/X HTTP/1.1\n"
                   "Host: the-target.example.invalid\n\n{\"prefixText\":\"s\"}\n")
    fake = _wire(monkeypatch, tmp_path, (True, REAL_CONFIRMED))

    result = hunt.run_sqlmap_request_file(str(req), domain="the-target.example.invalid")

    assert result is True
    assert len(fake.exploit_calls) == 1, "confirmed injection must drive ONE exploit loop"
    call = fake.exploit_calls[0]
    assert call["vuln_type"] == "SQL Injection"
    assert call["target_url"].startswith("https://the-target.example.invalid/")
    assert "PostgreSQL" in call["evidence"]
    assert "os-shell" in call["extra"].lower()  # DBMS-scoped RCE hint present


def test_no_injection_skips_exploit_loop(tmp_path, monkeypatch):
    req = tmp_path / "req.txt"
    req.write_text("POST https://x.example.invalid/y HTTP/1.1\nHost: x.example.invalid\n\na=1\n")
    fake = _wire(monkeypatch, tmp_path, (False, STDIN_BROKEN))

    result = hunt.run_sqlmap_request_file(str(req), domain="x.example.invalid")

    assert result is False
    assert fake.exploit_calls == [], "no confirmed injection => no exploit loop"

"""
hunt.py --request-file must launch sqlmap with a PTY on stdin (v10.6.0).

Without pty_stdin=True, sqlmap `-r` silently tests nothing under non-tty stdin
(nohup/cron/agent.py), so the brain SQLi->RCE escalation never runs. This pins
the wiring behaviourally — run_cmd is stubbed so no network/sqlmap is touched.
"""
import hunt


def test_request_file_runs_sqlmap_with_pty_stdin(tmp_path, monkeypatch):
    req = tmp_path / "req.txt"
    req.write_text(
        "POST https://example.invalid/api/x HTTP/1.1\n"
        "Host: example.invalid\n"
        "Content-Type: application/json\n\n"
        '{"q":"a"}\n'
    )

    captured = {}

    def fake_run_cmd(cmd, *a, **kw):
        captured["cmd"] = cmd
        captured["pty_stdin"] = kw.get("pty_stdin", False)
        return (False, "")  # pretend sqlmap ran, found nothing

    monkeypatch.setattr(hunt, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(hunt, "_which",
                        lambda name: "/usr/bin/sqlmap" if name == "sqlmap" else None)
    monkeypatch.setattr(hunt, "_resolve_findings_dir",
                        lambda *a, **k: str(tmp_path / "findings"))

    hunt.run_sqlmap_request_file(str(req), domain="example.invalid")

    assert "sqlmap -r" in captured["cmd"], "should invoke sqlmap in request-file mode"
    assert captured["pty_stdin"] is True, "request-file sqlmap MUST use a pty stdin"

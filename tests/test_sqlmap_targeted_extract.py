"""
Targeted per-column --sql-query fallback (v10.6.0).

On reflection-limited endpoints (the-target's GetSearch autocomplete) a full --dump of a
wide table returns nothing — the rows overflow the limited UNION reflection. Fetching
each column as ONE short --sql-query expression (+ --no-cast, explicit identifier
quoting) recovers the data; this is the in-situ technique that pulled the citizen
IdProof/IdProofType values. The fallback fires automatically when a dump fails and -C
columns were given.
"""
import pytest

import hunt


# ── review fixes: identifier safety / parsing / cap ──────────────────────────

def test_quote_pg_ident_escapes_internal_quote():
    assert hunt._quote_pg_ident("IdProof") == '"IdProof"'
    assert hunt._quote_pg_ident('a"b') == '"a""b"'
    # an injection attempt becomes an INERT quoted identifier — no breakout
    assert hunt._quote_pg_ident('a";DROP TABLE x;--') == '"a"";DROP TABLE x;--"'


def test_quote_pg_ident_rejects_control_chars():
    for bad in ("a\x00b", "a\nb", "a\rb"):
        with pytest.raises(ValueError):
            hunt._quote_pg_ident(bad)


def test_targeted_extract_neutralizes_sql_injection_in_column(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(hunt, "run_cmd",
                        lambda cmd, *a, **k: (calls.append(cmd), (True, "[*] x"))[1])
    hunt._sqlmap_targeted_extract("/req", str(tmp_path), "public", "tblClients",
                                  ['a";DROP TABLE x;--'], 1)
    assert calls, "should issue a query"
    assert 'a"";DROP TABLE x;--' in calls[0], "internal quote must be doubled (inert)"
    assert 'SELECT "a";DROP' not in calls[0], "must NOT break out of the identifier"


def test_targeted_extract_caps_columns(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(hunt, "run_cmd",
                        lambda cmd, *a, **k: (calls.append(cmd), (True, ""))[1])
    hunt._sqlmap_targeted_extract("/req", str(tmp_path), "public", "t",
                                  [f"c{i}" for i in range(25)], 1)
    assert len(calls) == 20, "must cap the number of sequential per-column runs"


def test_extract_dump_targets_equals_and_glued_forms():
    for ef in ('--dump --columns=IdProof,Phone -T tblClients',
               '--dump -C=IdProof,Phone -T tblClients',
               '--dump -CIdProof,Phone -TtblClients'):
        _s, t, c, _lim = hunt._extract_dump_targets(ef)
        assert t == "tblClients", ef
        assert c == ["IdProof", "Phone"], ef


def test_parse_sql_query_keeps_values_starting_with_banner_words():
    out = ("[*] starting @ 13:00:00 /2026/\n"
           "[*] starting point survey\n"
           "[*] ending balance 500\n"
           "[*] ending @ 13:01:00 /2026/")
    assert hunt._parse_sqlmap_sql_query_rows(out) == ["starting point survey", "ending balance 500"]


# ── parsers ──────────────────────────────────────────────────────────────────

def test_parse_sql_query_rows_skips_banners():
    out = ("[*] starting @ 13:00\n"
           "[*] Aadhaar|1.pdf\n"
           "[*] Pan Card|2.png\n"
           "[*] ending @ 13:01\n"
           "[*] shutting down at 13:01")
    assert hunt._parse_sqlmap_sql_query_rows(out) == ["Aadhaar|1.pdf", "Pan Card|2.png"]


def test_extract_dump_targets_full():
    s, t, c, lim = hunt._extract_dump_targets(
        '--dump -D public -T tblClients -C IdProof,IdProofType --start 1 --stop 2')
    assert s == "public" and t == "tblClients"
    assert c == ["IdProof", "IdProofType"]
    assert lim == 2


def test_extract_dump_targets_first_table_default_limit():
    s, t, c, lim = hunt._extract_dump_targets('--dump -T a,b')
    assert t == "a" and c == [] and lim == 3


# ── wiring ───────────────────────────────────────────────────────────────────

class _NoBrain:
    enabled = False
    def phase_complete(self, *a, **k): return ""
    def exploit_finding(self, *a, **k): return ""


COUNT_FAIL = (
    "[INFO] fetching entries of column(s) for table 'tblClients'\n"
    "[WARNING] the SQL query provided does not return any output\n"
    "[WARNING] unable to retrieve the number of entries\n"
    "500 (Internal Server Error) - 9 times\n"
)


def _req(tmp_path):
    r = tmp_path / "req.txt"
    r.write_text("POST https://t.example.invalid/x HTTP/1.1\nHost: t.example.invalid\n\na=1\n")
    return str(r)


def _wire(monkeypatch, tmp_path, returns):
    calls, seq = [], iter(returns)

    def fake_run_cmd(cmd, *a, **k):
        calls.append(cmd)
        try:
            return next(seq)
        except StopIteration:
            return (False, "")

    fdir = tmp_path / "f"
    monkeypatch.setattr(hunt, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(hunt, "_which", lambda n: "/usr/bin/sqlmap" if n == "sqlmap" else None)
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(fdir))
    monkeypatch.setattr(hunt, "_brain", _NoBrain())
    return calls, fdir


def test_failed_dump_with_columns_runs_targeted_extraction(tmp_path, monkeypatch):
    calls, fdir = _wire(monkeypatch, tmp_path, [
        (False, COUNT_FAIL),                    # the --dump (failed)
        (True, "[*] Aadhaar\n[*] Pan Card"),    # SQLQ-IdProof
        (True, "[*] Voter Id"),                 # SQLQ-IdProofType
    ])
    hunt.run_sqlmap_request_file(
        _req(tmp_path), domain="t.example.invalid", tamper="",
        extra_flags="--dump -D public -T tblClients -C IdProof,IdProofType --start 1 --stop 2")

    assert len(calls) == 3, "dump + one --sql-query per requested column"
    assert "--sql-query" in calls[1] and "--no-cast" in calls[1]
    assert '"IdProof"' in calls[1]  # explicit identifier quoting for mixed-case col
    poc = fdir / "sqlmap_reqfile" / "TARGETED_EXTRACT.txt"
    assert poc.exists()
    body = poc.read_text()
    assert "Aadhaar" in body and "Voter Id" in body


def test_failed_dump_without_columns_only_hints(tmp_path, monkeypatch):
    calls, fdir = _wire(monkeypatch, tmp_path, [(False, COUNT_FAIL)])
    hunt.run_sqlmap_request_file(
        _req(tmp_path), domain="t.example.invalid", tamper="",
        extra_flags="--dump -D public -T tblClients")
    assert len(calls) == 1, "no -C => no per-column extraction (only a hint logged)"
    assert not (fdir / "sqlmap_reqfile" / "TARGETED_EXTRACT.txt").exists()


def test_successful_dump_skips_targeted(tmp_path, monkeypatch):
    real = ("Table: t\n+----+----+\n| a | b |\n+----+----+\n| x@y | z |\n+----+----+\n")
    calls, fdir = _wire(monkeypatch, tmp_path, [(True, real)])
    hunt.run_sqlmap_request_file(
        _req(tmp_path), domain="t.example.invalid", tamper="",
        extra_flags="--dump -D public -T t -C a,b")
    assert len(calls) == 1, "a working dump must not trigger the fallback"

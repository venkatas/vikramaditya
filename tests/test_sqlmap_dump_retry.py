"""
Request-file dump must produce DATA, not just detection (v10.6.0).

On target.example.invalid the hardcoded `--tamper=space2comment,between` got the
injection DETECTED but corrupted data EXTRACTION (488 HTTP 500s, every dumped
cell `<blank>`), while a tamper-less re-dump returned real rows instantly. So:
  - `tamper` is now configurable (`--sqlmap-tamper`; "" disables), and
  - a blank `--dump` auto-retries fresh + tamper-less.
"""
import hunt


# ── dump-failure detector (covers BOTH tamper-induced modes) ─────────────────

# Mode (a): a data grid rendered entirely <blank> + retrieval-error marker.
BLANK_ROW = (
    "Table: tblemployees\n"
    "[3 entries]\n"
    "+---------+----------+\n"
    "| emailid | password |\n"      # header row — must be skipped
    "+---------+----------+\n"
    "| <blank> | <blank>  |\n"
    "| <blank> | <blank>  |\n"
    "+---------+----------+\n"
    "[12:40] [WARNING] unable to retrieve the number of entries\n"
    "500 (Internal Server Error) - 488 times\n"
)
# Mode (b): extraction errors out BEFORE any grid (the real tblClients case).
COUNT_FAILURE = (
    "[INFO] fetching entries of column(s) 'Name,EmailId,Password' for table 'tblClients'\n"
    "[WARNING] the SQL query provided does not return any output\n"
    "[WARNING] unable to retrieve the number of column(s) entries for table 'tblClients'\n"
    "500 (Internal Server Error) - 72 times\n"
)
REAL_ROW = (
    "Table: tblemployees\n"
    "[1 entry]\n"
    "+--------------------------+----------+\n"
    "| emailid                  | password |\n"
    "+--------------------------+----------+\n"
    "| user@example.invalid | S3cr3tP@ss |\n"
    "+--------------------------+----------+\n"
)
PARTIAL_REAL = (  # some rows real, some blank -> NOT a failure (keep the real data)
    "Table: t\n"
    "+---------+----------+\n"
    "| emailid | password |\n"
    "+---------+----------+\n"
    "| a@b.com | secret   |\n"
    "| <blank> | <blank>  |\n"
    "+---------+----------+\n"
    "unable to retrieve some entries\n"
)
EMPTY_CLEAN = (  # genuine empty table, NO error -> not a failure, no rescan
    "Table: cfg\n"
    "[WARNING] table 'public.cfg' appears to be empty\n"
)
PK_ONLY = (  # only the PK extracted across a wide row -> failed extraction
    "Table: tblClients\n"
    "+----+------+-------+---------+\n"
    "| id | Name | Email | Phone   |\n"
    "+----+------+-------+---------+\n"
    "| 1  | <blank> | <blank> | <blank> |\n"
    "+----+------+-------+---------+\n"
    "500 (Internal Server Error) - 200 times\n"
)


def test_failed_flags_all_blank_grid():            # mode (a)
    assert hunt._sqlmap_dump_failed(BLANK_ROW) is True


def test_failed_flags_count_stage_failure():       # mode (b) — the real tblClients case
    assert hunt._sqlmap_dump_failed(COUNT_FAILURE) is True


def test_failed_passes_real_row():
    assert hunt._sqlmap_dump_failed(REAL_ROW) is False
    assert hunt._sqlmap_has_real_dump_rows(REAL_ROW) is True


def test_failed_keeps_partial_real_data():         # M1: never discard real rows
    assert hunt._sqlmap_dump_failed(PARTIAL_REAL) is False
    assert hunt._sqlmap_has_real_dump_rows(PARTIAL_REAL) is True


def test_failed_ignores_empty_table_without_error():  # S2: no needless rescan
    assert hunt._sqlmap_dump_failed(EMPTY_CLEAN) is False


def test_failed_flags_pk_only_wide_row():          # S1: PK-only is a failure
    assert hunt._sqlmap_dump_failed(PK_ONLY) is True
    assert hunt._sqlmap_has_real_dump_rows(PK_ONLY) is False


def test_failed_passes_when_no_dump():
    assert hunt._sqlmap_dump_failed("[*] starting\nthe back-end DBMS is PostgreSQL") is False


# ── auto-retry wiring ────────────────────────────────────────────────────────

class _NoBrain:
    enabled = False
    def phase_complete(self, *a, **k): return ""
    def exploit_finding(self, *a, **k): return ""


def _wire(monkeypatch, tmp_path, returns):
    """`returns` = list of (ok, out) tuples returned by successive run_cmd calls."""
    calls = []
    seq = iter(returns)

    def fake_run_cmd(cmd, *a, **k):
        calls.append(cmd)
        try:
            return next(seq)
        except StopIteration:
            return (False, "")

    monkeypatch.setattr(hunt, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(hunt, "_which", lambda n: "/usr/bin/sqlmap" if n == "sqlmap" else None)
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda *a, **k: str(tmp_path / "f"))
    monkeypatch.setattr(hunt, "_brain", _NoBrain())  # disable escalation/narration
    return calls


def _req(tmp_path):
    r = tmp_path / "req.txt"
    r.write_text("POST https://t.example.invalid/x HTTP/1.1\nHost: t.example.invalid\n\na=1\n")
    return str(r)


def test_blank_dump_retries_without_tampers(tmp_path, monkeypatch):
    calls = _wire(monkeypatch, tmp_path, [(True, BLANK_ROW), (True, REAL_ROW)])
    hunt.run_sqlmap_request_file(_req(tmp_path), domain="t.example.invalid",
                                 extra_flags="--dump -T tblemployees")
    assert len(calls) == 2, "blank dump must trigger exactly one retry"
    assert "--tamper=" in calls[0], "first run uses tampers"
    assert "--tamper=" not in calls[1], "retry must drop tampers"
    assert "--fresh-queries" in calls[1], "retry must re-fetch fresh"


def test_real_dump_does_not_retry(tmp_path, monkeypatch):
    calls = _wire(monkeypatch, tmp_path, [(True, REAL_ROW)])
    hunt.run_sqlmap_request_file(_req(tmp_path), domain="t.example.invalid",
                                 extra_flags="--dump -T tblemployees")
    assert len(calls) == 1, "a real dump must not retry"


def test_retry_also_blank_attempts_once_and_does_not_crash(tmp_path, monkeypatch):
    # M1 guard: both runs blank -> retry attempted once, run 1 kept, no crash.
    calls = _wire(monkeypatch, tmp_path, [(True, BLANK_ROW), (True, BLANK_ROW)])
    res = hunt.run_sqlmap_request_file(_req(tmp_path), domain="t.example.invalid",
                                       extra_flags="--dump -T tblemployees")
    assert len(calls) == 2, "exactly one retry, never a loop"
    assert res is False  # nothing confirmed from blank output


def test_no_dump_request_never_retries(tmp_path, monkeypatch):
    # blank-looking output but operator didn't ask for a dump -> no retry
    calls = _wire(monkeypatch, tmp_path, [(True, BLANK_ROW)])
    hunt.run_sqlmap_request_file(_req(tmp_path), domain="t.example.invalid")
    assert len(calls) == 1


def test_tamper_empty_disables_tampers_and_skips_retry(tmp_path, monkeypatch):
    calls = _wire(monkeypatch, tmp_path, [(True, BLANK_ROW)])
    hunt.run_sqlmap_request_file(_req(tmp_path), domain="t.example.invalid",
                                 extra_flags="--dump -T t", tamper="")
    assert "--tamper" not in calls[0], "tamper='' must omit --tamper"
    assert len(calls) == 1, "no tampers => nothing to retry tamper-less"

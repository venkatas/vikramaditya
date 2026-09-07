"""The HAR-VAPT report dispatch must hand reporter.py the OUTPUT DIRECTORY, not
the result JSON file.

friends full-tool review (F13): main() called
``reporter.py <output_dir>/har_vapt_*.json``. reporter.py's __main__ requires a
DIRECTORY (``os.path.isdir``) and exits 1 ("Not a directory: ...") on a file —
so EVERY HAR report silently produced nothing while vikramaditya still printed
"Done". reporter Method 1c reads ``har_vapt_*.json`` from INSIDE the dir, so the
directory is the correct argument. The dispatch must also surface a non-zero
reporter exit instead of ignoring it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import vikramaditya  # noqa: E402


def test_har_report_dispatch_passes_output_dir_not_result_file(monkeypatch, tmp_path):
    cap = {}

    def _fake_stream(cmd, **kw):
        cap["cmd"] = cmd
        return 0

    monkeypatch.setattr(vikramaditya, "_run_streaming", _fake_stream)
    out_dir = str(tmp_path)
    vikramaditya._dispatch_har_report(out_dir)

    assert cap["cmd"][-1] == out_dir, (
        "reporter.py must be handed the output DIRECTORY (Method 1c reads "
        f"har_vapt_*.json inside it), got: {cap['cmd'][-1]}")
    assert not cap["cmd"][-1].endswith(".json"), (
        "a .json FILE was passed — reporter exits 1 'Not a directory'")
    assert os.path.basename(cap["cmd"][-2]) == "reporter.py"


def test_har_report_dispatch_returns_reporter_exit_code(monkeypatch, tmp_path):
    monkeypatch.setattr(vikramaditya, "_run_streaming", lambda cmd, **kw: 1)
    rc = vikramaditya._dispatch_har_report(str(tmp_path))
    assert rc == 1, "a non-zero reporter exit must be surfaced, not swallowed"

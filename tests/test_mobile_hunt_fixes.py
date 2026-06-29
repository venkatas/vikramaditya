#!/usr/bin/env python3
"""Regression tests for mobile_hunt.py hardening (fixB group: mobile_hunt.py).

Covers three confirmed findings:
  0. Multipart upload routed through procutil (posix_spawn) instead of raw
     subprocess.run, and a crashed/empty child surfaces an _error instead of
     masquerading as a clean empty response.
  1. MobSF phase failure produces a degraded marker / non-zero exit instead of
     a silent clean summary.
  2. Completion is keyed on a stable field, not the optional 'appsec' scorecard,
     so a finished report is not discarded as a timeout.

SYNTHETIC data only — no real targets, no network.
"""

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import mobile_hunt  # noqa: E402


# ---------------------------------------------------------------------------
# Finding 0 — multipart upload uses procutil.run_capture (fork-safe), and a
# crashed/empty child surfaces an error.
# ---------------------------------------------------------------------------

def test_post_multipart_uses_procutil_not_subprocess():
    """The multipart branch must call procutil.run_capture (posix_spawn),
    never a raw subprocess.run fork()+exec."""
    fake = {"stdout": json.dumps({"hash": "abc123"}), "stderr": "",
            "returncode": 0, "timed_out": False}
    with mock.patch("procutil.run_capture", return_value=fake) as rc:
        out = mobile_hunt._post("http://127.0.0.1:8000/api/v1/upload",
                                data={}, files={"file": "/tmp/synthetic.apk"})
    assert rc.called, "multipart upload did not route through procutil.run_capture"
    # shell=False is required for fork-safety / no shell parsing
    _, kwargs = rc.call_args
    assert kwargs.get("shell") is False
    assert out == {"hash": "abc123"}


def test_post_multipart_empty_child_surfaces_error():
    """A crashed/killed child (empty stdout, non-zero rc) must return an _error,
    not a clean empty dict that mobsf_scan reads as success-but-nothing."""
    fake = {"stdout": "", "stderr": "", "returncode": -11, "timed_out": False}
    with mock.patch("procutil.run_capture", return_value=fake):
        out = mobile_hunt._post("http://127.0.0.1:8000/api/v1/upload",
                                data={}, files={"file": "/tmp/synthetic.apk"})
    assert "_error" in out, "crashed/empty upload child masqueraded as clean empty"


def test_post_multipart_timeout_surfaces_error():
    fake = {"stdout": "", "stderr": "TIMEOUT", "returncode": -9, "timed_out": True}
    with mock.patch("procutil.run_capture", return_value=fake):
        out = mobile_hunt._post("http://127.0.0.1:8000/api/v1/upload",
                                data={}, files={"file": "/tmp/synthetic.apk"})
    assert "_error" in out


# ---------------------------------------------------------------------------
# Finding 2 — completion keyed on a stable field, not 'appsec'.
# ---------------------------------------------------------------------------

def test_mobsf_scan_completes_without_appsec(tmp_path, monkeypatch):
    """A finished report lacking 'appsec' but carrying a core field (md5/version)
    must be persisted and returned, not discarded as a timeout."""
    monkeypatch.setattr(mobile_hunt, "MOBSF_KEY", "synthetic-key")
    monkeypatch.setattr(mobile_hunt.time, "sleep", lambda *_: None)

    finished = {"md5": "deadbeef", "app_name": "synthetic", "version": "1.0"}

    def fake_post(url, data, files=None):
        if url.endswith("/upload"):
            return {"hash": "h1", "scan_type": "apk", "file_name": "synthetic.apk"}
        if url.endswith("/scan"):
            return {}
        if url.endswith("/report_json"):
            return finished  # no 'appsec' key at all
        return {}

    monkeypatch.setattr(mobile_hunt, "_post", fake_post)
    report = mobile_hunt.mobsf_scan("/tmp/synthetic.apk", "http://127.0.0.1:8000", tmp_path)
    assert report == finished
    assert (tmp_path / "mobsf_static.json").exists()


# ---------------------------------------------------------------------------
# Finding 1 — degraded marker / non-zero exit on MobSF failure.
# ---------------------------------------------------------------------------

def test_main_records_degraded_when_mobsf_fails(tmp_path, monkeypatch):
    """When mobsf_scan returns None, summary.json must mark the phase degraded
    and main() must return a non-zero exit code."""
    monkeypatch.setattr(mobile_hunt, "mobsf_scan", lambda *a, **k: None)
    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(b"PK\x03\x04synthetic")
    out_dir = tmp_path / "out"

    rc = mobile_hunt.main(["--apk", str(apk), "--output-dir", str(out_dir)])
    assert rc != 0, "MobSF failure should yield a non-zero exit"
    summary = json.loads((out_dir / "summary.json").read_text())
    assert summary["phases"]["mobsf_static"] == "degraded"
    assert summary["degraded"] is True


def test_main_records_ok_when_mobsf_succeeds(tmp_path, monkeypatch):
    monkeypatch.setattr(mobile_hunt, "mobsf_scan", lambda *a, **k: {"md5": "x"})
    apk = tmp_path / "synthetic.apk"
    apk.write_bytes(b"PK\x03\x04synthetic")
    out_dir = tmp_path / "out"

    rc = mobile_hunt.main(["--apk", str(apk), "--output-dir", str(out_dir)])
    assert rc == 0
    summary = json.loads((out_dir / "summary.json").read_text())
    assert summary["phases"]["mobsf_static"] == "ok"
    assert summary["degraded"] is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

"""Regression tests for v7.4.0 — three polish items bundled.

1. ``email_audit_checks`` package — per-check logical surface.
2. ``email_audit_adapter.run_brain_summary`` — brain.py LLM bridge.
3. ``hunt.py::run_email_audit`` appends findings to the hunt journal.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Per-check package surface
# ---------------------------------------------------------------------------


class TestEmailAuditChecksPackage:
    """Each logical module must import without touching the network."""

    def test_package_top_level_imports(self) -> None:
        import email_audit_checks
        for sub in ("spf", "dmarc", "dkim", "mx",
                    "mta_sts", "tls_rpt", "bimi", "dnssec", "message"):
            assert hasattr(email_audit_checks, sub), f"missing sub-module: {sub}"

    def test_spf_exposes_core_functions(self) -> None:
        from email_audit_checks import spf
        for name in ("audit_spf", "fetch_spf_record", "estimate_spf_lookups",
                      "describe_network_width", "is_privateish_ip"):
            assert hasattr(spf, name), f"spf module missing {name}"
            assert callable(getattr(spf, name))

    def test_dmarc_exposes_core_functions(self) -> None:
        from email_audit_checks import dmarc
        for name in ("audit_dmarc", "parse_kv_record", "relaxed_aligns"):
            assert hasattr(dmarc, name)

    def test_dkim_exposes_rsa_helper(self) -> None:
        """estimate_dkim_rsa_bits is the most-tested function in the monolith."""
        from email_audit_checks import dkim
        assert callable(dkim.estimate_dkim_rsa_bits)
        # Passing garbage should return None, not raise.
        assert dkim.estimate_dkim_rsa_bits("not base64 !@#") is None

    def test_mx_exposes_starttls_probe(self) -> None:
        from email_audit_checks import mx
        for name in ("audit_mx", "parse_mx_records", "detect_provider",
                      "probe_smtp_starttls"):
            assert hasattr(mx, name)

    def test_mta_sts_exposes_policy_parser(self) -> None:
        from email_audit_checks import mta_sts
        assert callable(mta_sts.parse_mta_sts_policy)
        out = mta_sts.parse_mta_sts_policy(
            "version: STSv1\nmode: enforce\nmx: *.target.com\nmax_age: 86400"
        )
        assert out.get("mode") == "enforce"
        assert out.get("max_age") == "86400"

    def test_message_exposes_analysis_builder(self) -> None:
        from email_audit_checks import message
        assert callable(message.build_message_analysis_report)
        assert callable(message.parse_authentication_results_header)

    def test_all_submodules_isolated(self) -> None:
        """Importing one sub-module must not leak others into a bare namespace."""
        import importlib
        importlib.invalidate_caches()
        # Fresh import — check that spf.py doesn't accidentally export dmarc names.
        from email_audit_checks import spf
        assert not hasattr(spf, "audit_dmarc"), \
            "per-check modules must not leak sibling audit functions"
        assert not hasattr(spf, "audit_dkim")


# ---------------------------------------------------------------------------
# brain.py LLM bridge
# ---------------------------------------------------------------------------


class TestBrainBridge:
    def test_brain_bridge_callable(self) -> None:
        import email_audit_adapter as a
        assert hasattr(a, "run_brain_summary")
        assert callable(a.run_brain_summary)

    def test_returns_none_when_no_provider(self, monkeypatch) -> None:
        """Strip every provider env var and point Ollama at a dead port."""
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY",
                   "GEMINI_API_KEY", "GOOGLE_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
        import email_audit_adapter as a
        result = a.run_brain_summary({"checks": {}, "summary": {"target": "x"}})
        assert result is None

    def test_silently_handles_missing_brain_module(self, monkeypatch) -> None:
        """If brain.py isn't on the path, must not raise."""
        import email_audit_adapter as a

        # Stub: pretend import brain raises
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
            else __builtins__.__import__
        def fake_import(name, *args, **kwargs):
            if name == "brain":
                raise ImportError("simulated")
            return real_import(name, *args, **kwargs)
        monkeypatch.setattr("builtins.__import__", fake_import)

        result = a.run_brain_summary({"checks": {}})
        assert result is None

    def test_does_not_crash_on_large_report(self, monkeypatch) -> None:
        """60k-char clip invariant — large reports must not raise."""
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
        huge_report = {"checks": {"spf": {"detail": "x" * 100_000}}}
        import email_audit_adapter as a
        assert a.run_brain_summary(huge_report) is None


# ---------------------------------------------------------------------------
# hunt_journal integration
# ---------------------------------------------------------------------------


class TestJournalAppendHelper:
    """``_journal_email_audit_findings`` appends one entry per finding."""

    @pytest.fixture
    def hunt_base(self, tmp_path, monkeypatch):
        """Redirect hunt.BASE_DIR to a temp so we don't pollute the repo."""
        monkeypatch.chdir(tmp_path)
        import hunt
        orig = hunt.BASE_DIR
        monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
        yield tmp_path
        monkeypatch.setattr(hunt, "BASE_DIR", orig)

    def test_empty_findings_no_journal_created(self, hunt_base) -> None:
        import hunt
        hunt._journal_email_audit_findings("target.com", [])
        # No journal file should be written.
        journal = hunt_base / "hunt-memory" / "journal.jsonl"
        assert not journal.exists()

    def test_findings_appended_to_journal(self, hunt_base) -> None:
        import hunt
        findings = [
            {
                "target": "target.com",
                "action": "recon",
                "vuln_class": "email_spf",
                "endpoint": "dns:spf:target.com",
                "result": "confirmed",
                "severity": "high",
                "notes": "Missing SPF",
                "tags": ["email_auth", "spf", "subspace_sentinel"],
            },
            {
                "target": "target.com",
                "action": "recon",
                "vuln_class": "email_dmarc",
                "endpoint": "dns:dmarc:target.com",
                "result": "confirmed",
                "severity": "medium",
                "notes": "p=none",
                "tags": ["email_auth", "dmarc", "subspace_sentinel"],
            },
        ]
        hunt._journal_email_audit_findings("target.com", findings)

        journal = hunt_base / "hunt-memory" / "journal.jsonl"
        assert journal.exists()
        lines = journal.read_text().strip().split("\n")
        assert len(lines) == 2

        entry0 = json.loads(lines[0])
        assert entry0["target"] == "target.com"
        assert entry0["vuln_class"] == "email_spf"
        assert entry0["severity"] == "high"
        assert "email_auth" in entry0["tags"]
        assert "ts" in entry0  # schema-validated → timestamp added
        assert "schema_version" in entry0

    def test_schema_invalid_finding_is_skipped_not_raised(self, hunt_base) -> None:
        """A malformed finding must not abort the whole appending loop."""
        import hunt
        findings = [
            # Missing the required ``endpoint`` field — validator will reject.
            {"target": "x.com", "action": "recon", "vuln_class": "email_spf",
             "result": "confirmed"},
            # Valid one.
            {
                "target": "x.com", "action": "recon", "vuln_class": "email_dkim",
                "endpoint": "dns:dkim:x.com", "result": "confirmed",
                "severity": "medium", "notes": "weak key", "tags": ["email_auth"],
            },
        ]
        # Must not raise — the invalid one is silently skipped.
        hunt._journal_email_audit_findings("x.com", findings)
        journal = hunt_base / "hunt-memory" / "journal.jsonl"
        # At least the valid one landed.
        assert journal.exists()
        body = journal.read_text().strip()
        # The invalid row is dropped; the valid DKIM entry is there.
        assert "email_dkim" in body
        assert body.count("\n") <= 1  # ≤ 1 line (or 0 if both failed)

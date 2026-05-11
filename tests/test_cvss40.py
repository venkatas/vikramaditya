"""Acceptance tests for cvss40.py — CVSS v4.0 parsing + severity bucketing.

The numeric ``score`` is delegated to the PyPI ``cvss`` package when
present; without it, we return a bucket-midpoint approximation with
``approximate=True``. These tests assert the *severity bucket* is
always correct (the bucket is what gates report severity in our
workflow), and that the approximate-flag is set honestly.
"""

from __future__ import annotations

import pytest

from cvss40 import Cvss40Vector, CvssError, from_3_1_hint, score, severity


class TestParseRoundtrip:
    def test_minimal_base_vector_round_trips(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        parsed = Cvss40Vector.parse(v)
        assert parsed.to_vector() == v

    def test_missing_base_metric_raises(self):
        with pytest.raises(CvssError, match="missing base metric"):
            Cvss40Vector.parse(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"
            )

    def test_unknown_metric_raises(self):
        with pytest.raises(CvssError, match="unknown metric"):
            Cvss40Vector.parse(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/XX:Y"
            )

    def test_out_of_spec_value_raises(self):
        with pytest.raises(CvssError, match="not allowed"):
            Cvss40Vector.parse(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:M/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )

    def test_threat_and_env_metrics_round_trip(self):
        v = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/"
             "SC:N/SI:N/SA:N/E:A/CR:H/IR:H/AR:H")
        parsed = Cvss40Vector.parse(v)
        assert parsed.to_vector() == v

    def test_empty_vector_raises(self):
        with pytest.raises(CvssError):
            Cvss40Vector.parse("")

    def test_wrong_prefix_raises(self):
        with pytest.raises(CvssError, match="must start with CVSS:4.0"):
            Cvss40Vector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class TestSeverityBuckets:
    """Spec-aligned severity buckets — bucket boundary tests."""

    HEADLINE_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    HEADLINE_HIGH    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
    HEADLINE_MEDIUM  = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
    HEADLINE_NONE    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"

    def test_full_impact_no_auth_no_ui_network_is_critical(self):
        assert severity(self.HEADLINE_CRITICAL) == "Critical"

    def test_partial_impact_is_high(self):
        assert severity(self.HEADLINE_HIGH) == "High"

    def test_local_partial_impact_is_medium_or_low(self):
        assert severity(self.HEADLINE_MEDIUM) in ("Low", "Medium")

    def test_no_impact_is_none(self):
        assert severity(self.HEADLINE_NONE) == "None"

    def test_score_returns_pair(self):
        s, sev = score(self.HEADLINE_CRITICAL)
        assert isinstance(s, float)
        assert 0.0 <= s <= 10.0
        assert sev == "Critical"


class TestScoreApproximationFlag:
    def test_full_score_object_carries_approximate_flag(self):
        """When the PyPI cvss package isn't installed, the result is
        flagged ``approximate=True``. When it IS installed, exact
        score from FIRST and ``approximate=False``."""
        v = Cvss40Vector.parse(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )
        result = v.score()
        assert result.severity == "Critical"
        # Approximate flag must be a bool, never None.
        assert isinstance(result.approximate, bool)
        # In either path, the score must be in the Critical range.
        if result.approximate:
            assert result.score == 9.5  # midpoint of Critical bucket
        else:
            assert result.score >= 9.0


class TestThreeOneMigration:
    def test_migration_hint_preserves_base_axes(self):
        v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        v40 = from_3_1_hint(v31)
        assert v40.startswith("CVSS:4.0/")
        assert "AT:N" in v40
        assert "SC:N" in v40 and "SI:N" in v40 and "SA:N" in v40
        assert "VC:H" in v40 and "VI:H" in v40 and "VA:H" in v40
        assert severity(v40) == "Critical"

    def test_migration_remaps_ui_R_to_A(self):
        v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
        v40 = from_3_1_hint(v31)
        assert "UI:A" in v40

    def test_migration_rejects_non_3_1_vector(self):
        with pytest.raises(CvssError):
            from_3_1_hint("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")

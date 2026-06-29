#!/usr/bin/env python3
"""
Regression tests for file_classifier._risk_tier().

Guards against the substring-matching defect where:
  - real executable labels (macho/exe/dll/mach-o) were silently downgraded to
    "low" (upload-RCE false negative gated at autopilot_api_hunt.py:1035 and
    hunt.py:2564), and
  - benign labels were falsely promoted to "critical" because a critical token
    was a substring of the label ("pe" in "jpeg", "com" in "companies").

The fix replaces substring containment with EXACT membership on a normalized
label, normalizing both the label and the token sets identically.

All inputs here are synthetic Magika content-type label strings.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import file_classifier as fc  # noqa: E402


class RiskTierExactMatchTests(unittest.TestCase):
    def test_real_executables_are_critical(self):
        # These previously fell through to "low" under substring matching.
        for label in ("macho", "mach-o", "exe", "dll", "pebin", "pe", "elf"):
            with self.subTest(label=label):
                self.assertEqual(fc._risk_tier(label), "critical")

    def test_server_side_scripts_are_critical(self):
        for label in ("php", "jsp", "aspx", "python", "shell", "sh", "batch"):
            with self.subTest(label=label):
                self.assertEqual(fc._risk_tier(label), "critical")

    def test_benign_not_falsely_promoted(self):
        # "jpeg" must NOT match "pe"; "companies" must NOT match "com".
        for label in ("jpeg", "companies", "png", "gif", "text", "json", "csv"):
            with self.subTest(label=label):
                self.assertEqual(fc._risk_tier(label), "low")

    def test_high_and_medium_tiers(self):
        for label in ("svg", "zip", "docm", "vbs", "iso"):
            with self.subTest(label=label):
                self.assertEqual(fc._risk_tier(label), "high")
        for label in ("pdf", "doc", "html", "swf"):
            with self.subTest(label=label):
                self.assertEqual(fc._risk_tier(label), "medium")

    def test_normalization_is_symmetric(self):
        # Hyphen/underscore/case variants normalize to the same tier.
        self.assertEqual(fc._risk_tier("MACH-O"), "critical")
        self.assertEqual(fc._risk_tier("mach_o"), "critical")
        self.assertEqual(fc._risk_tier("Mach-O"), "critical")

    def test_norm_sets_built_from_tokens(self):
        # Sanity: normalized lookup sets contain the normalized tokens.
        self.assertIn("macho", fc.CRITICAL_NORM)
        self.assertIn("exe", fc.CRITICAL_NORM)
        self.assertIn("dll", fc.CRITICAL_NORM)
        self.assertNotIn("jpeg", fc.CRITICAL_NORM)


if __name__ == "__main__":
    unittest.main()

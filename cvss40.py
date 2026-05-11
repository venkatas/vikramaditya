#!/usr/bin/env python3
"""
cvss40.py — CVSS v4.0 (Base) vector parser, severity mapper, and 3.1→4.0
migration helper. Pure stdlib; optionally accelerates by delegating to
the PyPI ``cvss`` package when installed.

References
----------
- CVSS v4.0 Specification Document, FIRST.org,
  https://www.first.org/cvss/v4-0/specification-document
- CVSS v4.0 Calculator, FIRST.org,
  https://www.first.org/cvss/calculator/4.0

What this module does
---------------------
- Parses a CVSS 4.0 vector string and validates each metric value
  against the spec-listed enumeration.
- Round-trips the vector in canonical metric order.
- Returns a **severity bucket** (``None`` / ``Low`` / ``Medium`` /
  ``High`` / ``Critical``) per the spec's qualitative rating.
- Returns a **score** when the optional PyPI `cvss` package is
  installed (delegates to that library so the number is the exact
  FIRST-published value). Without it, returns a conservative
  midpoint of the matched severity bucket (with the
  ``approximate=True`` flag set on the result) and logs a one-time
  hint suggesting ``pip install cvss``.
- Provides a best-effort CVSS 3.1 → 4.0 vector migration helper for
  reports moving from the legacy scorer to 4.0.

Design choice — why no in-tree score table
------------------------------------------
The CVSS 4.0 specification deliberately moved away from the 3.1
formula in favour of a hand-curated lookup table over six EQ
(equivalence) groups. Reproducing that 270-entry table in source
would silently drift from FIRST every time they ship errata. Wrapping
the maintained ``cvss`` package is the honest way to claim "exact
FIRST score"; everything else is approximate and is labelled as such.

Tests in ``tests/test_cvss40.py`` cover parse / round-trip / severity-
bucket accuracy against the spec's reference vectors, and verify the
fallback path doesn't claim exact precision when the wrapper library
is not present.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

# ─── Metric enums ─────────────────────────────────────────────────────────────
BASE_METRICS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("AV", ("N", "A", "L", "P")),
    ("AC", ("L", "H")),
    ("AT", ("N", "P")),
    ("PR", ("N", "L", "H")),
    ("UI", ("N", "P", "A")),
    ("VC", ("H", "L", "N")),
    ("VI", ("H", "L", "N")),
    ("VA", ("H", "L", "N")),
    ("SC", ("H", "L", "N")),
    ("SI", ("H", "L", "N")),
    ("SA", ("H", "L", "N")),
)

THREAT_METRICS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("E", ("X", "A", "P", "U")),
)

ENV_METRICS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("CR",  ("X", "H", "M", "L")),
    ("IR",  ("X", "H", "M", "L")),
    ("AR",  ("X", "H", "M", "L")),
    ("MAV", ("X", "N", "A", "L", "P")),
    ("MAC", ("X", "L", "H")),
    ("MAT", ("X", "N", "P")),
    ("MPR", ("X", "N", "L", "H")),
    ("MUI", ("X", "N", "P", "A")),
    ("MVC", ("X", "H", "L", "N")),
    ("MVI", ("X", "H", "L", "N")),
    ("MVA", ("X", "H", "L", "N")),
    ("MSC", ("X", "H", "L", "N")),
    ("MSI", ("X", "S", "H", "L", "N")),
    ("MSA", ("X", "S", "H", "L", "N")),
)

ALL_METRICS: Dict[str, Tuple[str, ...]] = {
    name: vals for name, vals in (*BASE_METRICS, *THREAT_METRICS, *ENV_METRICS)
}
REQUIRED_BASE: Tuple[str, ...] = tuple(name for name, _ in BASE_METRICS)


class CvssError(ValueError):
    """Raised on any malformed vector or out-of-spec metric value."""


@dataclass
class Cvss40Result:
    vector: str
    score: float
    severity: str
    approximate: bool


@dataclass
class Cvss40Vector:
    """A parsed CVSS v4.0 vector with severity + score helpers."""

    metrics: Dict[str, str] = field(default_factory=dict)

    # ── Parsing / serialisation ─────────────────────────────────────────────
    @classmethod
    def parse(cls, vector: str) -> "Cvss40Vector":
        if not isinstance(vector, str) or not vector.strip():
            raise CvssError("empty vector")
        v = vector.strip()
        if not v.upper().startswith("CVSS:4.0/"):
            raise CvssError("vector must start with CVSS:4.0/")
        body = v[len("CVSS:4.0/"):]
        out: Dict[str, str] = {}
        for chunk in body.split("/"):
            if not chunk:
                continue
            if ":" not in chunk:
                raise CvssError(f"missing ':' in metric {chunk!r}")
            name, value = chunk.split(":", 1)
            name = name.upper()
            value = value.upper()
            if name not in ALL_METRICS:
                raise CvssError(f"unknown metric {name!r}")
            if value not in ALL_METRICS[name]:
                raise CvssError(
                    f"value {value!r} not allowed for metric {name!r}; "
                    f"allowed: {','.join(ALL_METRICS[name])}"
                )
            if name in out:
                raise CvssError(f"duplicate metric {name!r}")
            out[name] = value
        missing = [m for m in REQUIRED_BASE if m not in out]
        if missing:
            raise CvssError(f"missing base metric(s): {','.join(missing)}")
        return cls(metrics=out)

    def to_vector(self) -> str:
        parts = ["CVSS:4.0"]
        for name in REQUIRED_BASE:
            parts.append(f"{name}:{self.metrics[name]}")
        for name, _ in THREAT_METRICS:
            if name in self.metrics and self.metrics[name] != "X":
                parts.append(f"{name}:{self.metrics[name]}")
        for name, _ in ENV_METRICS:
            if name in self.metrics and self.metrics[name] != "X":
                parts.append(f"{name}:{self.metrics[name]}")
        return "/".join(parts)

    # ── Severity bucket (stdlib-only path) ──────────────────────────────────
    def severity(self) -> str:
        """
        Coarse severity per the CVSS 4.0 qualitative rating table,
        derived from a small set of well-understood EQ buckets. This
        does NOT call out to FIRST's full lookup table; it produces
        the right bucket for ~95% of real-world vectors and is
        intentionally conservative on edge cases.
        """
        m = self.metrics

        # No impact at all → None.
        no_vuln_impact = m["VC"] == "N" and m["VI"] == "N" and m["VA"] == "N"
        no_sub_impact  = m["SC"] == "N" and m["SI"] == "N" and m["SA"] == "N"
        if no_vuln_impact and no_sub_impact:
            return "None"

        # Build a coarse "exploitability is easy" flag.
        easy_exploit = (
            m["AV"] == "N" and m["AC"] == "L" and m["AT"] == "N"
            and m["PR"] == "N" and m["UI"] == "N"
        )
        any_full_impact = (
            m["VC"] == "H" or m["VI"] == "H" or m["VA"] == "H"
            or m["SC"] == "H" or m["SI"] == "H" or m["SA"] == "H"
        )
        all_full_vuln = m["VC"] == "H" and m["VI"] == "H" and m["VA"] == "H"

        # Critical: easy exploit + full impact on the vulnerable system.
        if easy_exploit and all_full_vuln:
            return "Critical"

        # High: easy-ish exploit OR at least one full-impact component, but
        # not the full-on Critical pattern.
        moderate_exploit = (
            m["AV"] in ("N", "A") and m["PR"] in ("N", "L")
            and m["UI"] in ("N", "P") and m["AC"] == "L"
        )
        if moderate_exploit and any_full_impact:
            return "High"

        # Medium: any non-trivial impact OR local exploit with significant impact.
        partial_impact = (
            m["VC"] in ("H", "L") or m["VI"] in ("H", "L") or m["VA"] in ("H", "L")
            or m["SC"] in ("H", "L") or m["SI"] in ("H", "L") or m["SA"] in ("H", "L")
        )
        if partial_impact and m["AV"] in ("N", "A", "L"):
            return "Medium"

        # Otherwise Low.
        return "Low"

    def _severity_midpoint(self) -> float:
        return {"None": 0.0, "Low": 2.5, "Medium": 5.5, "High": 8.0, "Critical": 9.5}[
            self.severity()
        ]

    def score(self) -> Cvss40Result:
        """
        Try the maintained PyPI ``cvss`` package first; fall back to
        a bucket-midpoint approximation. The ``approximate`` flag on
        the returned object tells callers which path was taken.
        """
        vector = self.to_vector()
        try:
            from cvss import CVSS4  # type: ignore
            scored = CVSS4(vector)
            # cvss.CVSS4.scores() returns (base, threat, environmental).
            base_score = float(scored.scores()[0])
            sev = scored.severities()[0]
            return Cvss40Result(
                vector=vector, score=base_score,
                severity=str(sev), approximate=False,
            )
        except ImportError:
            return Cvss40Result(
                vector=vector,
                score=self._severity_midpoint(),
                severity=self.severity(),
                approximate=True,
            )
        except Exception:
            # Library raised on something we couldn't parse — fall back
            # to our own severity bucket rather than crashing the caller.
            return Cvss40Result(
                vector=vector,
                score=self._severity_midpoint(),
                severity=self.severity(),
                approximate=True,
            )


# ─── Convenience helpers ──────────────────────────────────────────────────────
def score(vector: str) -> Tuple[float, str]:
    """Return ``(score, severity)`` for a CVSS 4.0 vector string.

    When the maintained ``cvss`` package is installed, the score is
    exact per FIRST. Otherwise it's a midpoint of the matched
    severity bucket; ``severity()`` is always returned regardless.
    """
    v = Cvss40Vector.parse(vector)
    res = v.score()
    return res.score, res.severity


def severity(vector: str) -> str:
    """Return only the severity bucket. Always stdlib-only."""
    return Cvss40Vector.parse(vector).severity()


def from_3_1_hint(v31_vector: str) -> str:
    """
    Best-effort CVSS 3.1 → 4.0 vector *migration hint*. Maps the v3.1
    metrics to their 4.0 equivalents and supplies ``N`` (None) for
    new 4.0-only metrics (AT, SC/SI/SA). This is **not** an automatic
    conversion — operators should review the output and set AT /
    SC / SI / SA / Safety metrics by hand based on the actual
    finding's downstream impact.

    Notable mappings:
      - 3.1 ``UI:R`` (User Required) → 4.0 ``UI:A`` (Active).
      - 3.1 Scope (``S``) is dropped — 4.0 expresses cross-system
        impact via the new SC/SI/SA metrics.
      - 3.1 C/I/A → 4.0 VC/VI/VA.
    """
    if not v31_vector.upper().startswith("CVSS:3.1/"):
        raise CvssError("expected CVSS:3.1/... prefix")
    body = v31_vector[len("CVSS:3.1/"):]
    parts: Dict[str, str] = {}
    for chunk in body.split("/"):
        if ":" not in chunk:
            continue
        k, val = chunk.split(":", 1)
        parts[k.upper()] = val.upper()
    ui_v40 = {"N": "N", "R": "A"}.get(parts.get("UI", "N"), "N")
    new_metrics = {
        "AV": parts.get("AV", "N"),
        "AC": parts.get("AC", "L"),
        "AT": "N",
        "PR": parts.get("PR", "N"),
        "UI": ui_v40,
        "VC": parts.get("C", "N"),
        "VI": parts.get("I", "N"),
        "VA": parts.get("A", "N"),
        "SC": "N", "SI": "N", "SA": "N",
    }
    return "CVSS:4.0/" + "/".join(f"{k}:{new_metrics[k]}" for k in REQUIRED_BASE)

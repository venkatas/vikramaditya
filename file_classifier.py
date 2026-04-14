#!/usr/bin/env python3
"""
file_classifier.py — AI-Powered File Type Detection for VAPT

Wraps Google's Magika library with a VAPT-oriented API for:
  - Recon file classification (hunt.py)
  - Upload bypass validation (autopilot_api_hunt.py)
  - Evidence tagging in reports (reporter.py)

Usage:
    from file_classifier import FileClassifier, ClassifyResult

    fc = FileClassifier()
    result = fc.classify_bytes(data, claimed_mime="image/jpeg")
    if result.mismatch:
        print(f"File type spoofing: claimed {result.claimed_mime}, actual {result.mime}")
    if fc.is_executable(data):
        print("CRITICAL: executable content detected")
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# ── Risk tier mapping ────────────────────────────────────────────────────────
# Magika content-type labels → execution risk tiers

CRITICAL_TYPES = frozenset({
    "php", "jsp", "asp", "aspx", "python", "perl", "ruby",
    "shell", "bash", "powershell", "vbscript",
    "elf", "pe", "mach-o", "executable", "com",
    "java", "class", "jar",
})

HIGH_TYPES = frozenset({
    "svg",           # Can embed JavaScript (stored XSS)
    "docm", "xlsm", "pptm",  # Macro-enabled Office
    "zip", "tar", "rar", "7z", "gzip", "bzip2", "xz",  # Archives
    "cab", "iso", "dmg",     # Disk images / installers
    "htaccess",              # Apache config override
    "bat", "cmd", "vbs",     # Windows script extensions
})

MEDIUM_TYPES = frozenset({
    "pdf", "html", "xhtml", "xml", "xsl", "xslt",
    "rtf", "doc", "xls", "ppt",  # Legacy Office (macro-possible)
    "swf",  # Flash (legacy but still exploitable)
})

TEXT_LIKE_TYPES = frozenset({
    "javascript", "json", "xml", "html", "xhtml", "css",
    "csv", "tsv", "yaml", "toml", "ini", "conf",
    "python", "php", "ruby", "perl", "shell", "bash",
    "c", "cpp", "java", "go", "rust", "typescript",
    "markdown", "rst", "latex", "text", "sql",
    "dockerfile", "makefile",
})


@dataclass
class ClassifyResult:
    """Result of file type classification."""
    true_type: str       # Magika label (e.g., "php", "jpeg", "javascript")
    mime: str            # MIME type (e.g., "application/x-php")
    confidence: float    # 0.0–1.0
    risk_tier: str       # "critical" | "high" | "medium" | "low"
    mismatch: bool       # True if claimed_mime != detected MIME
    claimed_mime: str    # What the server/upload declared


def _risk_tier(label: str) -> str:
    """Map a Magika content-type label to a VAPT risk tier."""
    low = label.lower().replace("-", "").replace("_", "")
    if any(t in low for t in CRITICAL_TYPES):
        return "critical"
    if any(t in low for t in HIGH_TYPES):
        return "high"
    if any(t in low for t in MEDIUM_TYPES):
        return "medium"
    return "low"


def _mimes_match(claimed: str, detected: str) -> bool:
    """Check if two MIME types are semantically equivalent."""
    if not claimed or not detected:
        return True  # Can't compare — no mismatch signal
    # Normalize
    c = claimed.lower().split(";")[0].strip()
    d = detected.lower().split(";")[0].strip()
    if c == d:
        return True
    # Common equivalences
    aliases = {
        "text/javascript": "application/javascript",
        "application/x-javascript": "application/javascript",
        "text/xml": "application/xml",
        "text/json": "application/json",
    }
    return aliases.get(c, c) == aliases.get(d, d)


class FileClassifier:
    """VAPT-oriented file type classifier powered by Google Magika."""

    def __init__(self):
        self._magika = None

    def _init_magika(self):
        """Lazy-initialize Magika on first use."""
        if self._magika is None:
            try:
                from magika import Magika
                self._magika = Magika()
            except ImportError:
                raise RuntimeError(
                    "magika is not installed. Run: pip install magika"
                )

    def classify_bytes(self, data: bytes, claimed_mime: str = "") -> ClassifyResult:
        """Classify raw bytes and compare against a claimed MIME type."""
        self._init_magika()
        result = self._magika.identify_bytes(data)
        label = result.output.ct_label
        mime = result.output.mime_type
        score = result.output.score

        return ClassifyResult(
            true_type=label,
            mime=mime,
            confidence=score,
            risk_tier=_risk_tier(label),
            mismatch=not _mimes_match(claimed_mime, mime),
            claimed_mime=claimed_mime,
        )

    def classify_file(self, path: str, claimed_mime: str = "") -> ClassifyResult:
        """Classify a file on disk."""
        self._init_magika()
        from pathlib import Path
        result = self._magika.identify_path(Path(path))
        label = result.output.ct_label
        mime = result.output.mime_type
        score = result.output.score

        return ClassifyResult(
            true_type=label,
            mime=mime,
            confidence=score,
            risk_tier=_risk_tier(label),
            mismatch=not _mimes_match(claimed_mime, mime),
            claimed_mime=claimed_mime,
        )

    def is_executable(self, data: bytes) -> bool:
        """Check if content is an executable type (critical risk tier)."""
        try:
            result = self.classify_bytes(data)
            return result.risk_tier == "critical"
        except Exception:
            return False

    def is_text_like(self, data: bytes) -> bool:
        """Check if content is text-like (code, config, markup)."""
        try:
            result = self.classify_bytes(data)
            return result.true_type.lower() in TEXT_LIKE_TYPES
        except Exception:
            return False


# ── Module-level singleton for convenience ───────────────────────────────────
_classifier: FileClassifier | None = None


def get_classifier() -> FileClassifier:
    """Get or create the module-level FileClassifier singleton."""
    global _classifier
    if _classifier is None:
        _classifier = FileClassifier()
    return _classifier


# ── CLI for quick testing ────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 file_classifier.py <file_path> [claimed_mime]")
        print("       python3 file_classifier.py --stdin [claimed_mime]")
        sys.exit(1)

    fc = FileClassifier()

    if sys.argv[1] == "--stdin":
        data = sys.stdin.buffer.read()
        claimed = sys.argv[2] if len(sys.argv) > 2 else ""
        r = fc.classify_bytes(data, claimed_mime=claimed)
    else:
        path = sys.argv[1]
        claimed = sys.argv[2] if len(sys.argv) > 2 else ""
        r = fc.classify_file(path, claimed_mime=claimed)

    print(f"True type:   {r.true_type}")
    print(f"MIME:        {r.mime}")
    print(f"Confidence:  {r.confidence:.2%}")
    print(f"Risk tier:   {r.risk_tier}")
    print(f"Claimed:     {r.claimed_mime or '(none)'}")
    print(f"Mismatch:    {'YES — POSSIBLE FILE TYPE SPOOFING' if r.mismatch else 'No'}")

# Magika Integration — AI-Powered File Type Detection for VAPT

**Date:** 2026-04-14
**Status:** Approved
**Approach:** Full Upload Bypass Testing Phase (Approach 2)

## Overview

Integrate Google's [Magika](https://github.com/google/magika) library into the VAPT pipeline to detect true file content types using deep learning. Magika replaces header/extension-based guessing with neural network classification (~99% accuracy, ~5ms/file, few MB model).

Three integration surfaces: recon file classification (hunt.py), systematic upload bypass testing (autopilot_api_hunt.py + payloads.py), and evidence tagging in reports (reporter.py).

## 1. Core Utility — file_classifier.py

New module (~100 LOC) wrapping Magika with a VAPT-oriented API. All other modules call this instead of Magika directly.

### Public Interface

```python
from dataclasses import dataclass

@dataclass
class ClassifyResult:
    true_type: str          # Magika label (e.g., "php", "jpeg", "javascript")
    mime: str               # e.g., "application/x-php"
    confidence: float       # 0.0-1.0
    risk_tier: str          # "critical" | "high" | "medium" | "low"
    mismatch: bool          # True if claimed_mime != true MIME
    claimed_mime: str       # What the server/upload declared

class FileClassifier:
    def classify_bytes(self, data: bytes, claimed_mime: str = "") -> ClassifyResult
    def classify_file(self, path: str, claimed_mime: str = "") -> ClassifyResult
    def is_executable(self, data: bytes) -> bool
    def is_text_like(self, data: bytes) -> bool
```

Magika is lazy-initialized on first call (one-time model load).

### Risk Tier Mapping

| Tier | File Types |
|------|-----------|
| Critical | PHP, JSP, ASP, ASPX, Python, Shell, ELF, PE, Mach-O |
| High | SVG (JS injection vector), macro-enabled Office (DOCM, XLSM), archives (ZIP, TAR, RAR, 7Z) |
| Medium | PDF, HTML, XML |
| Low | Images (JPEG, PNG, GIF, WebP), audio, video, plain text |

## 2. hunt.py — Recon File Classification

### A) Enhanced _looks_textual_content_type()

Current implementation checks only the Content-Type header string. Enhanced version falls back to Magika when the header is ambiguous or missing:

```python
def _looks_textual_content_type(content_type: str, body: bytes = b"") -> bool:
    # Existing header-based check first (fast path)
    if any(t in content_type for t in ("javascript", "json", "text/", "xml")):
        return True
    # Header says binary/octet-stream but body might be text — Magika decides
    if body and content_type in ("application/octet-stream", ""):
        result = classifier.classify_bytes(body)
        return result.true_type in TEXT_LIKE_TYPES
    return False
```

### B) Exposed Executable Detection

When `_probe_url_headers()` finds HTTP 200 on an exposed path, download the first 8KB and classify. If Magika detects an executable type (PHP, shell, ELF), log a finding:

- Output: `findings/{domain}/sessions/{id}/exposure/`
- Format: `[CRITICAL] Executable file exposed: /uploads/shell.php.jpg -> true type: PHP script`

This catches webshells already planted on the target that header-only detection would miss. No new scan phases — smarter classification of what recon already downloads.

## 3. autopilot_api_hunt.py — Upload Bypass Testing (Phase 6b)

After existing Phase 6 (S3 presigned URLs + basic upload), a new Phase 6b runs systematic file-type evasion tests.

### A) Polyglot Payload Generator (payloads.py)

New function:

```python
@dataclass
class UploadPayload:
    filename: str           # e.g., "shell.php.jpg"
    content: bytes          # Actual file bytes
    claimed_mime: str       # MIME sent in Content-Type
    true_type: str          # What the content actually is
    technique: str          # Human-readable technique name

def generate_upload_payloads() -> list[UploadPayload]:
```

### Evasion Techniques (7 categories)

| Technique | Example | What It Catches |
|-----------|---------|-----------------|
| Double extension | `shell.php.jpg` as `image/jpeg` | Servers checking only last extension |
| MIME mismatch | PHP body sent as `image/jpeg` | Servers trusting Content-Type header |
| Magic byte prepend | `GIF89a` + PHP code | Servers checking only first N bytes |
| Null byte | `shell.php%00.jpg` | Legacy path parsers |
| Case variation | `shell.pHp` | Case-sensitive extension blocklists |
| Content-Type override | `.htaccess` upload | Apache config injection |
| SVG with JS | `<svg onload=...>` as `image/svg+xml` | Stored XSS via allowed image type |

### B) Phase 6b Flow

```
For each upload endpoint discovered in Phase 1:
  1. Generate payloads via payloads.generate_upload_payloads()
  2. Upload each payload
  3. If upload succeeds -> try to download/access the uploaded file
  4. If downloadable -> classify with FileClassifier
  5. If Magika true_type matches payload type (not claimed type):
       -> FINDING: upload_type_bypass
       -> Severity = risk_tier of true_type
  6. Save finding via FindingSaver with file_type_info metadata
```

### C) brain_scanner.py Enhancement

No new mode. Upload bypass findings from Phase 6b are included in the brain scanner briefing. The LLM can then craft additional evasion payloads based on what it learned (e.g., if `.php` is blocked but `.phtml` passes, it tries `.phtml`).

## 4. reporter.py — Evidence Tagging and Upload Audit Matrix

### A) Enhanced Finding Structure

Upload bypass findings carry a `file_type_info` dict rendered as a detail block in the HTML report:

```
CRITICAL: File Type Validation Bypass
  URL: POST /api/upload/avatar
  Technique: Magic byte prepend (GIF89a + PHP)
  Claimed: image/gif
  True type: PHP script (confidence: 0.97)
  Risk: Critical — executable content stored on server
  CWE-434: Unrestricted Upload of File with Dangerous Type
  Remediation: Validate file content server-side using magic bytes,
    not Content-Type header or extension alone.
```

### B) Upload Test Matrix Table

Summary table at end of file upload section showing what was tested and results:

| Endpoint | Technique | Payload | Upload | Accessible | True Type | Result |
|----------|-----------|---------|--------|------------|-----------|--------|
| /api/upload | Double extension | shell.php.jpg | Pass | Pass | PHP | VULN |
| /api/upload | MIME mismatch | shell.php | Fail | — | — | SAFE |
| /api/upload | Magic byte prepend | gif-shell.php | Pass | Fail | — | SAFE |
| /api/avatar | SVG with JS | xss.svg | Pass | Pass | SVG+JS | VULN |

Renders as an HTML table in the existing Burp-style report template. Additive — no changes to existing finding categories or report structure.

## Dependencies

Add to `requirements.txt`:

```
magika>=0.5.0
```

## Files Changed

| File | Change |
|------|--------|
| `file_classifier.py` | **New** — Magika wrapper with VAPT-oriented API |
| `hunt.py` | Enhance `_looks_textual_content_type()`, add exposed executable detection |
| `autopilot_api_hunt.py` | Add Phase 6b upload bypass testing |
| `payloads.py` | Add `generate_upload_payloads()` with 7 evasion techniques |
| `brain_scanner.py` | Include upload findings in LLM briefing |
| `reporter.py` | Add `file_type_info` rendering + upload test matrix table |
| `requirements.txt` | Add `magika>=0.5.0` |

## Out of Scope

- Classifying every recon artifact through Magika (Approach 3 — deferred)
- New CLI flags or vikramaditya.py orchestrator changes
- Magika model retraining or custom labels

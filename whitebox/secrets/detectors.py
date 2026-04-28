from __future__ import annotations
import math
import re

DETECTORS = {
    "aws_access_key_id":      re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_access_key":  re.compile(r"\b[A-Za-z0-9/+=]{40}\b"),
    "jwt":                    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "rsa_private_key":        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
    "github_pat":             re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "slack_token":            re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe_key":             re.compile(r"\b(sk|pk)_(live|test)_[A-Za-z0-9]{24,}\b"),
    "google_api_key":         re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "generic_password_assignment": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\";]{8,})"),
}

ENTROPY_THRESHOLD = 4.5
ENTROPY_MIN_LEN = 24


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}***{s[-4:]} (len={len(s)})"


def scan_text(text: str, source: str) -> list[dict]:
    hits: list[dict] = []
    seen_offsets: set[int] = set()
    for name, regex in DETECTORS.items():
        for m in regex.finditer(text):
            offset = m.start()
            if offset in seen_offsets:
                continue
            seen_offsets.add(offset)
            value = m.group(0)
            hits.append({
                "detector": name, "source": source, "offset": offset,
                "preview": _redact(value),
                "value": value,  # caller writes only to mode-0600 evidence
            })
    # Entropy pass: only on tokens >= ENTROPY_MIN_LEN that look like values
    for m in re.finditer(r"[A-Za-z0-9/+_=-]{%d,}" % ENTROPY_MIN_LEN, text):
        if m.start() in seen_offsets:
            continue
        token = m.group(0)
        if _entropy(token) >= ENTROPY_THRESHOLD:
            hits.append({
                "detector": "high_entropy", "source": source, "offset": m.start(),
                "preview": _redact(token), "value": token,
            })
    return hits

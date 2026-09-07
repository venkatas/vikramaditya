#!/usr/bin/env python3
from __future__ import annotations

"""Deterministic source-code audit for high-impact VAPT leads.

This module is intentionally conservative: it redacts secret values and emits
findings only for source-backed security issues that map to the normal report
folders.
"""

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".vs",
    "__pycache__",
    "bin",
    "build",
    "dist",
    "node_modules",
    "obj",
    "packages",
    "target",
    "vendor",
    "wwwroot/lib",
}

SOURCE_SUFFIXES = {
    ".asax",
    ".aspx",
    ".config",
    ".cs",
    ".env",
    ".ini",
    ".json",
    ".php",
    ".properties",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".vb",
    ".xml",
    ".yaml",
    ".yml",
}

PLACEHOLDER_RE = re.compile(
    r"(?i)\b("
    r"change-?me|changeme|example|placeholder|dummy|sample|"
    r"set-in-user-secrets|set-in-environment|your[-_]|localhost|"
    r"integrated security\s*=\s*true|trusted_connection\s*=\s*true|"
    r"your-sql-server|sqlserver\.example\.com"
    r")\b"
)

SECRET_LINE_RE = re.compile(
    r"(?i)("
    r"connectionString\s*=.*(?:password|pwd)\s*=|"
    r"\b(?:password|passwd|pwd|clientsecret|client_secret|api[_-]?key|"
    r"access[_-]?key|secret[_-]?access[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]{6,}|"
    r"<add\s+key\s*=\s*['\"][^'\"]*(?:password|secret|token|accesskey|apikey)[^'\"]*['\"]"
    r"\s+value\s*=\s*['\"][^'\"]{4,}|"
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
    r")"
)

SAFE_FILE_BYTES = 2_000_000


@dataclass(frozen=True)
class SourceFinding:
    vtype: str
    severity: str
    rule_id: str
    path: str
    line: int
    title: str
    evidence: str
    impact: str
    remediation: str
    confidence: str = "source"

    def to_report_line(self, root: Path) -> str:
        rel = _relpath(self.path, root)
        return (
            f"[{self.severity.upper()}] [SOURCE-AUDIT] {self.rule_id}: {self.title} "
            f"| file={rel}:{self.line} | evidence={self.evidence} "
            f"| impact={self.impact} | remediation={self.remediation}"
        )


def _relpath(path: str, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def _iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_parts = Path(dirpath).relative_to(root).parts if Path(dirpath) != root else ()
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and "/".join(rel_parts + (d,)) not in SKIP_DIRS
        ]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in SOURCE_SUFFIXES or name.lower() in {"web.config", "appsettings.json"}:
                try:
                    if path.stat().st_size <= SAFE_FILE_BYTES:
                        files.append(path)
                except OSError:
                    continue
    return sorted(files)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ""


def redact_secret(line: str) -> str:
    """Return a short redacted evidence line safe for reports and chat."""
    redacted = line.strip()
    substitutions = [
        (r"(?i)(Password\s*=\s*)[^;\"'\s]+", r"\1<redacted>"),
        (r"(?i)(Pwd\s*=\s*)[^;\"'\s]+", r"\1<redacted>"),
        (r"(?i)(User\s+ID\s*=\s*)[^;\"']+", r"\1<redacted>"),
        (r"(?i)(UID\s*=\s*)[^;\"']+", r"\1<redacted>"),
        (r"(?i)(\"(?:Password|ClientSecret|Client_Secret|ApiKey|AccessKey|Token)\"\s*:\s*\")[^\"]+(\")", r"\1<redacted>\2"),
        (r"(?i)(key\s*=\s*\"[^\"]*(?:Password|Secret|Token|AccessKey|ApiKey)[^\"]*\"\s+value\s*=\s*\")[^\"]+(\")", r"\1<redacted>\2"),
        (r"(?i)(value\s*=\s*\")[^\"]*(AKIA|ASIA)[0-9A-Z]{16}[^\"]*(\")", r"\1<redacted>\3"),
        (r"(AKIA|ASIA)[0-9A-Z]{12}([0-9A-Z]{4})", r"\1************\2"),
    ]
    for pattern, repl in substitutions:
        redacted = re.sub(pattern, repl, redacted)
    return redacted[:500]


def _looks_placeholder(line: str) -> bool:
    value_match = re.search(
        r"(?i)\b(?:password|passwd|pwd|clientsecret|client_secret|api[_-]?key|"
        r"access[_-]?key|secret[_-]?access[_-]?key|token)\b\s*[:=]\s*['\"]([^'\"]+)['\"]",
        line,
    )
    if value_match:
        value = value_match.group(1).strip().lower()
        if value in {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "apikey",
            "api_key",
            "clientsecret",
            "client_secret",
        } or value.startswith(("your_", "your-", "set-in-", "set_in_")):
            return True
    return bool(PLACEHOLDER_RE.search(line))


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")


def _line_no(lines: list[str], needle: str, *, include_comments: bool = False) -> int:
    for idx, line in enumerate(lines, start=1):
        if not include_comments and _is_comment_line(line):
            continue
        if needle in line:
            return idx
    return 1


def _add_once(findings: list[SourceFinding], seen: set[tuple[str, str, int]], finding: SourceFinding) -> None:
    key = (finding.rule_id, finding.path, finding.line)
    if key not in seen:
        findings.append(finding)
        seen.add(key)


def _detect_hardcoded_secrets(path: Path, lines: list[str], findings: list[SourceFinding], seen: set[tuple[str, str, int]]) -> None:
    for idx, line in enumerate(lines, start=1):
        if not SECRET_LINE_RE.search(line):
            continue
        if _looks_placeholder(line):
            continue
        evidence = redact_secret(line)
        _add_once(findings, seen, SourceFinding(
            vtype="exposure",
            severity="high",
            rule_id="source.hardcoded_secret",
            path=str(path),
            line=idx,
            title="Hardcoded credential material is present in source/config",
            evidence=evidence,
            impact="A repo, backup, or web.config exposure can disclose database, mail, or cloud credentials.",
            remediation="Move secrets to a vault or environment variables, rotate exposed values, and block secret commits in CI.",
        ))


def _uses_weak_base64_link(text: str) -> bool:
    has_base64_decode = "Convert.FromBase64String" in text
    has_query_input = "Request.QueryString" in text or "QueryLong(http" in text or "QueryDecoded(http" in text
    has_real_crypto = re.search(r"\b(HMAC|MachineKey|Protect|Unprotect|IDataProtector|Aes|Rijndael|SHA256|Sign)\b", text)
    return has_base64_decode and has_query_input and not has_real_crypto


def _detect_weak_link_tokens(path: Path, text: str, lines: list[str], findings: list[SourceFinding], seen: set[tuple[str, str, int]]) -> None:
    if not _uses_weak_base64_link(text):
        return
    lower = text.lower()
    sensitive_flow = any(token in lower for token in (
        "saveas",
        "transmitfile",
        "binarywrite",
        "generate",
        "requeststatus",
        "client_approval_update",
        "update",
        "deleted",
        "delete",
    ))
    if not sensitive_flow:
        return
    line = _line_no(lines, "Convert.FromBase64String")
    _add_once(findings, seen, SourceFinding(
        vtype="auth_bypass",
        severity="high",
        rule_id="source.base64_link_authorization",
        path=str(path),
        line=line,
        title="Sensitive workflow trusts Base64 query parameters without a signed token",
        evidence=redact_secret(lines[line - 1] if lines else "Convert.FromBase64String(...)"),
        impact="An attacker who obtains or guesses object IDs can tamper link parameters and reach data or state-changing flows without a server-side MAC.",
        remediation="Use a short-lived random server-side token or HMAC-signed payload and enforce authorization on the target record.",
    ))


def _has_auth_gate(text: str) -> bool:
    auth_patterns = (
        r"Session\s*\[\s*\"UserID\"\s*\]\s*!=\s*null",
        r"User\.Identity\.IsAuthenticated",
        r"\[Authorize",
        r"RequireAuthorization",
        r"Response\.Redirect\s*\(\s*\"Login",
    )
    return any(re.search(pattern, text, re.I) for pattern in auth_patterns)


def _detect_unauth_download_or_report(path: Path, text: str, lines: list[str], findings: list[SourceFinding], seen: set[tuple[str, str, int]]) -> None:
    if _has_auth_gate(text):
        return
    if "Request.QueryString" not in text:
        return
    leak_sink = re.search(r"\b(Response\.(?:BinaryWrite|TransmitFile|Write)|ReportViewer|ExecuteDataSet|GetMediaListList)\b", text)
    if not leak_sink:
        return
    line = _line_no(lines, leak_sink.group(0).split(".")[0])
    _add_once(findings, seen, SourceFinding(
        vtype="idor",
        severity="high",
        rule_id="source.unauthenticated_object_download",
        path=str(path),
        line=line,
        title="Unauthenticated query-driven report or file download path",
        evidence=redact_secret(lines[line - 1] if lines else leak_sink.group(0)),
        impact="A caller can request object-specific reports or files without an authenticated session check, creating a data-exposure or IDOR path.",
        remediation="Require authentication and verify the caller is allowed to access the requested object before rendering or transmitting data.",
    ))


def _extension_only_upload(text: str) -> bool:
    has_upload_sink = any(token in text for token in ("SaveAs(", "CopyToAsync(", "File.Create(", "Request.Files", "IFormFile"))
    has_extension_gate = "Path.GetExtension" in text or "FileExtension" in text or "AllowedFileExtensions" in text
    has_content_validation = re.search(r"\b(Magic|FileSignature|SequenceEqual|FileType|Magika|DetectContentType|ImageSharp|GetMimeMapping)\b", text)
    return has_upload_sink and has_extension_gate and not has_content_validation


def _detect_unsafe_upload(path: Path, text: str, lines: list[str], findings: list[SourceFinding], seen: set[tuple[str, str, int]], webroot_upload_path: bool) -> None:
    if not _extension_only_upload(text):
        return
    line = 1
    for needle in ("SaveAs(", "CopyToAsync(", "File.Create("):
        if needle in text:
            line = _line_no(lines, needle)
            break
    storage_note = " The configured upload path appears to sit below the web application tree." if webroot_upload_path else ""
    _add_once(findings, seen, SourceFinding(
        vtype="upload",
        severity="high",
        rule_id="source.extension_only_upload",
        path=str(path),
        line=line,
        title="File upload validation relies on extension allowlists only",
        evidence=redact_secret(lines[line - 1] if lines else "upload sink"),
        impact="An attacker can submit malicious content with an allowed extension; if served or parsed later this can become data exposure, stored XSS, parser abuse, or code execution depending on deployment.",
        remediation="Validate file signatures and parsed content, enforce size limits, re-encode where possible, and serve uploads from non-executable storage with attachment disposition.",
    ))
    if webroot_upload_path:
        _add_once(findings, seen, SourceFinding(
            vtype="exposure",
            severity="high",
            rule_id="source.uploads_under_webroot",
            path=str(path),
            line=line,
            title="Uploaded files are stored under a web application path",
            evidence=redact_secret(lines[line - 1] if lines else "upload sink") + storage_note,
            impact="Uploaded client files may become reachable by URL or executable by the web server if handler mappings change.",
            remediation="Store uploads outside the webroot or in object storage that cannot execute server-side code.",
        ))


def _detect_webroot_upload_config(snapshots: dict[Path, list[str]]) -> bool:
    for lines in snapshots.values():
        for line in lines:
            if "AttachmentPath" not in line and "UploadPath" not in line:
                continue
            if re.search(r"(?i)(wwwroot|\\Web\\|/Web/|\.Web\\|Documents\\|/Documents/)", line):
                return True
    return False


def scan_source_tree(source_dir: str | os.PathLike[str]) -> list[SourceFinding]:
    root = Path(source_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"source directory not found: {source_dir}")

    snapshots: dict[Path, list[str]] = {}
    for path in _iter_source_files(root):
        text = _read_text(path)
        if text:
            snapshots[path] = text.splitlines()

    findings: list[SourceFinding] = []
    seen: set[tuple[str, str, int]] = set()
    webroot_upload_path = _detect_webroot_upload_config(snapshots)

    for path, lines in snapshots.items():
        text = "\n".join(lines)
        active_text = "\n".join(line for line in lines if not _is_comment_line(line))
        _detect_hardcoded_secrets(path, lines, findings, seen)
        if path.suffix.lower() in {".cs", ".asax"}:
            _detect_weak_link_tokens(path, active_text, lines, findings, seen)
            _detect_unauth_download_or_report(path, active_text, lines, findings, seen)
            _detect_unsafe_upload(path, active_text, lines, findings, seen, webroot_upload_path)

    return sorted(findings, key=lambda f: (f.vtype, f.path, f.line, f.rule_id))


def write_findings(findings: list[SourceFinding], findings_dir: str | os.PathLike[str], source_dir: str | os.PathLike[str]) -> dict[str, int]:
    root = Path(source_dir)
    base = Path(findings_dir)
    base.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    by_vtype: dict[str, list[SourceFinding]] = {}
    for finding in findings:
        by_vtype.setdefault(finding.vtype, []).append(finding)

    for vtype, items in by_vtype.items():
        out_dir = base / vtype
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "source_audit.txt"
        out_file.write_text("\n".join(item.to_report_line(root) for item in items) + "\n", encoding="utf-8")
        counts[vtype] = len(items)

    review_dir = base / "manual_review"
    review_dir.mkdir(parents=True, exist_ok=True)
    (review_dir / "source_audit.json").write_text(
        json.dumps([asdict(item) for item in findings], indent=2),
        encoding="utf-8",
    )
    (review_dir / "source_audit_summary.txt").write_text(
        "\n".join(f"{key}: {counts[key]}" for key in sorted(counts)) + ("\n" if counts else "no source findings\n"),
        encoding="utf-8",
    )
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic high-impact source audit")
    parser.add_argument("source_dir", help="Source directory to audit")
    parser.add_argument("--findings-dir", default="", help="Existing findings directory to write into")
    parser.add_argument("--json", action="store_true", help="Print JSON findings")
    args = parser.parse_args()

    findings = scan_source_tree(args.source_dir)
    if args.findings_dir:
        write_findings(findings, args.findings_dir, args.source_dir)
    if args.json:
        print(json.dumps([asdict(item) for item in findings], indent=2))
    else:
        for finding in findings:
            print(finding.to_report_line(Path(args.source_dir)))
    return 0 if findings else 1


if __name__ == "__main__":
    raise SystemExit(main())

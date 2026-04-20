#!/usr/bin/env python3
"""
Email authentication and mail security posture auditor.

Ported in Vikramaditya v7.2.0 from MIT-licensed upstream
https://github.com/venkatas/subspace-sentinel (commit state at
2026-03-27). Upstream license preserved. Original one-file design
retained; v7.3.0 will refactor into an ``email_audit/`` package
that shares Vikramaditya's LLM dispatcher (brain.py) and finding
schema (memory/schemas.py).

Checks:
- SPF
- DMARC
- DKIM (common selectors or user-provided selectors)
- MX hygiene
- DNSSEC
- MTA-STS
- SMTP TLS reporting (TLS-RPT)
- BIMI
- Optional live SMTP STARTTLS probing
- Optional AI-assisted analysis via `.env`-backed Ollama, Claude, OpenAI, xAI, Gemini, or compatible APIs

Examples:
  python3 email_auth_audit.py example.com
  python3 email_auth_audit.py alice@example.com --selectors selector1,selector2,google
  python3 email_auth_audit.py example.com --smtp-probe --json
  python3 email_auth_audit.py --message-file sample.eml
  python3 email_auth_audit.py --targets-file domains.txt --json
  python3 email_auth_audit.py example.com --ai-provider ollama --ai-model qwen3-coder-64k:latest
  python3 email_auth_audit.py example.com --env-file .env
  python3 email_auth_audit.py example.com --ai-provider claude --ai-model your-claude-model --env-file .env
"""

import argparse
import base64
import email
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Tuple


try:
    import dns.resolver  # type: ignore
    import dns.exception  # type: ignore
except ImportError:
    dns = None  # type: ignore


DEFAULT_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "k2",
    "dkim",
    "mail",
    "smtp",
    "api",
    "mg",
    "mandrill",
    "amazonses",
    "m1",
    "m2",
]

FALLBACK_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]

PROVIDER_DKIM_HINTS = {
    "Google Workspace": ["google"],
    "Microsoft 365": ["selector1", "selector2"],
    "Zoho Mail": ["zoho", "zmail", "zm", "selector1", "selector2"],
    "Fastmail": ["fm1", "fm2", "mesmtp"],
}

MX_PROVIDER_PATTERNS = {
    "Google Workspace": ["google.com", "googlemail.com", "l.google.com"],
    "Microsoft 365": ["protection.outlook.com", "outlook.com", "office365.com"],
    "Proofpoint": ["pphosted.com", "proofpoint.com"],
    "Mimecast": ["mimecast.com"],
    "Zoho Mail": ["zoho.com"],
    "Fastmail": ["messagingengine.com"],
    "Yahoo": ["yahoodns.net", "yahoodns.com"],
    "Cisco Secure Email": ["iphmx.com"],
}

DNS_HOST_HINT_PATTERNS = {
    "GoDaddy": ["domaincontrol.com", "jomax.net"],
    "Cloudflare": ["cloudflare.com"],
    "Amazon Route 53": ["awsdns", "route53"],
    "Squarespace": ["squarespacedns.com"],
    "Namecheap": ["registrar-servers.com"],
    "Bluehost": ["bluehost.com"],
    "DigitalOcean": ["digitalocean.com"],
}

AI_PROVIDER_ALIASES = {
    "anthropic": "claude",
    "grok": "xai",
    "x": "xai",
}

AI_PROVIDER_MODEL_ENVS = {
    "ollama": "OLLAMA_MODEL",
    "claude": "ANTHROPIC_MODEL",
    "openai": "OPENAI_MODEL",
    "xai": "XAI_MODEL",
    "gemini": "GEMINI_MODEL",
    "openai-compatible": "OPENAI_COMPATIBLE_MODEL",
}

AI_PROVIDER_ENDPOINT_ENVS = {
    "ollama": "OLLAMA_HOST",
    "claude": "ANTHROPIC_BASE_URL",
    "openai": "OPENAI_BASE_URL",
    "xai": "XAI_BASE_URL",
    "gemini": "GEMINI_BASE_URL",
    "openai-compatible": "OPENAI_COMPATIBLE_BASE_URL",
}

AI_PROVIDER_API_KEY_ENVS = {
    "claude": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "xai": "XAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openai-compatible": "OPENAI_COMPATIBLE_API_KEY",
}

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

STATUS_ORDER = {
    "fail": 3,
    "warn": 2,
    "info": 1,
    "pass": 0,
}

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

HTTP_SSL_CTX = ssl.create_default_context()
try:
    import certifi  # type: ignore

    HTTP_SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    pass


@dataclass
class Issue:
    severity: str
    area: str
    title: str
    detail: str
    recommendation: str = ""
    evidence: Any = None


def make_issue(
    severity: str,
    area: str,
    title: str,
    detail: str,
    recommendation: str = "",
    evidence: Any = None,
) -> Issue:
    return Issue(
        severity=severity,
        area=area,
        title=title,
        detail=detail,
        recommendation=recommendation,
        evidence=evidence,
    )


class DNSClient:
    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout
        self.backend = self._detect_backend()
        self.resolver = None
        if self.backend == "dnspython":
            self.resolver = dns.resolver.Resolver()  # type: ignore[attr-defined]
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout

    def _detect_backend(self) -> str:
        if dns is not None:
            return "dnspython"
        if shutil.which("dig"):
            return "dig"
        raise RuntimeError("No DNS backend available. Install dnspython or ensure dig is installed.")

    def query(self, name: str, qtype: str) -> List[str]:
        if self.backend == "dnspython":
            return self._query_dnspython(name, qtype)
        return self._query_dig(name, qtype)

    def _query_dnspython(self, name: str, qtype: str) -> List[str]:
        try:
            answers = self.resolver.resolve(name, qtype, raise_on_no_answer=False)
        except Exception:
            return []

        results = []
        for answer in answers:
            text = answer.to_text().strip()
            if qtype.upper() == "TXT":
                text = normalize_txt_chunks(text)
            results.append(text)
        return results

    def _query_dig(self, name: str, qtype: str) -> List[str]:
        attempts = [None] + FALLBACK_DNS_SERVERS
        last_stdout = ""

        for server in attempts:
            cmd = [
                "dig",
                "+short",
                "+time={0}".format(max(1, int(round(self.timeout)))),
                "+tries=1",
            ]
            if server:
                cmd.append("@{0}".format(server))
            cmd.extend([name, qtype.upper()])

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=max(self.timeout + 1.0, 2.0),
                    check=False,
                )
            except Exception:
                continue

            if result.returncode != 0:
                continue

            last_stdout = result.stdout
            break
        else:
            return []

        lines = []
        for raw_line in last_stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if qtype.upper() == "TXT":
                line = normalize_txt_chunks(line)
            lines.append(line)
        return lines


def normalize_txt_chunks(value: str) -> str:
    parts = re.findall(r'"([^"]*)"', value)
    if parts:
        return "".join(parts)
    return value.strip()


def normalize_target(target: str) -> Tuple[str, str, Optional[str]]:
    raw_target = target.strip()
    local_part = None
    target_type = "domain"

    if "@" in raw_target:
        local_part, raw_target = raw_target.rsplit("@", 1)
        target_type = "email"

    raw_target = raw_target.strip().lower()
    raw_target = raw_target.split("://", 1)[-1]
    raw_target = raw_target.split("/", 1)[0]
    raw_target = raw_target.strip("[]").rstrip(".")

    if ":" in raw_target and raw_target.count(":") == 1:
        host_part, port_part = raw_target.rsplit(":", 1)
        if port_part.isdigit():
            raw_target = host_part

    try:
        domain = raw_target.encode("idna").decode("ascii")
    except UnicodeError:
        domain = raw_target

    if not domain or not re.match(r"^[a-z0-9.-]+$", domain):
        raise ValueError("Target must be a domain or email address.")

    return target_type, domain, local_part


def parse_kv_record(record: str) -> Dict[str, str]:
    values = {}
    for chunk in record.split(";"):
        part = chunk.strip()
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        values[key.strip().lower()] = value.strip()
    return values


def load_selectors(args: argparse.Namespace) -> List[str]:
    selectors = list(DEFAULT_DKIM_SELECTORS)

    if args.selector_file:
        try:
            with open(args.selector_file, "r", encoding="utf-8") as handle:
                file_values = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
            selectors.extend(file_values)
        except OSError as exc:
            print("Warning: could not read selector file: {0}".format(exc), file=sys.stderr)

    if args.selectors:
        selectors.extend([item.strip() for item in args.selectors.split(",") if item.strip()])

    deduped = []
    seen = set()
    for selector in selectors:
        lowered = selector.lower()
        if lowered not in seen:
            deduped.append(lowered)
            seen.add(lowered)
    return deduped


def merge_unique_strings(*groups: List[str]) -> List[str]:
    values: List[str] = []
    seen = set()
    for group in groups:
        for item in group:
            lowered = item.lower()
            if lowered in seen:
                continue
            values.append(lowered)
            seen.add(lowered)
    return values


def infer_dkim_selectors(base_selectors: List[str], provider_guess: Optional[str], spf_record: Optional[str]) -> List[str]:
    hints: List[str] = []

    if provider_guess and provider_guess in PROVIDER_DKIM_HINTS:
        hints.extend(PROVIDER_DKIM_HINTS[provider_guess])

    if spf_record:
        lowered_spf = spf_record.lower()
        if "spf.protection.outlook.com" in lowered_spf:
            hints.extend(["selector1", "selector2"])
        if "_spf.google.com" in lowered_spf or "googlemail.com" in lowered_spf:
            hints.extend(["google"])
        if "zohomail" in lowered_spf:
            hints.extend(["zoho", "zmail", "zm"])
        if "secureserver.net" in lowered_spf:
            hints.extend(["default", "s1", "s2"])
        if "amazonses.com" in lowered_spf:
            hints.extend(["amazonses"])

    return merge_unique_strings(hints, base_selectors)


def extract_domain_from_address(value: str) -> Optional[str]:
    _, address = parseaddr(value or "")
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().lower().rstrip(".")
    return domain or None


def normalize_auth_domain(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cleaned = value.strip().lower().rstrip(".").strip("<>")
    if "@" in cleaned:
        address_domain = extract_domain_from_address(cleaned)
        if address_domain:
            return address_domain
    return cleaned or None


def strip_parenthetical_content(value: str) -> str:
    output: List[str] = []
    depth = 0
    for char in value:
        if char == "(":
            depth += 1
            continue
        if char == ")":
            if depth > 0:
                depth -= 1
            continue
        if depth == 0:
            output.append(char)
    return "".join(output)


def relaxed_aligns(domain_a: Optional[str], domain_b: Optional[str]) -> bool:
    if not domain_a or not domain_b:
        return False
    if domain_a == domain_b:
        return True
    return domain_a.endswith("." + domain_b) or domain_b.endswith("." + domain_a)


def parse_authentication_results_header(value: str) -> Dict[str, Any]:
    parsed = {
        "raw": value,
        "direct_raw": strip_parenthetical_content(value),
        "spf": None,
        "spf_domain": None,
        "dkim": None,
        "dkim_domain": None,
        "dmarc": None,
        "dmarc_domain": None,
        "arc": None,
    }
    direct_value = parsed["direct_raw"]

    patterns = [
        ("spf", r"\bspf=(pass|fail|softfail|neutral|temperror|permerror|none)\b"),
        ("dkim", r"\bdkim=(pass|fail|policy|neutral|temperror|permerror|none)\b"),
        ("dmarc", r"\bdmarc=(pass|fail|bestguesspass|temperror|permerror|none)\b"),
        ("arc", r"\barc=(pass|fail|none)\b"),
    ]
    for key, pattern in patterns:
        match = re.search(pattern, direct_value, flags=re.IGNORECASE)
        if match:
            parsed[key] = match.group(1).lower()

    domain_patterns = [
        ("spf_domain", r"\bsmtp\.mailfrom=([^\s;]+)"),
        ("spf_domain", r"\benvelope-from=([^\s;]+)"),
        ("dkim_domain", r"\bheader\.d=([^\s;]+)"),
        ("dkim_identity", r"\bheader\.i=([^\s;]+)"),
        ("dmarc_domain", r"\bheader\.from=([^\s;]+)"),
    ]
    for key, pattern in domain_patterns:
        match = re.search(pattern, direct_value, flags=re.IGNORECASE)
        if not match:
            continue
        extracted = normalize_auth_domain(match.group(1))
        if key == "dkim_identity":
            parsed["dkim_domain"] = extracted.lstrip("@") if extracted else None
            continue
        parsed[key] = extracted

    return parsed


def parse_received_spf_header(value: str) -> Dict[str, Any]:
    parsed = {"raw": value, "result": None, "domain": None}
    match = re.search(r"^(pass|fail|softfail|neutral|temperror|permerror|none)\b", value.strip(), flags=re.IGNORECASE)
    if match:
        parsed["result"] = match.group(1).lower()
    domain_match = re.search(r"\benvelope-from=([^\s;]+)", value, flags=re.IGNORECASE)
    if domain_match:
        parsed["domain"] = normalize_auth_domain(domain_match.group(1))
    return parsed


def parse_arc_authentication_results_header(value: str) -> Dict[str, Any]:
    parsed = {
        "raw": value,
        "instance": None,
        "arc": None,
        "direct_spf": None,
        "direct_spf_domain": None,
        "upstream": {
            "spf": None,
            "spf_domain": None,
            "dkim": None,
            "dkim_domain": None,
            "dmarc": None,
            "dmarc_domain": None,
        },
    }

    instance_match = re.search(r"\bi=(\d+)\b", value, flags=re.IGNORECASE)
    if instance_match:
        try:
            parsed["instance"] = int(instance_match.group(1))
        except ValueError:
            parsed["instance"] = None

    direct_value = strip_parenthetical_content(value)
    arc_match = re.search(r"\barc=(pass|fail|none)\b", direct_value, flags=re.IGNORECASE)
    if arc_match:
        parsed["arc"] = arc_match.group(1).lower()

    direct_spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|temperror|permerror|none)\b", direct_value, flags=re.IGNORECASE)
    if direct_spf_match:
        parsed["direct_spf"] = direct_spf_match.group(1).lower()
    direct_spf_domain_match = re.search(r"\bsmtp\.mailfrom=([^\s;]+)", direct_value, flags=re.IGNORECASE)
    if direct_spf_domain_match:
        parsed["direct_spf_domain"] = normalize_auth_domain(direct_spf_domain_match.group(1))

    upstream_match = re.search(r"\barc=(pass|fail|none)\s*\((.*?)\)", value, flags=re.IGNORECASE | re.DOTALL)
    if upstream_match:
        details = upstream_match.group(2)
        patterns = [
            ("spf", r"\bspf=(pass|fail|softfail|neutral|temperror|permerror|none)\b"),
            ("spf_domain", r"\bspfdomain=([^\s;]+)"),
            ("dkim", r"\bdkim=(pass|fail|policy|neutral|temperror|permerror|none)\b"),
            ("dkim_domain", r"\bdkdomain=([^\s;]+)"),
            ("dmarc", r"\bdmarc=(pass|fail|bestguesspass|temperror|permerror|none)\b"),
            ("dmarc_domain", r"\bfromdomain=([^\s;]+)"),
        ]
        for key, pattern in patterns:
            match = re.search(pattern, details, flags=re.IGNORECASE)
            if not match:
                continue
            value = match.group(1).lower()
            if key.endswith("_domain"):
                value = normalize_auth_domain(value) or value
            parsed["upstream"][key] = value

    return parsed


def read_message_file(path: str) -> email.message.Message:
    with open(path, "rb") as handle:
        content = handle.read()

    if b"\n\n" in content or b"\r\n\r\n" in content:
        return BytesParser(policy=policy.default).parsebytes(content)
    return Parser(policy=policy.default).parsestr(content.decode("utf-8", errors="replace"))


def extract_message_body_preview(message: email.message.Message, max_chars: int = 4000) -> str:
    parts: List[str] = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            content_type = part.get_content_type().lower()
            disposition = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disposition:
                continue
            if content_type not in ("text/plain", "text/html"):
                continue
            try:
                payload = part.get_content()
            except Exception:
                payload = None
            if not payload:
                continue
            if content_type == "text/html":
                payload = re.sub(r"<[^>]+>", " ", str(payload))
            payload = re.sub(r"\s+", " ", str(payload)).strip()
            if payload:
                parts.append(payload)
            if sum(len(item) for item in parts) >= max_chars:
                break
    else:
        try:
            payload = message.get_content()
        except Exception:
            payload = None
        if payload:
            text = re.sub(r"\s+", " ", str(payload)).strip()
            if text:
                parts.append(text)

    preview = "\n".join(parts).strip()
    return preview[:max_chars]


def collect_message_header_snapshot(message: email.message.Message, max_received: int = 5, max_dkim: int = 4) -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {
        "from": message.get_all("From", []),
        "to": message.get_all("To", []),
        "cc": message.get_all("Cc", []),
        "reply_to": message.get_all("Reply-To", []),
        "return_path": message.get_all("Return-Path", []),
        "subject": message.get_all("Subject", []),
        "message_id": message.get_all("Message-ID", []),
        "sender": message.get_all("Sender", []),
        "x_mailer": message.get_all("X-Mailer", []),
        "list_unsubscribe": message.get_all("List-Unsubscribe", []),
        "list_unsubscribe_post": message.get_all("List-Unsubscribe-Post", []),
        "authentication_results": message.get_all("Authentication-Results", []),
        "arc_authentication_results": message.get_all("ARC-Authentication-Results", []),
        "received_spf": message.get_all("Received-SPF", []),
        "dkim_signature": message.get_all("DKIM-Signature", [])[:max_dkim],
        "received": message.get_all("Received", [])[:max_received],
    }
    return {key: value for key, value in snapshot.items() if value}


def extract_urls_from_text(value: str, limit: int = 20) -> List[str]:
    urls = re.findall(r"https?://[^\s<>()\"']+", value or "", flags=re.IGNORECASE)
    deduped: List[str] = []
    seen = set()
    for item in urls:
        if item in seen:
            continue
        deduped.append(item)
        seen.add(item)
        if len(deduped) >= limit:
            break
    return deduped


def issue_from_result(result: Optional[str], good_values: Tuple[str, ...], area: str, title: str, detail: str, recommendation: str) -> Optional[Issue]:
    if result is None or result in good_values:
        return None

    severity = "medium" if result in ("fail", "permerror") else "low"
    return make_issue(severity, area, title, detail, recommendation)


def build_message_analysis_report(message_path: str) -> Dict[str, Any]:
    message = read_message_file(message_path)
    body_preview = extract_message_body_preview(message)
    header_snapshot = collect_message_header_snapshot(message)
    urls = extract_urls_from_text(body_preview)

    headers = {
        "from": message.get("From", ""),
        "return_path": message.get("Return-Path", ""),
        "subject": message.get("Subject", ""),
        "to": message.get("To", ""),
        "date": message.get("Date", ""),
        "message_id": message.get("Message-ID", ""),
    }
    from_domain = extract_domain_from_address(headers["from"])
    return_path_domain = extract_domain_from_address(headers["return_path"])

    auth_results = [parse_authentication_results_header(value) for value in message.get_all("Authentication-Results", [])]
    arc_auth_results = [parse_arc_authentication_results_header(value) for value in message.get_all("ARC-Authentication-Results", [])]
    received_spf = [parse_received_spf_header(value) for value in message.get_all("Received-SPF", [])]
    dkim_signature_domains = []
    for value in message.get_all("DKIM-Signature", []):
        match = re.search(r"\bd=([^\s;]+)", value, flags=re.IGNORECASE)
        if match:
            dkim_signature_domains.append(match.group(1).strip().lower().rstrip("."))

    combined = {
        "spf": next((item.get("spf") for item in auth_results if item.get("spf")), None),
        "spf_domain": next((item.get("spf_domain") for item in auth_results if item.get("spf_domain")), None),
        "dkim": next((item.get("dkim") for item in auth_results if item.get("dkim")), None),
        "dkim_domain": next((item.get("dkim_domain") for item in auth_results if item.get("dkim_domain")), None),
        "dmarc": next((item.get("dmarc") for item in auth_results if item.get("dmarc")), None),
        "dmarc_domain": next((item.get("dmarc_domain") for item in auth_results if item.get("dmarc_domain")), None),
        "arc": next((item.get("arc") for item in auth_results if item.get("arc")), None),
        "received_spf": next((item.get("result") for item in received_spf if item.get("result")), None),
    }

    if not combined["dkim_domain"] and dkim_signature_domains:
        combined["dkim_domain"] = dkim_signature_domains[0]

    arc_summary = {
        "arc": next((item.get("arc") for item in arc_auth_results if item.get("arc")), None),
        "upstream_spf": next((item["upstream"].get("spf") for item in arc_auth_results if item["upstream"].get("spf")), None),
        "upstream_spf_domain": next((item["upstream"].get("spf_domain") for item in arc_auth_results if item["upstream"].get("spf_domain")), None),
        "upstream_dkim": next((item["upstream"].get("dkim") for item in arc_auth_results if item["upstream"].get("dkim")), None),
        "upstream_dkim_domain": next((item["upstream"].get("dkim_domain") for item in arc_auth_results if item["upstream"].get("dkim_domain")), None),
        "upstream_dmarc": next((item["upstream"].get("dmarc") for item in arc_auth_results if item["upstream"].get("dmarc")), None),
        "upstream_dmarc_domain": next((item["upstream"].get("dmarc_domain") for item in arc_auth_results if item["upstream"].get("dmarc_domain")), None),
        "direct_spf": next((item.get("direct_spf") for item in arc_auth_results if item.get("direct_spf")), None),
        "direct_spf_domain": next((item.get("direct_spf_domain") for item in arc_auth_results if item.get("direct_spf_domain")), None),
    }

    effective = {
        "spf": combined["spf"] or combined["received_spf"] or arc_summary["direct_spf"] or arc_summary["upstream_spf"],
        "spf_domain": combined["spf_domain"] or arc_summary["direct_spf_domain"] or arc_summary["upstream_spf_domain"] or return_path_domain,
        "dkim": combined["dkim"],
        "dkim_domain": combined["dkim_domain"],
        "dmarc": combined["dmarc"],
        "dmarc_domain": combined["dmarc_domain"] or from_domain,
        "arc": combined["arc"] or arc_summary["arc"],
        "sources": {
            "spf": "direct" if (combined["spf"] or combined["received_spf"]) else ("arc" if (arc_summary["direct_spf"] or arc_summary["upstream_spf"]) else "none"),
            "dkim": "direct" if combined["dkim"] else "none",
            "dmarc": "direct" if combined["dmarc"] else "none",
        },
    }

    if effective["spf"] == "pass" and effective["spf_domain"]:
        effective["spf_domain"] = normalize_auth_domain(effective["spf_domain"])

    if (effective["dkim"] in (None, "none")) and arc_summary["arc"] == "pass" and arc_summary["upstream_dkim"] == "pass":
        effective["dkim"] = "pass"
        effective["dkim_domain"] = arc_summary["upstream_dkim_domain"]
        effective["sources"]["dkim"] = "arc"

    if (effective["dmarc"] in (None, "none")) and arc_summary["arc"] == "pass" and arc_summary["upstream_dmarc"] == "pass":
        effective["dmarc"] = "pass"
        effective["dmarc_domain"] = arc_summary["upstream_dmarc_domain"] or from_domain
        effective["sources"]["dmarc"] = "arc"

    alignment = {
        "spf_relaxed": relaxed_aligns(from_domain, effective["spf_domain"] or return_path_domain),
        "dkim_relaxed": relaxed_aligns(from_domain, effective["dkim_domain"]),
    }

    issues: List[Issue] = []
    if not auth_results:
        issues.append(
            make_issue(
                "low",
                "Headers",
                "No Authentication-Results header present",
                "The supplied message does not contain Authentication-Results, so downstream auth decisions cannot be verified from headers alone.",
                "Capture the full delivered message including Authentication-Results if you want deterministic message-path analysis.",
            )
        )

    spf_result = effective["spf"]
    if spf_result == "permerror" and arc_summary["arc"] == "pass" and arc_summary["upstream_spf"] == "pass":
        maybe_issue = make_issue(
            "low",
            "SPF",
            "Direct SPF evaluation hit permerror, but ARC preserved an upstream SPF pass",
            "The receiving hop reported SPF permerror, while the trusted ARC chain records an upstream SPF pass for {0}.".format(arc_summary["upstream_spf_domain"] or from_domain or "the sender"),
            "Review SPF include depth and recursion so direct SPF checks do not exceed receiver lookup limits.",
        )
    else:
        maybe_issue = issue_from_result(
            spf_result,
            ("pass",),
            "SPF",
            "SPF did not pass for this message",
            "The supplied message headers indicate SPF result: {0}.".format((spf_result or "unknown").upper()),
            "Verify the envelope sender and authorized sending IPs for the path that produced this message.",
        )
    if maybe_issue:
        issues.append(maybe_issue)

    maybe_issue = issue_from_result(
        effective["dkim"],
        ("pass",),
        "DKIM",
        "DKIM did not pass for this message",
        "The supplied message headers indicate DKIM result: {0}.".format((effective["dkim"] or "unknown").upper()),
        "Verify the signer domain, selector, and canonicalization for the sending service that produced this message.",
    )
    if maybe_issue:
        issues.append(maybe_issue)

    maybe_issue = issue_from_result(
        effective["dmarc"],
        ("pass",),
        "DMARC",
        "DMARC did not pass for this message",
        "The supplied message headers indicate DMARC result: {0}.".format((effective["dmarc"] or "unknown").upper()),
        "Check both SPF and DKIM alignment against the visible From domain for this message.",
    )
    if maybe_issue:
        issues.append(maybe_issue)

    if effective["dkim"] == "pass" and not alignment["dkim_relaxed"]:
        issues.append(
            make_issue(
                "low",
                "DKIM",
                "DKIM passed but does not appear aligned to the visible From domain",
                "The DKIM signer domain {0} does not appear relaxed-aligned with From domain {1}.".format(effective["dkim_domain"], from_domain),
                "If DMARC should rely on DKIM alignment, verify the signer domain or use a properly aligned signing identity.",
            )
        )

    if effective["spf"] == "pass" and not alignment["spf_relaxed"]:
        issues.append(
            make_issue(
                "low",
                "SPF",
                "SPF passed but does not appear aligned to the visible From domain",
                "The envelope sender domain {0} does not appear relaxed-aligned with From domain {1}.".format(effective["spf_domain"] or return_path_domain, from_domain),
                "If DMARC should rely on SPF alignment, verify the envelope sender or return-path configuration.",
            )
        )

    if not dkim_signature_domains and not (arc_summary["arc"] == "pass" and arc_summary["upstream_dkim"] == "pass"):
        issues.append(
            make_issue(
                "info",
                "DKIM",
                "No DKIM-Signature header present",
                "The supplied message does not include a DKIM-Signature header.",
                "If the message should be DKIM-signed, capture the original delivered message or review the sending service configuration.",
            )
        )

    summary = {
        "mode": "message-analysis",
        "source_file": message_path,
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "auth_results_count": len(auth_results),
        "arc_auth_results_count": len(arc_auth_results),
        "dkim_signature_domains": dkim_signature_domains,
        "url_count": len(urls),
        "overall_risk": calculate_overall_risk(issues),
    }

    return {
        "summary": summary,
        "headers": headers,
        "header_snapshot": header_snapshot,
        "body_preview": body_preview,
        "urls": urls,
        "auth_results": auth_results,
        "arc_auth_results": arc_auth_results,
        "arc_summary": arc_summary,
        "received_spf": received_spf,
        "combined": combined,
        "effective": effective,
        "alignment": alignment,
        "issues": [asdict(issue) for issue in sort_issues(issues)],
        "ai_analysis": None,
        "mode": "message-analysis",
    }


def classify_check_status(issues: List[Issue]) -> str:
    if not issues:
        return "pass"
    if any(issue.severity in ("critical", "high") for issue in issues):
        return "fail"
    if any(issue.severity in ("medium", "low") for issue in issues):
        return "warn"
    return "info"


def issues_to_dicts(issues: List[Issue]) -> List[Dict[str, Any]]:
    return [asdict(issue) for issue in sort_issues(issues)]


def sort_issues(issues: List[Issue]) -> List[Issue]:
    return sorted(
        issues,
        key=lambda issue: (-SEVERITY_RANK.get(issue.severity, -1), issue.area, issue.title),
    )


def summarize_counts(issues: List[Issue]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for issue in issues:
        counts[issue.severity] = counts.get(issue.severity, 0) + 1
    return counts


def detect_provider(mx_hosts: List[str]) -> Optional[str]:
    lowered_hosts = [host.lower().rstrip(".") for host in mx_hosts]
    for provider, suffixes in MX_PROVIDER_PATTERNS.items():
        for host in lowered_hosts:
            if any(host.endswith(suffix) for suffix in suffixes):
                return provider
    return None


def infer_provider_from_domain_hints(
    domain: str,
    dns_client: "DNSClient",
    spf_record: Optional[str],
) -> Optional[str]:
    lowered_spf = (spf_record or "").lower()
    txt_records = [record.lower() for record in dns_client.query(domain, "TXT")]

    if "spf.protection.outlook.com" in lowered_spf or any("onmicrosoft.com" in record for record in txt_records):
        return "Microsoft 365"
    if "_spf.google.com" in lowered_spf:
        return "Google Workspace"
    if "zohomail" in lowered_spf or any("zoho-verification" in record for record in txt_records):
        return "Zoho Mail"
    return None


def infer_dns_host_hint(domain: str, dns_client: "DNSClient") -> Optional[str]:
    records = [record.lower().rstrip(".") for record in dns_client.query(domain, "NS")]
    soa_records = dns_client.query(domain, "SOA")
    for soa_record in soa_records:
        parts = soa_record.lower().split()
        if len(parts) >= 2:
            records.extend([parts[0].rstrip("."), parts[1].rstrip(".")])

    for provider, patterns in DNS_HOST_HINT_PATTERNS.items():
        for record in records:
            if any(pattern in record for pattern in patterns):
                return provider
    return None


def parse_mx_records(raw_records: List[str]) -> List[Dict[str, Any]]:
    parsed = []
    for record in raw_records:
        match = re.match(r"^(\d+)\s+(.+)$", record.strip())
        if not match:
            continue
        parsed.append(
            {
                "priority": int(match.group(1)),
                "host": match.group(2).strip().rstrip("."),
            }
        )
    return sorted(parsed, key=lambda item: (item["priority"], item["host"]))


def parse_mailto_domains(value: str) -> List[str]:
    domains = []
    for item in value.split(","):
        part = item.strip()
        if not part.lower().startswith("mailto:"):
            continue
        address = part.split(":", 1)[1]
        address = address.split("!", 1)[0]
        if "@" not in address:
            continue
        _, domain = address.rsplit("@", 1)
        domains.append(domain.lower())
    return domains


def is_privateish_ip(value: str) -> bool:
    """True if ``value`` is not publicly routable.

    v7.4.2 — carves out the RFC 6052 NAT64 well-known prefix ``64:ff9b::/96``.
    Python's ``is_reserved`` flag marks it True because IANA reserved the
    prefix, but NAT64 addresses are **publicly routable on the IPv6
    internet** — they translate to a real IPv4 address on the way out. A
    previous version of this check flagged every NAT64-hosted MX as a HIGH
    "non-public IP" finding (see gov.in engagement on 2026-04-20, where
    ``mx.mgovcloud.in`` → ``64:ff9b::a994:8e4b`` = public IPv4
    ``169.148.142.75``). The carve-out decodes the embedded IPv4 from the
    low 32 bits and answers based on that address's routability instead.
    """
    try:
        parsed = ip_address(value)
    except ValueError:
        return False

    # RFC 6052 NAT64 well-known prefix — routable despite ``is_reserved``.
    if parsed.version == 6 and int(parsed) >> 32 == 0x0064FF9B_00000000_00000000_00000000 >> 32:
        embedded_v4 = ip_address(int(parsed) & 0xFFFFFFFF)
        return (
            embedded_v4.is_private
            or embedded_v4.is_loopback
            or embedded_v4.is_link_local
            or embedded_v4.is_multicast
            or embedded_v4.is_unspecified
        )

    return (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_unspecified
        or parsed.is_reserved
    )


def describe_network_width(token: str) -> Optional[Issue]:
    if not token.startswith(("ip4:", "ip6:")):
        return None

    value = token.split(":", 1)[1]
    try:
        network = ip_network(value, strict=False)
    except ValueError:
        return make_issue(
            "medium",
            "SPF",
            "Malformed network definition in SPF",
            "The SPF record contains an invalid network: {0}".format(token),
            "Fix the invalid ip4/ip6 mechanism so SPF evaluation does not fail unpredictably.",
        )

    if network.prefixlen == 0:
        return make_issue(
            "critical",
            "SPF",
            "SPF allows every IP address",
            "The SPF mechanism {0} effectively authorizes the entire Internet.".format(token),
            "Remove the /0 network and replace it with explicit sender IP ranges or provider includes.",
        )
    return None


def fetch_spf_record(domain: str, dns_client: DNSClient) -> Tuple[List[str], List[str]]:
    txt_records = dns_client.query(domain, "TXT")
    spf_records = [record for record in txt_records if record.lower().startswith("v=spf1")]
    return txt_records, spf_records


def estimate_spf_lookups(
    domain: str,
    dns_client: DNSClient,
    cache: Optional[Dict[str, Dict[str, Any]]] = None,
    stack: Optional[List[str]] = None,
) -> Dict[str, Any]:
    if cache is None:
        cache = {}
    if stack is None:
        stack = []

    lowered_domain = domain.lower()
    if lowered_domain in cache:
        return cache[lowered_domain]

    if lowered_domain in stack:
        return {
            "lookups": 0,
            "loops": [lowered_domain],
            "missing_domains": [],
            "records": {},
        }

    _, spf_records = fetch_spf_record(lowered_domain, dns_client)
    if len(spf_records) != 1:
        result = {
            "lookups": 0,
            "loops": [],
            "missing_domains": [lowered_domain] if not spf_records else [],
            "records": {},
        }
        cache[lowered_domain] = result
        return result

    record = spf_records[0]
    result = {
        "lookups": 0,
        "loops": [],
        "missing_domains": [],
        "records": {lowered_domain: record},
    }

    next_stack = stack + [lowered_domain]
    tokens = record.split()[1:]
    for token in tokens:
        normalized = token.lstrip("+-~?")

        if normalized.startswith("include:"):
            include_domain = normalized.split(":", 1)[1].strip().lower()
            result["lookups"] += 1
            if "%" in include_domain:
                continue
            child = estimate_spf_lookups(include_domain, dns_client, cache, next_stack)
            result["lookups"] += child["lookups"]
            result["loops"].extend(child["loops"])
            result["missing_domains"].extend(child["missing_domains"])
            result["records"].update(child["records"])
            continue

        if normalized.startswith("redirect="):
            redirect_domain = normalized.split("=", 1)[1].strip().lower()
            result["lookups"] += 1
            if "%" in redirect_domain:
                continue
            child = estimate_spf_lookups(redirect_domain, dns_client, cache, next_stack)
            result["lookups"] += child["lookups"]
            result["loops"].extend(child["loops"])
            result["missing_domains"].extend(child["missing_domains"])
            result["records"].update(child["records"])
            continue

        if normalized in ("a", "mx", "ptr") or normalized.startswith(("a:", "a/", "mx:", "mx/", "ptr:")):
            result["lookups"] += 1
            continue

        if normalized.startswith("exists:"):
            result["lookups"] += 1

    result["loops"] = sorted(set(result["loops"]))
    result["missing_domains"] = sorted(set(result["missing_domains"]))
    cache[lowered_domain] = result
    return result


def audit_spf(domain: str, dns_client: DNSClient, target_type: str) -> Dict[str, Any]:
    issues = []
    txt_records, spf_records = fetch_spf_record(domain, dns_client)

    result = {
        "record": None,
        "records_found": spf_records,
        "txt_records": txt_records,
        "lookup_estimate": 0,
        "all_mechanism": None,
        "status": "info",
        "issues": [],
        "summary": "",
    }

    if not spf_records:
        severity = "high" if target_type == "email" else "medium"
        issues.append(
            make_issue(
                severity,
                "SPF",
                "No SPF record published",
                "The domain does not publish a v=spf1 record, which weakens anti-spoofing and sender authorization.",
                "Publish a single SPF record with explicit sender sources and a hard fail policy when ready.",
            )
        )
        result["status"] = classify_check_status(issues)
        result["issues"] = issues_to_dicts(issues)
        result["summary"] = "No SPF record found"
        return result

    if len(spf_records) > 1:
        issues.append(
            make_issue(
                "high",
                "SPF",
                "Multiple SPF records published",
                "Multiple v=spf1 TXT records were found. SPF treats this as a permanent error.",
                "Consolidate to exactly one SPF record.",
                evidence=spf_records,
            )
        )

    record = spf_records[0]
    result["record"] = record

    tokens = record.split()
    all_mechanism = None
    for token in tokens[1:]:
        normalized = token.lstrip("+-~?")
        if normalized == "all":
            all_mechanism = token[0] if token[0] in "+-~?" else "+"
            break
    result["all_mechanism"] = all_mechanism

    lookup_data = estimate_spf_lookups(domain, dns_client)
    result["lookup_estimate"] = lookup_data["lookups"]

    if lookup_data["lookups"] > 10:
        issues.append(
            make_issue(
                "high",
                "SPF",
                "SPF likely exceeds the 10-DNS-lookup limit",
                "The SPF tree is estimated to require {0} DNS lookups.".format(lookup_data["lookups"]),
                "Reduce includes and redirect chains or flatten the record safely.",
                evidence=lookup_data["records"],
            )
        )

    if lookup_data["loops"]:
        issues.append(
            make_issue(
                "medium",
                "SPF",
                "SPF include or redirect loop detected",
                "A recursive SPF reference loop was detected in: {0}".format(", ".join(lookup_data["loops"])),
                "Break circular include/redirect chains.",
            )
        )

    missing_nested = [item for item in lookup_data["missing_domains"] if item != domain.lower()]
    if missing_nested:
        issues.append(
            make_issue(
                "medium",
                "SPF",
                "Nested SPF include or redirect target missing",
                "One or more included domains did not publish a usable SPF record: {0}".format(", ".join(missing_nested)),
                "Verify provider includes and redirect targets so SPF does not fail with permerror.",
            )
        )

    for token in tokens[1:]:
        issue = describe_network_width(token.lstrip("+-~?"))
        if issue:
            issues.append(issue)

        normalized = token.lstrip("+-~?")
        if normalized == "ptr" or normalized.startswith("ptr:"):
            issues.append(
                make_issue(
                    "low",
                    "SPF",
                    "SPF uses ptr",
                    "The SPF record uses the ptr mechanism, which is discouraged and often slow or fragile.",
                    "Replace ptr with explicit ip4/ip6 ranges or provider includes.",
                )
            )

    if all_mechanism == "+":
        issues.append(
            make_issue(
                "critical",
                "SPF",
                "SPF ends in +all",
                "The SPF record authorizes every sender by ending with +all.",
                "Replace +all with -all after validating your legitimate senders.",
            )
        )
    elif all_mechanism == "~":
        issues.append(
            make_issue(
                "low",
                "SPF",
                "SPF uses softfail (~all)",
                "Softfail is better than no policy, but it still allows weaker enforcement than -all.",
                "Move toward -all once you confirm all legitimate sending sources are covered.",
            )
        )
    elif all_mechanism == "?":
        issues.append(
            make_issue(
                "medium",
                "SPF",
                "SPF uses neutral (?all)",
                "Neutral leaves receivers with little policy guidance and weak anti-spoofing value.",
                "Prefer -all or at least ~all during rollout.",
            )
        )
    elif all_mechanism is None:
        issues.append(
            make_issue(
                "medium",
                "SPF",
                "SPF has no terminal all mechanism",
                "The record does not end in an all mechanism, which can make policy intent ambiguous.",
                "Add an explicit -all or ~all after the final authorized sender mechanism.",
            )
        )

    result["status"] = classify_check_status(issues)
    result["issues"] = issues_to_dicts(issues)
    result["summary"] = "SPF record found; estimated DNS lookups: {0}".format(result["lookup_estimate"])
    return result


def audit_dmarc(domain: str, dns_client: DNSClient, target_type: str) -> Dict[str, Any]:
    issues = []
    dmarc_name = "_dmarc.{0}".format(domain)
    txt_records = dns_client.query(dmarc_name, "TXT")
    dmarc_records = [record for record in txt_records if record.lower().startswith("v=dmarc1")]

    result = {
        "record": None,
        "records_found": dmarc_records,
        "policy": None,
        "pct": None,
        "rua": [],
        "ruf": [],
        "alignment": {},
        "status": "info",
        "issues": [],
        "summary": "",
    }

    if not dmarc_records:
        severity = "high" if target_type == "email" else "medium"
        issues.append(
            make_issue(
                severity,
                "DMARC",
                "No DMARC record published",
                "The domain does not publish a DMARC policy, so receivers have little guidance for spoofed mail.",
                "Publish a DMARC record with rua reporting, then move from p=none to quarantine/reject.",
            )
        )
        result["status"] = classify_check_status(issues)
        result["issues"] = issues_to_dicts(issues)
        result["summary"] = "No DMARC record found"
        return result

    if len(dmarc_records) > 1:
        issues.append(
            make_issue(
                "high",
                "DMARC",
                "Multiple DMARC records published",
                "Multiple v=DMARC1 records were found. DMARC requires exactly one policy record.",
                "Consolidate to a single DMARC record.",
                evidence=dmarc_records,
            )
        )

    record = dmarc_records[0]
    result["record"] = record

    tags = parse_kv_record(record)
    policy = tags.get("p")
    subdomain_policy = tags.get("sp")
    pct_value = tags.get("pct", "100")
    rua = parse_mailto_domains(tags.get("rua", ""))
    ruf = parse_mailto_domains(tags.get("ruf", ""))
    result["policy"] = policy
    result["pct"] = pct_value
    result["rua"] = rua
    result["ruf"] = ruf
    result["alignment"] = {
        "adkim": tags.get("adkim", "r"),
        "aspf": tags.get("aspf", "r"),
    }

    if policy not in ("none", "quarantine", "reject"):
        issues.append(
            make_issue(
                "high",
                "DMARC",
                "DMARC policy is missing or invalid",
                "The DMARC record does not contain a valid p=none|quarantine|reject tag.",
                "Set a valid p= tag and validate the full record syntax.",
                evidence=record,
            )
        )

    if policy == "none":
        issues.append(
            make_issue(
                "high",
                "DMARC",
                "DMARC is monitor-only (p=none)",
                "The domain collects reports but does not tell receivers to quarantine or reject spoofed mail.",
                "Move to quarantine and then reject once legitimate mail sources are aligned.",
            )
        )

    if subdomain_policy == "none":
        issues.append(
            make_issue(
                "medium",
                "DMARC",
                "Subdomain DMARC policy is weak",
                "The DMARC record explicitly sets sp=none, leaving subdomains weakly protected.",
                "Use sp=quarantine or sp=reject if subdomains should also resist spoofing.",
            )
        )

    try:
        pct = int(pct_value)
        if pct < 100 and policy in ("quarantine", "reject"):
            issues.append(
                make_issue(
                    "medium",
                    "DMARC",
                    "DMARC enforcement is partial",
                    "The DMARC record uses pct={0}, so enforcement only applies to part of the mail stream.".format(pct),
                    "Move pct to 100 once rollout is stable.",
                )
            )
    except ValueError:
        issues.append(
            make_issue(
                "medium",
                "DMARC",
                "DMARC pct tag is invalid",
                "The pct value could not be parsed: {0}".format(pct_value),
                "Set pct to an integer from 0 to 100.",
            )
        )

    if not rua and not ruf:
        issues.append(
            make_issue(
                "low",
                "DMARC",
                "DMARC reporting is not configured",
                "The record does not define rua or ruf destinations, reducing visibility during rollout and monitoring.",
                "Add at least rua aggregate reporting mailboxes.",
            )
        )

    if tags.get("adkim", "r") == "r":
        issues.append(
            make_issue(
                "low",
                "DMARC",
                "DKIM alignment is relaxed",
                "DMARC uses adkim=r. Relaxed alignment is common, but strict alignment offers tighter hardening.",
                "Use adkim=s if your mail flow can support strict DKIM alignment.",
            )
        )

    if tags.get("aspf", "r") == "r":
        issues.append(
            make_issue(
                "low",
                "DMARC",
                "SPF alignment is relaxed",
                "DMARC uses aspf=r. Relaxed alignment is common, but strict alignment offers tighter hardening.",
                "Use aspf=s if your sending infrastructure supports strict SPF alignment.",
            )
        )

    external_report_domains = []
    for mailbox_domain in rua + ruf:
        if mailbox_domain == domain.lower():
            continue
        external_report_domains.append(mailbox_domain)
        auth_name = "{0}._report._dmarc.{1}".format(domain, mailbox_domain)
        auth_records = dns_client.query(auth_name, "TXT")
        if not auth_records:
            issues.append(
                make_issue(
                    "medium",
                    "DMARC",
                    "External DMARC reporting target lacks authorization record",
                    "Reports are sent to {0}, but {1} was not found.".format(mailbox_domain, auth_name),
                    "Publish the DMARC external reporting authorization record on the destination domain.",
                )
            )

    result["external_reporting_domains"] = sorted(set(external_report_domains))
    result["status"] = classify_check_status(issues)
    result["issues"] = issues_to_dicts(issues)
    result["summary"] = "DMARC policy: {0}".format(policy or "invalid")
    return result


def _read_der_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of DER input")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    octet_count = first & 0x7F
    if octet_count == 0 or octet_count > 4:
        raise ValueError("Invalid DER length")
    if offset + octet_count > len(data):
        raise ValueError("DER length exceeds input")
    length = int.from_bytes(data[offset:offset + octet_count], "big")
    return length, offset + octet_count


def _read_der_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of DER input")
    tag = data[offset]
    length, value_offset = _read_der_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise ValueError("DER value exceeds input")
    return tag, data[value_offset:end], end


def estimate_dkim_rsa_bits(public_key_b64: str) -> Optional[int]:
    try:
        der = base64.b64decode(public_key_b64 + "==", validate=False)
    except Exception:
        return None

    try:
        tag, value, _ = _read_der_tlv(der, 0)
        if tag != 0x30:
            return None

        child_tag, child_value, next_offset = _read_der_tlv(value, 0)

        if child_tag == 0x02:
            modulus = child_value.lstrip(b"\x00")
            return len(modulus) * 8

        if child_tag == 0x30:
            second_tag, second_value, _ = _read_der_tlv(value, next_offset)
            if second_tag != 0x03 or not second_value:
                return None
            if second_value[0] != 0:
                return None
            return estimate_dkim_rsa_bits(base64.b64encode(second_value[1:]).decode("ascii"))
    except ValueError:
        return None

    return None


def audit_dkim(
    domain: str,
    dns_client: DNSClient,
    selectors: List[str],
    provider_guess: Optional[str] = None,
    spf_record: Optional[str] = None,
) -> Dict[str, Any]:
    issues = []
    found = []
    empty_key_selectors = []
    selectors_to_check = infer_dkim_selectors(selectors, provider_guess, spf_record)

    for selector in selectors_to_check:
        record_name = "{0}._domainkey.{1}".format(selector, domain)
        txt_records = dns_client.query(record_name, "TXT")
        dkim_records = [record for record in txt_records if record.lower().startswith("v=dkim1")]
        if not dkim_records:
            continue

        record = dkim_records[0]
        tags = parse_kv_record(record)
        key_type = tags.get("k", "rsa").lower()
        public_key = tags.get("p", "")
        info = {
            "selector": selector,
            "record_name": record_name,
            "record": record,
            "key_type": key_type,
            "test_mode": "y" in tags.get("t", "").lower().split(":"),
            "public_key_present": bool(public_key),
            "hash_algorithms": tags.get("h", ""),
            "bits": None,
        }

        if not public_key:
            empty_key_selectors.append(info)
        elif key_type == "rsa":
            bits = estimate_dkim_rsa_bits(public_key)
            info["bits"] = bits
            if bits is not None and bits < 1024:
                issues.append(
                    make_issue(
                        "high",
                        "DKIM",
                        "Weak DKIM RSA key detected",
                        "Selector {0} appears to use an RSA key around {1} bits.".format(selector, bits),
                        "Rotate DKIM to at least 2048-bit RSA where supported.",
                        evidence=record_name,
                    )
                )
            elif bits is not None and bits < 2048:
                issues.append(
                    make_issue(
                        "medium",
                        "DKIM",
                        "DKIM RSA key is below modern hardening guidance",
                        "Selector {0} appears to use an RSA key around {1} bits.".format(selector, bits),
                        "Rotate DKIM to 2048-bit RSA where your provider supports it.",
                        evidence=record_name,
                    )
                )
        elif key_type == "ed25519":
            info["bits"] = 256

        if info["test_mode"]:
            issues.append(
                make_issue(
                    "low",
                    "DKIM",
                    "DKIM selector is in test mode",
                    "Selector {0} publishes t=y, which signals testing mode.".format(selector),
                    "Remove test mode on production selectors once validation is complete.",
                    evidence=record_name,
                )
            )

        hash_algorithms = tags.get("h", "")
        if hash_algorithms and "sha256" not in hash_algorithms.lower():
            issues.append(
                make_issue(
                    "low",
                    "DKIM",
                    "DKIM selector does not advertise sha256",
                    "Selector {0} advertises h={1}.".format(selector, hash_algorithms),
                    "Prefer sha256-capable DKIM selectors for modern interoperability and security.",
                    evidence=record_name,
                )
            )

        found.append(info)

    if empty_key_selectors:
        unique_empty_records = {item["record"] for item in empty_key_selectors}
        if len(empty_key_selectors) == len(found) and len(unique_empty_records) == 1:
            issues.append(
                make_issue(
                    "info",
                    "DKIM",
                    "Wildcard or catch-all DKIM revocation record detected",
                    "All discovered selectors returned the same empty p= record, which usually indicates an intentional wildcard DKIM revocation policy rather than many separate selector problems.",
                    "If this is intentional, no action is needed. If not, verify whether _domainkey uses a wildcard TXT record.",
                    evidence={"selectors": [item["selector"] for item in empty_key_selectors]},
                )
            )
        else:
            for info in empty_key_selectors:
                issues.append(
                    make_issue(
                        "low",
                        "DKIM",
                        "DKIM selector is revoked or empty",
                        "Selector {0} publishes an empty p= value.".format(info["selector"]),
                        "Remove stale selectors or publish the current active public key if that selector is still meant to sign mail.",
                        evidence=info["record_name"],
                    )
                )

    if not found:
        detail = "DKIM selectors cannot be enumerated globally. The tool did not find a key in the current selector wordlist."
        recommendation = "If you know the provider or selector names, rerun with --selectors or --selector-file for deeper coverage."
        if provider_guess:
            detail += " Provider hint used: {0}.".format(provider_guess)
        issues.append(
            make_issue(
                "info",
                "DKIM",
                "No DKIM selectors found in the probed selector list",
                detail,
                recommendation,
            )
        )

    result = {
        "selectors_checked": selectors_to_check,
        "selector_wordlist_size": len(selectors_to_check),
        "provider_hint": provider_guess,
        "selectors_found": found,
        "status": classify_check_status(issues),
        "issues": issues_to_dicts(issues),
        "summary": "Found {0} DKIM selector(s) from {1} probes".format(len(found), len(selectors_to_check)),
    }
    return result


def smtp_read_response(file_handle: Any) -> List[str]:
    lines = []
    while True:
        raw_line = file_handle.readline(4096)
        if not raw_line:
            break
        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
        lines.append(line)
        if len(line) < 4 or line[3] != "-":
            break
    return lines


def probe_smtp_starttls(host: str, timeout: float) -> Dict[str, Any]:
    outcome = {
        "host": host,
        "connect_ok": False,
        "starttls": False,
        "banner": [],
        "ehlo": [],
        "tls_version": None,
        "cipher": None,
        "error": None,
    }

    sock = None
    wrapped_sock = None
    try:
        sock = socket.create_connection((host, 25), timeout=timeout)
        sock.settimeout(timeout)
        file_handle = sock.makefile("rb")

        outcome["banner"] = smtp_read_response(file_handle)
        outcome["connect_ok"] = True

        sock.sendall(b"EHLO audit.local\r\n")
        outcome["ehlo"] = smtp_read_response(file_handle)
        outcome["starttls"] = any("STARTTLS" in line.upper() for line in outcome["ehlo"])

        if outcome["starttls"]:
            sock.sendall(b"STARTTLS\r\n")
            starttls_reply = smtp_read_response(file_handle)
            if not starttls_reply or not starttls_reply[0].startswith("220"):
                outcome["error"] = "STARTTLS was advertised but not accepted"
                return outcome

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            wrapped_sock = context.wrap_socket(sock, server_hostname=host)
            outcome["tls_version"] = wrapped_sock.version()
            cipher = wrapped_sock.cipher()
            outcome["cipher"] = cipher[0] if cipher else None
            sock = None
    except Exception as exc:
        outcome["error"] = str(exc)
    finally:
        if wrapped_sock is not None:
            try:
                wrapped_sock.close()
            except OSError:
                pass
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return outcome


def audit_mx(
    domain: str,
    dns_client: DNSClient,
    target_type: str,
    smtp_probe: bool,
    timeout: float,
    provider_hint: Optional[str] = None,
) -> Dict[str, Any]:
    issues = []
    raw_mx = dns_client.query(domain, "MX")
    mx_records = parse_mx_records(raw_mx)
    provider_guess = detect_provider([record["host"] for record in mx_records]) or provider_hint

    result = {
        "mx_records": mx_records,
        "provider_guess": provider_guess,
        "accepts_mail": bool(mx_records),
        "status": "info",
        "issues": [],
        "summary": "",
        "smtp_probe": [],
    }

    if not mx_records:
        a_records = dns_client.query(domain, "A")
        aaaa_records = dns_client.query(domain, "AAAA")
        if a_records or aaaa_records:
            issues.append(
                make_issue(
                    "medium",
                    "MX",
                    "No MX record; mail may fall back to A/AAAA",
                    "The domain has address records but no MX record, so SMTP delivery may fall back to the bare host.",
                    "Publish explicit MX records or a null MX if the domain must not receive mail.",
                )
            )
            result["accepts_mail"] = True
        else:
            severity = "high" if target_type == "email" else "info"
            issues.append(
                make_issue(
                    severity,
                    "MX",
                    "No reachable mail routing found",
                    "The domain does not publish MX or A/AAAA records for mail delivery.",
                    "If the domain should receive mail, publish MX records. Otherwise, publish a null MX and SPF -all.",
                )
            )
        result["status"] = classify_check_status(issues)
        result["issues"] = issues_to_dicts(issues)
        if provider_guess:
            result["summary"] = "No MX records found; likely provider hint: {0}".format(provider_guess)
        else:
            result["summary"] = "No MX records found"
        return result

    if len(mx_records) == 1 and mx_records[0]["host"] == "":
        issues.append(
            make_issue(
                "info",
                "MX",
                "Null MX published",
                "The domain publishes a null MX and explicitly does not accept mail.",
                "If that is intentional, pair it with SPF -all and a strict DMARC policy.",
            )
        )
        result["accepts_mail"] = False

    mx_host_details = []
    for mx_record in mx_records:
        host = mx_record["host"]
        if host == "":
            continue

        cnames = dns_client.query(host, "CNAME")
        ips = dns_client.query(host, "A") + dns_client.query(host, "AAAA")
        detail = {
            "host": host,
            "priority": mx_record["priority"],
            "cname": cnames,
            "ips": ips,
        }

        if cnames:
            issues.append(
                make_issue(
                    "medium",
                    "MX",
                    "MX host is a CNAME",
                    "The MX host {0} resolves via CNAME, which is discouraged and breaks some receivers.".format(host),
                    "Point the MX record at a hostname with direct A/AAAA records.",
                    evidence={"host": host, "cname": cnames},
                )
            )

        if not ips:
            issues.append(
                make_issue(
                    "medium",
                    "MX",
                    "MX host does not resolve to A or AAAA",
                    "The MX host {0} has no address records.".format(host),
                    "Fix DNS for the MX target so it resolves directly to the mail gateway.",
                )
            )

        for value in ips:
            if is_privateish_ip(value):
                issues.append(
                    make_issue(
                        "high",
                        "MX",
                        "MX host resolves to a non-public IP",
                        "The MX host {0} resolves to {1}, which is not globally routable.".format(host, value),
                        "Publish public-facing MX IPs or fix split-horizon DNS leakage.",
                    )
                )

        mx_host_details.append(detail)

    if smtp_probe:
        for mx_record in mx_records[:5]:
            host = mx_record["host"]
            if not host:
                continue
            probe = probe_smtp_starttls(host, timeout)
            result["smtp_probe"].append(probe)
            if probe["connect_ok"] and not probe["starttls"]:
                issues.append(
                    make_issue(
                        "medium",
                        "SMTP",
                        "MX host does not advertise STARTTLS",
                        "The MX host {0} accepted SMTP but did not advertise STARTTLS.".format(host),
                        "Enable STARTTLS if the mail flow and provider support it.",
                    )
                )
            elif probe["tls_version"] in ("TLSv1", "TLSv1.1"):
                issues.append(
                    make_issue(
                        "medium",
                        "SMTP",
                        "MX host negotiated an outdated TLS version",
                        "The MX host {0} negotiated {1} during STARTTLS.".format(host, probe["tls_version"]),
                        "Disable legacy TLS versions and prefer TLS 1.2+ on inbound SMTP.",
                    )
                )

    result["mx_hosts"] = mx_host_details
    result["status"] = classify_check_status(issues)
    result["issues"] = issues_to_dicts(issues)
    result["summary"] = "Found {0} MX record(s)".format(len(mx_records))
    return result


def fetch_url_text(url: str, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "claude-bug-bounty-email-auth-audit/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=HTTP_SSL_CTX) as response:
            body = response.read().decode("utf-8", errors="replace")
            return body, None
    except Exception as exc:
        return None, str(exc)


def parse_mta_sts_policy(text: str) -> Dict[str, Any]:
    policy = {"mx": []}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "mx":
            policy["mx"].append(value)
        else:
            policy[key] = value
    return policy


def audit_mta_sts(domain: str, dns_client: DNSClient, timeout: float, skip_http: bool) -> Dict[str, Any]:
    issues = []
    record_name = "_mta-sts.{0}".format(domain)
    txt_records = dns_client.query(record_name, "TXT")
    sts_records = [record for record in txt_records if record.lower().startswith("v=stsv1")]

    result = {
        "record": None,
        "policy": None,
        "policy_url": "https://mta-sts.{0}/.well-known/mta-sts.txt".format(domain),
        "status": "info",
        "issues": [],
        "summary": "",
        "http_error": None,
    }

    if not sts_records:
        issues.append(
            make_issue(
                "low",
                "MTA-STS",
                "MTA-STS is not deployed",
                "The domain does not publish an _mta-sts TXT record.",
                "If you want stronger SMTP transport hardening, publish MTA-STS and pair it with TLS-RPT.",
            )
        )
        result["status"] = classify_check_status(issues)
        result["issues"] = issues_to_dicts(issues)
        result["summary"] = "No MTA-STS record found"
        return result

    if len(sts_records) > 1:
        issues.append(
            make_issue(
                "medium",
                "MTA-STS",
                "Multiple MTA-STS TXT records published",
                "Multiple v=STSv1 records were found.",
                "Consolidate to a single _mta-sts TXT record.",
            )
        )

    record = sts_records[0]
    result["record"] = record
    tags = parse_kv_record(record)
    if "id" not in tags:
        issues.append(
            make_issue(
                "medium",
                "MTA-STS",
                "MTA-STS TXT record is missing id=",
                "The _mta-sts TXT record does not include an id tag used for policy cache invalidation.",
                "Add id=<version string> to the record.",
            )
        )

    if skip_http:
        result["status"] = classify_check_status(issues)
        result["issues"] = issues_to_dicts(issues)
        result["summary"] = "MTA-STS TXT record found; policy body fetch skipped"
        return result

    policy_body, error = fetch_url_text(result["policy_url"], timeout)
    result["http_error"] = error
    if error:
        issues.append(
            make_issue(
                "medium",
                "MTA-STS",
                "MTA-STS policy body could not be fetched",
                "The TXT record exists but the HTTPS policy body could not be retrieved: {0}".format(error),
                "Serve /.well-known/mta-sts.txt over HTTPS on mta-sts.{0}.".format(domain),
            )
        )
    elif policy_body is not None:
        policy = parse_mta_sts_policy(policy_body)
        result["policy"] = policy
        if policy.get("version") != "STSv1":
            issues.append(
                make_issue(
                    "medium",
                    "MTA-STS",
                    "MTA-STS policy version is invalid",
                    "The fetched policy did not contain version: STSv1.",
                    "Publish a syntactically valid MTA-STS policy body.",
                )
            )
        mode = policy.get("mode")
        if mode not in ("enforce", "testing", "none"):
            issues.append(
                make_issue(
                    "medium",
                    "MTA-STS",
                    "MTA-STS mode is invalid",
                    "The fetched policy did not contain a valid mode setting.",
                    "Use mode: enforce, testing, or none.",
                )
            )
        elif mode in ("testing", "none"):
            issues.append(
                make_issue(
                    "low",
                    "MTA-STS",
                    "MTA-STS is not enforcing",
                    "The fetched policy uses mode: {0}.".format(mode),
                    "Move to mode: enforce if the mail flow is ready.",
                )
            )

        if not policy.get("mx"):
            issues.append(
                make_issue(
                    "medium",
                    "MTA-STS",
                    "MTA-STS policy has no mx patterns",
                    "The fetched policy body does not define any mx: lines.",
                    "Add allowed MX patterns to the policy.",
                )
            )

        try:
            max_age = int(policy.get("max_age", ""))
            if max_age < 86400:
                issues.append(
                    make_issue(
                        "low",
                        "MTA-STS",
                        "MTA-STS max_age is very short",
                        "The policy uses max_age={0} seconds.".format(max_age),
                        "Use a longer cache window once the policy is stable.",
                    )
                )
        except ValueError:
            issues.append(
                make_issue(
                    "medium",
                    "MTA-STS",
                    "MTA-STS max_age is invalid",
                    "The policy did not contain a valid integer max_age.",
                    "Set max_age to an integer number of seconds.",
                )
            )

    result["status"] = classify_check_status(issues)
    result["issues"] = issues_to_dicts(issues)
    result["summary"] = "MTA-STS TXT record found"
    return result


def audit_tls_rpt(domain: str, dns_client: DNSClient) -> Dict[str, Any]:
    issues = []
    record_name = "_smtp._tls.{0}".format(domain)
    txt_records = dns_client.query(record_name, "TXT")
    rpt_records = [record for record in txt_records if record.lower().startswith("v=tlsrptv1")]

    result = {
        "record": None,
        "rua": [],
        "status": "info",
        "issues": [],
        "summary": "",
    }

    if not rpt_records:
        issues.append(
            make_issue(
                "low",
                "TLS-RPT",
                "SMTP TLS reporting is not configured",
                "The domain does not publish a TLS-RPT record.",
                "Publish _smtp._tls.{0} with rua=mailto:... to monitor TLS delivery failures.".format(domain),
            )
        )
        result["status"] = classify_check_status(issues)
        result["issues"] = issues_to_dicts(issues)
        result["summary"] = "No TLS-RPT record found"
        return result

    if len(rpt_records) > 1:
        issues.append(
            make_issue(
                "medium",
                "TLS-RPT",
                "Multiple TLS-RPT records published",
                "Multiple v=TLSRPTv1 records were found.",
                "Consolidate to a single TLS-RPT record.",
            )
        )

    record = rpt_records[0]
    tags = parse_kv_record(record)
    result["record"] = record
    result["rua"] = parse_mailto_domains(tags.get("rua", ""))

    if not result["rua"]:
        issues.append(
            make_issue(
                "medium",
                "TLS-RPT",
                "TLS-RPT record is missing rua=",
                "The TLS-RPT record exists but does not define report destinations.",
                "Add rua=mailto:... to collect transport security reports.",
            )
        )

    result["status"] = classify_check_status(issues)
    result["issues"] = issues_to_dicts(issues)
    result["summary"] = "TLS-RPT record found"
    return result


def audit_bimi(domain: str, dns_client: DNSClient, dmarc_result: Dict[str, Any]) -> Dict[str, Any]:
    issues = []
    record_name = "default._bimi.{0}".format(domain)
    txt_records = dns_client.query(record_name, "TXT")
    bimi_records = [record for record in txt_records if record.lower().startswith("v=bimi1")]

    result = {
        "record": None,
        "logo": None,
        "assertion": None,
        "status": "info",
        "issues": [],
        "summary": "",
    }

    if not bimi_records:
        issues.append(
            make_issue(
                "info",
                "BIMI",
                "No BIMI record found",
                "The domain does not publish a default._bimi record.",
                "If brand indicators matter to the mail program, deploy BIMI after DMARC is fully enforcing.",
            )
        )
        result["status"] = classify_check_status(issues)
        result["issues"] = issues_to_dicts(issues)
        result["summary"] = "No BIMI record found"
        return result

    if len(bimi_records) > 1:
        issues.append(
            make_issue(
                "medium",
                "BIMI",
                "Multiple BIMI records published",
                "Multiple v=BIMI1 records were found.",
                "Consolidate to a single default._bimi record.",
            )
        )

    record = bimi_records[0]
    result["record"] = record
    tags = parse_kv_record(record)
    result["logo"] = tags.get("l")
    result["assertion"] = tags.get("a")

    dmarc_policy = (dmarc_result.get("policy") or "").lower()
    try:
        dmarc_pct = int(dmarc_result.get("pct") or 100)
    except ValueError:
        dmarc_pct = 0

    if dmarc_policy not in ("quarantine", "reject") or dmarc_pct < 100:
        issues.append(
            make_issue(
                "medium",
                "BIMI",
                "BIMI is published without strong DMARC enforcement",
                "BIMI usually expects DMARC enforcement at quarantine/reject with pct=100, but the current DMARC posture is weaker.",
                "Move DMARC to quarantine/reject with pct=100 before relying on BIMI.",
            )
        )

    if not result["logo"]:
        issues.append(
            make_issue(
                "low",
                "BIMI",
                "BIMI logo location is missing",
                "The BIMI record does not contain l= for the SVG logo.",
                "Publish a valid SVG logo URI in l=.",
            )
        )

    result["status"] = classify_check_status(issues)
    result["issues"] = issues_to_dicts(issues)
    result["summary"] = "BIMI record found"
    return result


def audit_dnssec(domain: str, dns_client: DNSClient) -> Dict[str, Any]:
    issues = []
    ds_records = dns_client.query(domain, "DS")
    dnskey_records = dns_client.query(domain, "DNSKEY")

    result = {
        "ds_records": ds_records,
        "dnskey_records": dnskey_records,
        "status": "info",
        "issues": [],
        "summary": "",
    }

    if not ds_records:
        issues.append(
            make_issue(
                "low",
                "DNSSEC",
                "No DNSSEC DS record found",
                "The domain does not appear to have a DS record published at the parent zone.",
                "Enable DNSSEC if the registrar and DNS provider support it to harden DNS integrity.",
            )
        )
    elif not dnskey_records:
        issues.append(
            make_issue(
                "medium",
                "DNSSEC",
                "DS exists but DNSKEY was not retrieved",
                "A DS record was found, but the zone DNSKEY record could not be retrieved.",
                "Verify that DNSSEC is published correctly and the zone is serving DNSKEY records.",
            )
        )

    result["status"] = classify_check_status(issues)
    result["issues"] = issues_to_dicts(issues)
    result["summary"] = "DNSSEC {0}".format("appears enabled" if ds_records else "not detected")
    return result


def derive_cross_findings(results: Dict[str, Any]) -> List[Issue]:
    issues = []

    spf = results["checks"]["spf"]
    dmarc = results["checks"]["dmarc"]
    mx = results["checks"]["mx"]
    dkim = results["checks"]["dkim"]
    mta_sts = results["checks"]["mta_sts"]
    tls_rpt = results["checks"]["tls_rpt"]

    accepts_mail = bool(mx.get("accepts_mail"))
    weak_spf = spf.get("record") is None or spf.get("all_mechanism") in (None, "~", "?", "+")
    weak_dmarc = dmarc.get("policy") in (None, "none")

    if accepts_mail and weak_spf and weak_dmarc:
        detail = "The domain appears to accept mail, but DMARC is not enforcing and SPF is missing or weak."
        if not dkim.get("selectors_found"):
            detail += " DKIM was also not confirmed in the probed selector set."
        issues.append(
            make_issue(
                "high",
                "Cross-check",
                "High spoofing and impersonation exposure",
                detail,
                "Tighten SPF, move DMARC to quarantine/reject, and confirm DKIM alignment for real senders.",
            )
        )

    if accepts_mail and mta_sts.get("record") is None and tls_rpt.get("record") is None:
        issues.append(
            make_issue(
                "low",
                "Cross-check",
                "No SMTP transport security policy or reporting",
                "The domain accepts mail but does not appear to use MTA-STS or TLS-RPT.",
                "Deploy MTA-STS and TLS-RPT if you want stronger visibility into SMTP transport downgrade issues.",
            )
        )

    return issues


def severity_badge(severity: str) -> str:
    return severity_badge_colored(severity, use_color=True)


def severity_badge_colored(severity: str, use_color: bool) -> str:
    if not use_color:
        return severity.upper()
    colors = {
        "critical": RED,
        "high": RED,
        "medium": YELLOW,
        "low": CYAN,
        "info": DIM,
    }
    return "{0}{1}{2}".format(colors.get(severity, ""), severity.upper(), RESET)


def status_badge(status: str) -> str:
    return status_badge_colored(status, use_color=True)


def status_badge_colored(status: str, use_color: bool) -> str:
    if not use_color:
        return status.upper()
    colors = {
        "pass": GREEN,
        "warn": YELLOW,
        "fail": RED,
        "info": CYAN,
    }
    return "{0}{1}{2}".format(colors.get(status, ""), status.upper(), RESET)


def render_text_report(report: Dict[str, Any], use_color: bool = True) -> str:
    lines = []
    summary = report["summary"]

    bold = BOLD if use_color else ""
    reset = RESET if use_color else ""

    lines.append("{0}Email Auth Audit{1}".format(bold, reset))
    lines.append("Target: {0}".format(summary["target"]))
    lines.append("Domain: {0}".format(summary["domain"]))
    lines.append("Input type: {0}".format(summary["target_type"]))
    lines.append("DNS backend: {0}".format(summary["dns_backend"]))
    if summary.get("provider_guess"):
        lines.append("Mail provider guess: {0}".format(summary["provider_guess"]))
    if summary.get("dns_host_hint"):
        lines.append("DNS host hint: {0}".format(summary["dns_host_hint"]))
    lines.append("Overall risk: {0}".format(summary["overall_risk"].upper()))
    lines.append("")
    lines.append("{0}Checks{1}".format(bold, reset))

    for key in ("spf", "dmarc", "dkim", "mx", "dnssec", "mta_sts", "tls_rpt", "bimi"):
        check = report["checks"][key]
        title = key.replace("_", "-").upper()
        lines.append("  {0:<10} {1}  {2}".format(title, status_badge_colored(check["status"], use_color), check["summary"]))

    if report["checks"]["mx"].get("smtp_probe"):
        lines.append("")
        lines.append("{0}SMTP Probe{1}".format(bold, reset))
        for probe in report["checks"]["mx"]["smtp_probe"]:
            if probe.get("error"):
                lines.append("  {0}: {1}".format(probe["host"], probe["error"]))
                continue
            lines.append(
                "  {0}: STARTTLS={1}, TLS={2}, cipher={3}".format(
                    probe["host"],
                    "yes" if probe.get("starttls") else "no",
                    probe.get("tls_version") or "n/a",
                    probe.get("cipher") or "n/a",
                )
            )

    lines.append("")
    lines.append("{0}Findings{1}".format(bold, reset))
    if not report["issues"]:
        lines.append("  No material issues found.")
    else:
        for issue in report["issues"]:
            lines.append(
                "  [{0}] {1} - {2}".format(
                    issue["area"],
                    severity_badge_colored(issue["severity"], use_color),
                    issue["title"],
                )
            )
            lines.append("    {0}".format(issue["detail"]))
            if issue.get("recommendation"):
                lines.append("    Fix: {0}".format(issue["recommendation"]))

    if report.get("ai_analysis"):
        lines.append("")
        lines.append("{0}AI Commentary (Advisory){1}".format(bold, reset))
        lines.append(report["ai_analysis"].strip())

    remediation_plan = report.get("remediation_plan") or []
    if remediation_plan:
        lines.append("")
        lines.append("{0}Remediation Plan{1}".format(bold, reset))
        for item in remediation_plan:
            lines.append("  [{0}] {1}".format(item["priority"].upper(), item["title"]))
            lines.append("    Why: {0}".format(item["why"]))
            for step in item.get("steps", []):
                lines.append("    Step: {0}".format(step))
            if item.get("example_record"):
                record = item["example_record"]
                lines.append("    Example DNS: {0} {1} {2}".format(record["name"], record["type"], record["value"]))
            for record in item.get("example_records", []):
                lines.append("    Example DNS: {0} {1} {2}".format(record["name"], record["type"], record["value"]))
            if item.get("example_note"):
                lines.append("    Note: {0}".format(item["example_note"]))
            if item.get("example_policy"):
                lines.append("    Example policy:")
                for policy_line in item["example_policy"].splitlines():
                    lines.append("      {0}".format(policy_line))

    return "\n".join(lines)


def render_message_analysis_report(report: Dict[str, Any], use_color: bool = True) -> str:
    lines = []
    summary = report["summary"]
    bold = BOLD if use_color else ""
    reset = RESET if use_color else ""

    lines.append("{0}Message Auth Analysis{1}".format(bold, reset))
    lines.append("Source file: {0}".format(summary["source_file"]))
    lines.append("From domain: {0}".format(summary.get("from_domain") or "n/a"))
    lines.append("Return-Path domain: {0}".format(summary.get("return_path_domain") or "n/a"))
    lines.append("Overall risk: {0}".format(summary["overall_risk"].upper()))
    if summary.get("user_question"):
        lines.append("Question: {0}".format(summary["user_question"]))
    lines.append("")
    lines.append("{0}Authentication Results{1}".format(bold, reset))
    combined = report["combined"]
    effective = report.get("effective", combined)
    lines.append(
        "  SPF: {0}{1}".format(
            (effective.get("spf") or combined.get("received_spf") or "n/a").upper(),
            " (via ARC)" if effective.get("sources", {}).get("spf") == "arc" else "",
        )
    )
    lines.append(
        "  DKIM: {0}{1}".format(
            (effective.get("dkim") or "n/a").upper(),
            " (via ARC)" if effective.get("sources", {}).get("dkim") == "arc" else "",
        )
    )
    lines.append(
        "  DMARC: {0}{1}".format(
            (effective.get("dmarc") or "n/a").upper(),
            " (via ARC)" if effective.get("sources", {}).get("dmarc") == "arc" else "",
        )
    )
    lines.append("  ARC: {0}".format((effective.get("arc") or combined.get("arc") or "n/a").upper()))

    arc_summary = report.get("arc_summary") or {}
    if any(arc_summary.get(key) for key in ("upstream_spf", "upstream_dkim", "upstream_dmarc")):
        lines.append("")
        lines.append("{0}ARC Chain{1}".format(bold, reset))
        lines.append("  Upstream SPF: {0}".format((arc_summary.get("upstream_spf") or "n/a").upper()))
        lines.append("  Upstream DKIM: {0}".format((arc_summary.get("upstream_dkim") or "n/a").upper()))
        lines.append("  Upstream DMARC: {0}".format((arc_summary.get("upstream_dmarc") or "n/a").upper()))
    lines.append("")
    lines.append("{0}Findings{1}".format(bold, reset))
    if not report["issues"]:
        lines.append("  No material issues found in the supplied headers.")
    else:
        for issue in report["issues"]:
            lines.append(
                "  [{0}] {1} - {2}".format(
                    issue["area"],
                    severity_badge_colored(issue["severity"], use_color),
                    issue["title"],
                )
            )
            lines.append("    {0}".format(issue["detail"]))
            if issue.get("recommendation"):
                lines.append("    Fix: {0}".format(issue["recommendation"]))

    if report.get("ai_analysis"):
        lines.append("")
        lines.append("{0}AI Commentary (Advisory){1}".format(bold, reset))
        lines.append(report["ai_analysis"].strip())

    return "\n".join(lines)


def render_bulk_report(report: Dict[str, Any], use_color: bool = True) -> str:
    lines = []
    summary = report["summary"]
    bold = BOLD if use_color else ""
    reset = RESET if use_color else ""

    lines.append("{0}Bulk Email Auth Audit{1}".format(bold, reset))
    lines.append("Targets scanned: {0}".format(summary["targets_scanned"]))
    lines.append("Overall risk: {0}".format(summary["overall_risk"].upper()))
    lines.append("")
    lines.append("{0}Portfolio Summary{1}".format(bold, reset))
    for severity, count in summary["issue_counts"].items():
        if count:
            lines.append("  {0}: {1}".format(severity.upper(), count))
    lines.append("")
    lines.append("{0}Per Domain{1}".format(bold, reset))
    for entry in report["domains"]:
        lines.append(
            "  {0:<30} {1}  {2}".format(
                entry["domain"],
                severity_badge_colored(entry["overall_risk"], use_color),
                ", ".join(entry["top_titles"][:3]) if entry["top_titles"] else "no material findings",
            )
        )

    if report["top_findings"]:
        lines.append("")
        lines.append("{0}Top Findings{1}".format(bold, reset))
        for item in report["top_findings"][:10]:
            lines.append("  {0}  {1} ({2} domain(s))".format(severity_badge_colored(item["severity"], use_color), item["title"], item["count"]))

    if report.get("ai_analysis"):
        lines.append("")
        lines.append("{0}AI Commentary (Advisory){1}".format(bold, reset))
        lines.append(report["ai_analysis"].strip())

    return "\n".join(lines)


def load_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        raise SystemExit("Config file not found: {0}".format(path))
    except json.JSONDecodeError as exc:
        raise SystemExit("Config file is not valid JSON: {0}".format(exc))


def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def load_dotenv_file(path: str, required: bool = False) -> Dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        if required:
            raise SystemExit("Env file not found: {0}".format(path))
        return {}
    except OSError as exc:
        raise SystemExit("Could not read env file {0}: {1}".format(path, exc))

    values: Dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if value and value[0] in ("'", '"') and value[-1:] == value[0]:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].strip()

        values[key] = value

    return values


def load_default_dotenv(script_path: str, explicit_env_file: Optional[str]) -> Tuple[Dict[str, str], Optional[str]]:
    if explicit_env_file:
        return load_dotenv_file(explicit_env_file, required=True), explicit_env_file

    script_env = os.path.join(os.path.dirname(os.path.abspath(script_path)), ".env")
    cwd_env = os.path.join(os.getcwd(), ".env")

    merged: Dict[str, str] = {}
    loaded_path = None
    for candidate in (cwd_env, script_env):
        if candidate == loaded_path or not os.path.exists(candidate):
            continue
        merged.update(load_dotenv_file(candidate))
        loaded_path = candidate

    return merged, loaded_path


def env_get(name: str, dotenv_values: Dict[str, str]) -> Optional[str]:
    if name in os.environ:
        return os.environ[name]
    return dotenv_values.get(name)


def normalize_ai_provider(provider: str) -> str:
    lowered = provider.strip().lower()
    return AI_PROVIDER_ALIASES.get(lowered, lowered)


def default_model_for_provider(provider: str) -> str:
    if provider == "ollama":
        return "qwen3-coder-64k:latest"
    return ""


def default_endpoint_for_provider(provider: str) -> str:
    defaults = {
        "ollama": "http://localhost:11434",
        "claude": "https://api.anthropic.com",
        "openai": "https://api.openai.com/v1",
        "xai": "https://api.x.ai/v1",
        "gemini": "https://generativelanguage.googleapis.com/v1beta/models",
        "openai-compatible": "",
    }
    return defaults.get(provider, "")


def resolve_ai_settings(args: argparse.Namespace, config: Dict[str, Any], dotenv_values: Dict[str, str]) -> Dict[str, Any]:
    ai_config = config.get("email_security_ai", {})

    provider = first_non_empty(
        args.ai_provider,
        env_get("EMAIL_AUDIT_AI_PROVIDER", dotenv_values),
        ai_config.get("provider"),
        "none",
    )
    provider = normalize_ai_provider(str(provider))

    provider_model_env = AI_PROVIDER_MODEL_ENVS.get(provider)
    provider_endpoint_env = AI_PROVIDER_ENDPOINT_ENVS.get(provider)
    provider_api_key_env = AI_PROVIDER_API_KEY_ENVS.get(provider)

    model = first_non_empty(
        args.ai_model,
        env_get("EMAIL_AUDIT_AI_MODEL", dotenv_values),
        env_get(provider_model_env, dotenv_values) if provider_model_env else None,
        ai_config.get("model"),
        default_model_for_provider(provider),
        "",
    )
    endpoint = first_non_empty(
        args.ai_endpoint,
        env_get("EMAIL_AUDIT_AI_ENDPOINT", dotenv_values),
        env_get(provider_endpoint_env, dotenv_values) if provider_endpoint_env else None,
        ai_config.get("endpoint"),
        default_endpoint_for_provider(provider),
        "",
    )
    api_key_env = first_non_empty(
        args.api_key_env,
        env_get("EMAIL_AUDIT_AI_API_KEY_ENV", dotenv_values),
        ai_config.get("api_key_env"),
        provider_api_key_env,
        "OPENAI_API_KEY",
    )
    timeout = first_non_empty(
        args.ai_timeout,
        env_get("EMAIL_AUDIT_AI_TIMEOUT", dotenv_values),
        ai_config.get("timeout"),
        60,
    )

    return {
        "provider": provider,
        "model": str(model),
        "endpoint": str(endpoint),
        "api_key_env": str(api_key_env),
        "timeout": float(timeout),
        "api_key": env_get(str(api_key_env), dotenv_values) if api_key_env else None,
    }


def normalize_openai_compatible_endpoint(endpoint: str) -> str:
    trimmed = endpoint.rstrip("/")
    if trimmed.endswith("/chat/completions"):
        return trimmed
    if trimmed.endswith("/v1"):
        return trimmed + "/chat/completions"
    return trimmed + "/v1/chat/completions"


def normalize_anthropic_endpoint(endpoint: str) -> str:
    trimmed = endpoint.rstrip("/")
    if trimmed.endswith("/messages"):
        return trimmed
    if trimmed.endswith("/v1"):
        return trimmed + "/messages"
    return trimmed + "/v1/messages"


def normalize_gemini_endpoint(endpoint: str, model: str, api_key: str) -> str:
    trimmed = endpoint.rstrip("/")
    if ":generateContent" not in trimmed:
        if "/models/" not in trimmed:
            trimmed = trimmed + "/" + urllib.parse.quote(model, safe="")
        elif not trimmed.endswith(model):
            trimmed = trimmed + "/" + urllib.parse.quote(model, safe="")
        trimmed = trimmed + ":generateContent"

    if "key=" in trimmed:
        return trimmed
    separator = "&" if "?" in trimmed else "?"
    return trimmed + separator + urllib.parse.urlencode({"key": api_key})


def call_openai_style_analysis(
    endpoint: str,
    api_key: str,
    model: str,
    system_prompt: str,
    prompt: str,
    timeout: float,
) -> str:
    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(api_key),
        },
    )
    with urllib.request.urlopen(request, timeout=timeout, context=HTTP_SSL_CTX) as response:
        body = json.loads(response.read().decode("utf-8", errors="replace"))
    choices = body.get("choices", [])
    if not choices:
        return "AI analysis returned no choices."
    message = choices[0].get("message", {})
    return (message.get("content") or "").strip() or "AI analysis returned an empty message."


def split_ai_findings(issues: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    heuristic_titles = {
        "No DKIM selectors found in the probed selector list",
    }
    confirmed = []
    heuristic = []
    for issue in issues:
        if issue.get("title") in heuristic_titles:
            heuristic.append(issue)
        else:
            confirmed.append(issue)
    return confirmed, heuristic


def dispatch_ai_prompt(
    prompt: str,
    ai_settings: Dict[str, Any],
    timeout: float,
    system_prompt: str = "You analyze email authentication findings and provide concise, security-focused next steps.",
) -> Optional[str]:
    provider = ai_settings["provider"]
    if provider == "none":
        return None

    if not ai_settings["model"]:
        return "AI analysis skipped: no model configured."
    if not ai_settings["endpoint"]:
        return "AI analysis skipped: no endpoint configured."

    try:
        if provider == "ollama":
            endpoint = ai_settings["endpoint"].rstrip("/") + "/api/generate"
            payload = json.dumps(
                {
                    "model": ai_settings["model"],
                    "prompt": "{0}\n\n{1}".format(system_prompt, prompt),
                    "stream": False,
                    "options": {"temperature": 0.2},
                }
            ).encode("utf-8")
            request = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=timeout, context=HTTP_SSL_CTX) as response:
                body = json.loads(response.read().decode("utf-8", errors="replace"))
            return body.get("response", "").strip() or "AI analysis returned no content."

        if provider in ("openai", "xai", "openai-compatible"):
            endpoint = normalize_openai_compatible_endpoint(ai_settings["endpoint"])
            api_key = ai_settings.get("api_key")
            if not api_key:
                return "AI analysis skipped: environment variable {0} is not set.".format(ai_settings["api_key_env"])
            return call_openai_style_analysis(endpoint, api_key, ai_settings["model"], system_prompt, prompt, timeout)

        if provider == "claude":
            api_key = ai_settings.get("api_key")
            if not api_key:
                return "AI analysis skipped: environment variable {0} is not set.".format(ai_settings["api_key_env"])

            endpoint = normalize_anthropic_endpoint(ai_settings["endpoint"])
            payload = json.dumps(
                {
                    "model": ai_settings["model"],
                    "max_tokens": 700,
                    "system": system_prompt,
                    "messages": [
                        {"role": "user", "content": prompt},
                    ],
                }
            ).encode("utf-8")
            request = urllib.request.Request(
                endpoint,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            with urllib.request.urlopen(request, timeout=timeout, context=HTTP_SSL_CTX) as response:
                body = json.loads(response.read().decode("utf-8", errors="replace"))
            content = body.get("content", [])
            text_parts = [item.get("text", "") for item in content if item.get("type") == "text"]
            return "\n".join(part for part in text_parts if part).strip() or "AI analysis returned no content."

        if provider == "gemini":
            api_key = ai_settings.get("api_key")
            if not api_key:
                return "AI analysis skipped: environment variable {0} is not set.".format(ai_settings["api_key_env"])

            endpoint = normalize_gemini_endpoint(ai_settings["endpoint"], ai_settings["model"], api_key)
            payload = json.dumps(
                {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2},
                }
            ).encode("utf-8")
            request = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=timeout, context=HTTP_SSL_CTX) as response:
                body = json.loads(response.read().decode("utf-8", errors="replace"))
            candidates = body.get("candidates", [])
            if not candidates:
                return "AI analysis returned no candidates."
            parts = ((candidates[0].get("content") or {}).get("parts") or [])
            text_parts = [part.get("text", "") for part in parts if part.get("text")]
            return "\n".join(text_parts).strip() or "AI analysis returned no content."

        return "AI analysis skipped: unsupported provider {0}.".format(provider)
    except urllib.error.HTTPError as exc:
            return "AI analysis failed with HTTP {0}: {1}".format(exc.code, exc.reason)
    except Exception as exc:
        return "AI analysis failed: {0}".format(exc)


def call_ai_analysis(report: Dict[str, Any], ai_settings: Dict[str, Any], timeout: float) -> Optional[str]:
    confirmed_issues, heuristic_issues = split_ai_findings(report["issues"])
    condensed = {
        "target": report["summary"]["target"],
        "domain": report["summary"]["domain"],
        "provider_guess": report["summary"].get("provider_guess"),
        "summary": report["summary"],
        "checks": report["checks"],
        "confirmed_findings": confirmed_issues[:12],
        "heuristic_findings": heuristic_issues[:6],
        "remediation_plan": report.get("remediation_plan", [])[:6],
    }

    prompt = (
        "You are reviewing an email authentication posture audit for a security engineer.\n"
        "Use ONLY the confirmed_findings in the JSON as authoritative evidence.\n"
        "If heuristic_findings exist, mention them only as unconfirmed probes or coverage gaps.\n"
        "Do NOT claim a control is missing unless it appears in confirmed_findings.\n"
        "Do NOT say DKIM is absent if the only evidence is that no probed selectors were found.\n"
        "Prioritize spoofing, transport security, and DNS hygiene risks.\n"
        "Call out confidence caveats and concrete next steps.\n"
        "Be concise and practical.\n\n"
        "Audit JSON:\n{0}".format(json.dumps(condensed, indent=2))
    )

    return dispatch_ai_prompt(prompt, ai_settings, timeout)


def call_ai_message_analysis(
    report: Dict[str, Any],
    ai_settings: Dict[str, Any],
    timeout: float,
    user_question: Optional[str] = None,
) -> Optional[str]:
    condensed = {
        "summary": report["summary"],
        "headers": report["headers"],
        "header_snapshot": report.get("header_snapshot"),
        "body_preview": report.get("body_preview"),
        "urls": report.get("urls"),
        "combined_results": report["combined"],
        "effective_results": report.get("effective"),
        "arc_summary": report.get("arc_summary"),
        "alignment": report["alignment"],
        "dkim_signature_domains": report["summary"].get("dkim_signature_domains", []),
        "findings": report["issues"][:12],
    }

    if user_question:
        prompt = (
            "You are reviewing authentication headers and message content from an uploaded email file.\n"
            "Answer the user's question using ONLY the supplied message evidence.\n"
            "If ARC data is present, distinguish direct receiver results from upstream ARC-preserved results.\n"
            "If the file appears to be a sent/archive copy rather than a fully delivered message, say so clearly.\n"
            "Do NOT invent DNS posture or delivery outcomes that are not shown in the evidence.\n"
            "Be concise, explicit about confidence, and answer the question directly before adding supporting details.\n\n"
            "User question:\n{0}\n\n"
            "Message JSON:\n{1}".format(user_question, json.dumps(condensed, indent=2))
        )
    else:
        prompt = (
            "You are reviewing authentication headers from a delivered email message.\n"
            "Analyze ONLY the supplied message evidence.\n"
            "If ARC data is present, distinguish direct receiver results from upstream ARC-preserved results.\n"
            "Do NOT infer DNS posture or claim the sender domain lacks SPF, DKIM, or DMARC records unless the message evidence itself shows that.\n"
            "Explain likely causes of failures or alignment problems, note confidence limits, and give concise remediation next steps.\n"
            "Be practical and avoid speculation.\n\n"
            "Message JSON:\n{0}".format(json.dumps(condensed, indent=2))
        )

    return dispatch_ai_prompt(prompt, ai_settings, timeout)


def call_ai_bulk_analysis(report: Dict[str, Any], ai_settings: Dict[str, Any], timeout: float) -> Optional[str]:
    condensed = {
        "summary": report["summary"],
        "domains": report["domains"][:50],
        "top_findings": report["top_findings"][:15],
    }

    prompt = (
        "You are reviewing a portfolio-level email authentication audit across multiple domains.\n"
        "Use the supplied findings as the source of truth.\n"
        "Focus on repeated patterns, highest-risk domains, and the most efficient remediation sequence.\n"
        "Group similar issues together, call out provider patterns when present, and end with a short prioritized action plan.\n"
        "Do not invent missing controls beyond the supplied data.\n\n"
        "Portfolio JSON:\n{0}".format(json.dumps(condensed, indent=2))
    )

    return dispatch_ai_prompt(prompt, ai_settings, timeout)


def calculate_overall_risk(issues: List[Issue]) -> str:
    if any(issue.severity == "critical" for issue in issues):
        return "critical"
    if any(issue.severity == "high" for issue in issues):
        return "high"
    if any(issue.severity == "medium" for issue in issues):
        return "medium"
    if any(issue.severity == "low" for issue in issues):
        return "low"
    return "informational"


def sample_spf_for_provider(provider_guess: Optional[str]) -> Optional[str]:
    samples = {
        "Microsoft 365": "v=spf1 include:spf.protection.outlook.com -all",
        "Google Workspace": "v=spf1 include:_spf.google.com -all",
        "Zoho Mail": "v=spf1 include:zohomail.in -all",
    }
    return samples.get(provider_guess or "")


def sample_mx_records_for_provider(
    provider_guess: Optional[str],
    domain: str,
    spf_record: Optional[str] = None,
) -> Tuple[List[Dict[str, str]], Optional[str]]:
    if provider_guess == "Microsoft 365":
        tenant_host = re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")
        records = [
            {
                "name": domain,
                "type": "MX",
                "value": "0 {0}.mail.protection.outlook.com".format(tenant_host),
            }
        ]
        note = "Verify the exact MX target in the Microsoft 365 admin center before publishing it."
        return records, note

    if provider_guess == "Google Workspace":
        records = [
            {"name": domain, "type": "MX", "value": "1 ASPMX.L.GOOGLE.COM"},
            {"name": domain, "type": "MX", "value": "5 ALT1.ASPMX.L.GOOGLE.COM"},
            {"name": domain, "type": "MX", "value": "5 ALT2.ASPMX.L.GOOGLE.COM"},
            {"name": domain, "type": "MX", "value": "10 ALT3.ASPMX.L.GOOGLE.COM"},
            {"name": domain, "type": "MX", "value": "10 ALT4.ASPMX.L.GOOGLE.COM"},
        ]
        return records, None

    if provider_guess == "Zoho Mail":
        lowered_spf = (spf_record or "").lower()
        suffix = "com"
        if "zohomail.in" in lowered_spf:
            suffix = "in"
        elif "zohomail.eu" in lowered_spf:
            suffix = "eu"
        records = [
            {"name": domain, "type": "MX", "value": "10 mx.zoho.{0}".format(suffix)},
            {"name": domain, "type": "MX", "value": "20 mx2.zoho.{0}".format(suffix)},
            {"name": domain, "type": "MX", "value": "50 mx3.zoho.{0}".format(suffix)},
        ]
        note = "Confirm the Zoho region before publishing these MX records."
        return records, note

    return [], None


def dns_host_update_steps(dns_host_hint: Optional[str]) -> List[str]:
    steps = {
        "GoDaddy": [
            "Sign in to GoDaddy, open My Products, and choose DNS for the domain.",
            "In the DNS records page, add or edit MX records at the root of the domain (@).",
            "Remove stale MX records if you are replacing an older mail provider.",
            "Save the records and allow DNS time to propagate.",
        ],
        "Cloudflare": [
            "Open the domain in Cloudflare and go to DNS.",
            "Add or edit MX records at the root of the domain (@).",
            "Remove stale MX records if you are replacing an older mail provider.",
            "Save the records and allow DNS time to propagate.",
        ],
        "Namecheap": [
            "Open Domain List in Namecheap and choose Manage for the domain.",
            "Go to Advanced DNS or Mail Settings and add or edit MX records at the root of the domain.",
            "Remove stale MX records if you are replacing an older mail provider.",
            "Save the records and allow DNS time to propagate.",
        ],
    }
    return steps.get(dns_host_hint or "", [])


def generate_domain_remediation_plan(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary = report["summary"]
    checks = report["checks"]
    domain = summary["domain"]
    provider_guess = summary.get("provider_guess")
    dns_host_hint = summary.get("dns_host_hint")
    dns_host_steps = dns_host_update_steps(dns_host_hint)
    plan: List[Dict[str, Any]] = []

    if checks["spf"]["record"] is None:
        sample = sample_spf_for_provider(provider_guess)
        action = {
            "priority": "high",
            "title": "Publish an SPF record",
            "why": "The domain currently has no SPF policy, which weakens sender authorization and anti-spoofing.",
            "steps": [
                "Inventory every legitimate outbound mail source before publishing the final record.",
                "Publish exactly one SPF TXT record at the zone apex.",
            ],
        }
        if sample:
            action["example_record"] = {"name": domain, "type": "TXT", "value": sample}
        plan.append(action)
    elif checks["spf"]["all_mechanism"] == "~":
        plan.append(
            {
                "priority": "medium",
                "title": "Move SPF from softfail to hard fail when ready",
                "why": "The domain already has SPF, but ~all is weaker than -all.",
                "steps": [
                    "Confirm all legitimate senders are covered by the existing SPF policy.",
                    "Replace ~all with -all after validation.",
                ],
            }
        )

    dmarc = checks["dmarc"]
    if dmarc.get("policy") and not dmarc.get("rua"):
        plan.append(
            {
                "priority": "medium",
                "title": "Add DMARC aggregate reporting",
                "why": "Aggregate DMARC reporting helps you validate enforcement and monitor abuse.",
                "steps": [
                    "Choose a mailbox or external processor for DMARC aggregate reports.",
                    "Add rua=mailto:dmarc@{0} or your preferred reporting address.".format(domain),
                ],
                "example_record": {
                    "name": "_dmarc.{0}".format(domain),
                    "type": "TXT",
                    "value": "v=DMARC1; p={0}; rua=mailto:dmarc@{1};".format(dmarc.get("policy"), domain),
                },
            }
        )

    if checks["mta_sts"]["record"] is None:
        mx_host = None
        if checks["mx"].get("mx_records"):
            mx_host = checks["mx"]["mx_records"][0]["host"]
        mx_pattern = "*.{0}".format(mx_host.split(".", 1)[1]) if mx_host and "." in mx_host else "*.mail.example.net"
        plan.append(
            {
                "priority": "medium",
                "title": "Deploy MTA-STS",
                "why": "MTA-STS helps receiving MTAs detect downgrade or MX hijack conditions for inbound mail.",
                "steps": [
                    "Publish an _mta-sts TXT record with a versioned id value.",
                    "Serve /.well-known/mta-sts.txt over HTTPS on mta-sts.{0}.".format(domain),
                ],
                "example_record": {
                    "name": "_mta-sts.{0}".format(domain),
                    "type": "TXT",
                    "value": "v=STSv1; id=20260326T000000",
                },
                "example_policy": "version: STSv1\nmode: enforce\nmx: {0}\nmax_age: 86400".format(mx_pattern),
            }
        )

    if checks["tls_rpt"]["record"] is None:
        plan.append(
            {
                "priority": "medium",
                "title": "Publish TLS-RPT reporting",
                "why": "TLS-RPT gives visibility into SMTP TLS delivery failures and works well alongside MTA-STS.",
                "steps": [
                    "Choose a mailbox for SMTP TLS reports.",
                    "Publish a TLS-RPT record on _smtp._tls.{0}.".format(domain),
                ],
                "example_record": {
                    "name": "_smtp._tls.{0}".format(domain),
                    "type": "TXT",
                    "value": "v=TLSRPTv1; rua=mailto:tls-report@{0}".format(domain),
                },
            }
        )

    if checks["mx"]["mx_records"] == [] and checks["mx"].get("accepts_mail"):
        mx_examples, mx_note = sample_mx_records_for_provider(provider_guess, domain, checks["spf"].get("record"))
        action = {
            "priority": "medium",
            "title": "Publish explicit MX records or a null MX",
            "why": "The domain currently falls back to A/AAAA for mail routing, which is less explicit and easier to misread operationally.",
            "steps": [
                "If the domain should receive mail, publish explicit MX records.",
                "If the domain should not receive mail, publish a null MX and keep SPF/DMARC strict.",
            ],
        }
        if provider_guess and mx_examples:
            action["title"] = "Publish explicit MX records for {0}".format(provider_guess)
            action["steps"] = [
                "Publish explicit MX records for the active provider instead of relying on A/AAAA fallback.",
                "Validate that the mailbox or alias exists for each address you expect to receive mail.",
            ]
            if dns_host_hint:
                action["steps"].append(
                    "Open {0} DNS management and add these MX records at the zone apex.".format(dns_host_hint)
                )
                action["steps"].extend(dns_host_steps)
            action["example_records"] = mx_examples
            if mx_note:
                action["example_note"] = mx_note
        plan.append(action)

    if summary.get("provider_guess"):
        action = {
            "priority": "info",
            "title": "Provider-specific validation checklist",
            "why": "The domain appears to use {0}; validate DNS settings against that provider's mail documentation.".format(summary["provider_guess"]),
            "steps": [
                "Confirm DKIM selectors, SPF includes, and MX hostnames match the active provider setup.",
                "Validate any staged rollouts in a non-production domain before tightening alignment settings.",
            ],
        }
        if dns_host_hint:
            action["steps"].append(
                "DNS appears to be hosted at {0}; use that control panel to add or update MX, TXT, and CNAME records.".format(dns_host_hint)
            )
            action["steps"].extend(dns_host_steps)
        plan.append(action)

    return plan


def build_report(
    target: str,
    target_type: str,
    domain: str,
    dns_client: DNSClient,
    selectors: List[str],
    smtp_probe: bool,
    timeout: float,
    skip_http: bool,
) -> Dict[str, Any]:
    checks = {}

    checks["spf"] = audit_spf(domain, dns_client, target_type)
    checks["dmarc"] = audit_dmarc(domain, dns_client, target_type)
    provider_hint = infer_provider_from_domain_hints(domain, dns_client, checks["spf"].get("record"))
    dns_host_hint = infer_dns_host_hint(domain, dns_client)
    checks["mx"] = audit_mx(domain, dns_client, target_type, smtp_probe, timeout, provider_hint=provider_hint)
    checks["dkim"] = audit_dkim(
        domain,
        dns_client,
        selectors,
        provider_guess=checks["mx"].get("provider_guess") or provider_hint,
        spf_record=checks["spf"].get("record"),
    )
    checks["dnssec"] = audit_dnssec(domain, dns_client)
    checks["mta_sts"] = audit_mta_sts(domain, dns_client, timeout, skip_http)
    checks["tls_rpt"] = audit_tls_rpt(domain, dns_client)
    checks["bimi"] = audit_bimi(domain, dns_client, checks["dmarc"])

    all_issues = []
    for check in checks.values():
        all_issues.extend(
            Issue(
                severity=item["severity"],
                area=item["area"],
                title=item["title"],
                detail=item["detail"],
                recommendation=item.get("recommendation", ""),
                evidence=item.get("evidence"),
            )
            for item in check["issues"]
        )

    all_issues.extend(derive_cross_findings({"checks": checks}))
    all_issues = sort_issues(all_issues)

    provider_guess = checks["mx"].get("provider_guess") or provider_hint
    summary = {
        "target": target,
        "target_type": target_type,
        "domain": domain,
        "dns_backend": dns_client.backend,
        "provider_guess": provider_guess,
        "dns_host_hint": dns_host_hint,
        "overall_risk": calculate_overall_risk(all_issues),
        "issue_counts": summarize_counts(all_issues),
        "limitations": [
            "DKIM discovery is heuristic unless the real selector names are known.",
            "AI commentary is advisory and should not override the raw DNS findings.",
        ],
    }

    report = {
        "summary": summary,
        "checks": checks,
        "issues": [asdict(issue) for issue in all_issues],
        "remediation_plan": [],
        "ai_analysis": None,
    }
    report["remediation_plan"] = generate_domain_remediation_plan(report)
    return report


def collect_targets(single_target: Optional[str], targets_csv: Optional[str], targets_file: Optional[str]) -> List[str]:
    values: List[str] = []
    if single_target:
        values.append(single_target)
    if targets_csv:
        values.extend([item.strip() for item in targets_csv.split(",") if item.strip()])
    if targets_file:
        with open(targets_file, "r", encoding="utf-8") as handle:
            values.extend([line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#")])

    seen = set()
    deduped = []
    for value in values:
        if value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return deduped


def build_bulk_report(
    targets: List[str],
    dns_client: DNSClient,
    selectors: List[str],
    smtp_probe: bool,
    timeout: float,
    skip_http: bool,
) -> Dict[str, Any]:
    domain_reports = []
    portfolio_issues: List[Dict[str, Any]] = []

    for target in targets:
        target_type, domain, _ = normalize_target(target)
        domain_report = build_report(
            target=target,
            target_type=target_type,
            domain=domain,
            dns_client=dns_client,
            selectors=selectors,
            smtp_probe=smtp_probe,
            timeout=timeout,
            skip_http=skip_http,
        )
        domain_reports.append(domain_report)
        for issue in domain_report["issues"]:
            item = dict(issue)
            item["domain"] = domain
            portfolio_issues.append(item)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    risk_counts: Dict[str, int] = {}
    finding_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    per_domain = []

    for report in domain_reports:
        overall = report["summary"]["overall_risk"]
        risk_counts[overall] = risk_counts.get(overall, 0) + 1
        for issue in report["issues"]:
            counts[issue["severity"]] = counts.get(issue["severity"], 0) + 1
            key = (issue["severity"], issue["title"])
            if key not in finding_map:
                finding_map[key] = {"severity": issue["severity"], "title": issue["title"], "count": 0, "domains": []}
            finding_map[key]["count"] += 1
            finding_map[key]["domains"].append(report["summary"]["domain"])

        per_domain.append(
            {
                "domain": report["summary"]["domain"],
                "overall_risk": overall,
                "top_titles": [issue["title"] for issue in report["issues"][:5]],
                "provider_guess": report["summary"].get("provider_guess"),
            }
        )

    top_findings = sorted(
        finding_map.values(),
        key=lambda item: (-SEVERITY_RANK.get(item["severity"], -1), -item["count"], item["title"]),
    )

    overall_risk = "informational"
    for candidate in ("critical", "high", "medium", "low"):
        if risk_counts.get(candidate):
            overall_risk = candidate
            break

    return {
        "mode": "bulk-analysis",
        "summary": {
            "targets_scanned": len(domain_reports),
            "overall_risk": overall_risk,
            "issue_counts": counts,
            "risk_counts": risk_counts,
        },
        "domains": per_domain,
        "top_findings": top_findings,
        "issues": portfolio_issues,
        "reports": domain_reports,
        "ai_analysis": None,
    }


def write_output(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
        if not content.endswith("\n"):
            handle.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit email authentication and mail security posture for a domain or email address.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="Domain name or email address to audit")
    parser.add_argument("--message-file", help="Path to a raw .eml or header file for delivered-message authentication analysis")
    parser.add_argument("--question", help="Optional freeform question for AI-assisted analysis, especially useful with --message-file")
    parser.add_argument("--targets", help="Comma-separated list of domains or email addresses for bulk auditing")
    parser.add_argument("--targets-file", help="Path to a file containing one target per line for bulk auditing")
    parser.add_argument("--selectors", help="Comma-separated DKIM selectors to probe")
    parser.add_argument("--selector-file", help="Path to a file containing one DKIM selector per line")
    parser.add_argument("--smtp-probe", action="store_true", help="Attempt live SMTP STARTTLS probes against MX hosts")
    parser.add_argument("--skip-http", action="store_true", help="Skip HTTP fetches such as the MTA-STS policy body")
    parser.add_argument("--timeout", type=float, default=4.0, help="Per-query timeout in seconds (default: 4.0)")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text output")
    parser.add_argument("--output", help="Write the report to a file")
    parser.add_argument("--env-file", help="Optional path to a .env file. Defaults to .env in the project or current directory.")
    parser.add_argument("--config", help="Legacy JSON config file. Prefer .env for AI settings.")
    parser.add_argument(
        "--ai-provider",
        choices=["none", "ollama", "claude", "anthropic", "openai", "xai", "x", "grok", "gemini", "openai-compatible"],
        default=None,
        help="Optional AI analysis backend",
    )
    parser.add_argument("--ai-model", help="Model name for AI analysis")
    parser.add_argument("--ai-endpoint", help="Base endpoint for AI analysis")
    parser.add_argument("--api-key-env", help="Environment variable name that stores the API key for the selected cloud provider")
    parser.add_argument("--ai-timeout", type=float, help="Timeout in seconds for the AI analysis request")
    args = parser.parse_args()

    if args.message_file and any([args.target, args.targets, args.targets_file]):
        parser.error("--message-file cannot be combined with domain targets.")

    bulk_mode = bool(args.targets or args.targets_file)
    if not args.message_file and not args.target and not bulk_mode:
        parser.error("Provide a target, --message-file, or --targets/--targets-file.")

    try:
        dns_client = DNSClient(timeout=args.timeout)
    except RuntimeError as exc:
        raise SystemExit(str(exc))

    selectors = load_selectors(args)
    dotenv_values, loaded_env_path = load_default_dotenv(__file__, args.env_file)
    config = load_config(args.config)
    ai_settings = resolve_ai_settings(args, config, dotenv_values)

    if args.message_file:
        report = build_message_analysis_report(args.message_file)
        report["summary"]["user_question"] = args.question
        report["ai_analysis"] = call_ai_message_analysis(report, ai_settings, ai_settings["timeout"], user_question=args.question)
        report["summary"]["env_file"] = loaded_env_path
    elif bulk_mode:
        targets = collect_targets(args.target, args.targets, args.targets_file)
        if not targets:
            parser.error("Bulk mode requires at least one target.")
        report = build_bulk_report(
            targets=targets,
            dns_client=dns_client,
            selectors=selectors,
            smtp_probe=args.smtp_probe,
            timeout=args.timeout,
            skip_http=args.skip_http,
        )
        report["ai_analysis"] = call_ai_bulk_analysis(report, ai_settings, ai_settings["timeout"])
        report["summary"]["env_file"] = loaded_env_path
    else:
        try:
            target_type, domain, _ = normalize_target(args.target)
        except ValueError as exc:
            raise SystemExit(str(exc))

        report = build_report(
            target=args.target,
            target_type=target_type,
            domain=domain,
            dns_client=dns_client,
            selectors=selectors,
            smtp_probe=args.smtp_probe,
            timeout=args.timeout,
            skip_http=args.skip_http,
        )
        report["ai_analysis"] = call_ai_analysis(report, ai_settings, ai_settings["timeout"])
        report["summary"]["env_file"] = loaded_env_path

    if args.json:
        output = json.dumps(report, indent=2)
    else:
        if report.get("mode") == "message-analysis":
            output = render_message_analysis_report(report, use_color=sys.stdout.isatty())
        elif report.get("mode") == "bulk-analysis":
            output = render_bulk_report(report, use_color=sys.stdout.isatty())
        else:
            output = render_text_report(report, use_color=sys.stdout.isatty())

    if args.output:
        if args.json:
            file_output = output
        elif report.get("mode") == "message-analysis":
            file_output = render_message_analysis_report(report, use_color=False)
        elif report.get("mode") == "bulk-analysis":
            file_output = render_bulk_report(report, use_color=False)
        else:
            file_output = render_text_report(report, use_color=False)
        write_output(args.output, file_output)
        if not args.json:
            print(output)
            print("")
            print("Wrote report to {0}".format(args.output))
        else:
            print("Wrote JSON report to {0}".format(args.output))
    else:
        print(output)


if __name__ == "__main__":
    main()

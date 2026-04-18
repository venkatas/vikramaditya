#!/usr/bin/env python3
"""
OpenAPI / Swagger discovery and low-noise unauthenticated API audit.

Usage:
    python3 openapi_audit.py --recon-dir /path/to/recon/example.com
    python3 openapi_audit.py --recon-dir /path/to/recon/example.com --max-hosts 30 --max-ops 120
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


SPEC_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/openapi.yml",
    "/api-docs",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger-ui/index.html",
    "/swagger-ui.html",
    "/redoc",
]

HTML_SPEC_RE = re.compile(
    r"""(?:
        ["'](?P<quoted>(?:https?://|/)[^"' ]*(?:swagger|openapi)[^"' ]*\.(?:json|ya?ml))["']
        |
        url\s*:\s*["'](?P<config>(?:https?://|/)[^"' ]+\.(?:json|ya?ml))["']
    )""",
    re.IGNORECASE | re.VERBOSE,
)
PATH_PARAM_RE = re.compile(r"\{[^}/]+\}")
SENSITIVE_PATH_RE = re.compile(
    r"/(admin|auth|apikey|api-key|token|secret|key|user|users|account|profile|"
    r"workspace|team|org|settings|config|document|documents|file|files|"
    r"webhook|integration|internal|private|billing|invoice|payment|"
    r"customer|tenant|member|role)",
    re.IGNORECASE,
)
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")
SAFE_PROBE_METHODS = {"get", "head", "options"}


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        return [line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip()]
    except OSError:
        return []


def dedupe(items: list[str]) -> list[str]:
    seen = set()
    ordered = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def file_count(path: Path) -> int:
    return len(read_lines(path))


def safe_name(url: str) -> str:
    digest = hashlib.md5(url.encode()).hexdigest()[:8]
    parsed = urlparse(url)
    host = re.sub(r"[^a-zA-Z0-9._-]+", "_", parsed.netloc or "spec")
    return f"{host}_{digest}"


def fetch(url: str, timeout: int = 6) -> dict[str, Any]:
    req = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (OpenAPI-Audit)",
            "Accept": "application/json, application/yaml, text/yaml, text/plain, text/html;q=0.9, */*;q=0.8",
        },
    )
    context = ssl._create_unverified_context()
    try:
        with urlopen(req, timeout=timeout, context=context) as resp:
            body = resp.read(1_000_000).decode("utf-8", errors="ignore")
            return {
                "status": resp.getcode(),
                "content_type": resp.headers.get("Content-Type", ""),
                "body": body,
                "final_url": resp.geturl(),
            }
    except HTTPError as exc:
        try:
            body = exc.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return {
            "status": exc.code,
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
            "body": body,
            "final_url": url,
        }
    except (URLError, TimeoutError, OSError):
        return {
            "status": 0,
            "content_type": "",
            "body": "",
            "final_url": url,
        }


def looks_like_yaml_spec(text: str) -> bool:
    lowered = text.lower()
    return ("openapi:" in lowered or "swagger:" in lowered) and "paths:" in lowered


def parse_spec(text: str) -> tuple[dict[str, Any] | None, str]:
    text = text.strip()
    if not text:
        return None, "empty"

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            if parsed.get("openapi") or parsed.get("swagger") or parsed.get("paths"):
                return parsed, "json"
    except Exception:
        pass

    if yaml is not None and looks_like_yaml_spec(text):
        try:
            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict) and (parsed.get("openapi") or parsed.get("swagger") or parsed.get("paths")):
                return parsed, "yaml"
        except Exception:
            pass

    return None, "unknown"


def extract_html_spec_links(base_url: str, body: str) -> list[str]:
    links = []
    for match in HTML_SPEC_RE.finditer(body):
        raw = match.group("quoted") or match.group("config")
        if raw:
            links.append(urljoin(base_url, raw))
    return dedupe(links)


def build_base_url(spec: dict[str, Any], source_url: str) -> str:
    parsed_source = urlparse(source_url)
    source_root = f"{parsed_source.scheme}://{parsed_source.netloc}"

    servers = spec.get("servers") or []
    if isinstance(servers, list) and servers:
        server_url = servers[0].get("url")
        if isinstance(server_url, str) and server_url.strip():
            return urljoin(source_root, server_url.strip())

    host = spec.get("host")
    base_path = spec.get("basePath", "")
    schemes = spec.get("schemes") or []
    if host:
        scheme = schemes[0] if isinstance(schemes, list) and schemes else (parsed_source.scheme or "https")
        return f"{scheme}://{host}{base_path}"

    return source_root


def join_api_url(base_url: str, path: str) -> str:
    if re.match(r"^https?://", path):
        return path
    parsed = urlparse(base_url)
    base_path = parsed.path.rstrip("/")
    final_path = f"{base_path}/{path.lstrip('/')}" if base_path else f"/{path.lstrip('/')}"
    return urlunparse((parsed.scheme, parsed.netloc, final_path, "", "", ""))


def sample_path(path: str) -> str:
    return PATH_PARAM_RE.sub("1", path)


def operation_requires_auth(spec: dict[str, Any], operation: dict[str, Any]) -> bool:
    op_security = operation.get("security")
    if op_security == []:
        return False
    if op_security is not None:
        return bool(op_security)
    global_security = spec.get("security")
    return bool(global_security)


def extract_operations(spec: dict[str, Any], source_url: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    title = ((spec.get("info") or {}).get("title") or "").strip()
    version = spec.get("openapi") or spec.get("swagger") or "unknown"
    base_url = build_base_url(spec, source_url)
    paths = spec.get("paths") or {}
    operations = []

    if not isinstance(paths, dict):
        paths = {}

    for raw_path, config in paths.items():
        if not isinstance(config, dict):
            continue
        for method in HTTP_METHODS:
            operation = config.get(method)
            if not isinstance(operation, dict):
                continue
            full_url = join_api_url(base_url, sample_path(raw_path))
            operations.append({
                "method": method.upper(),
                "path": raw_path,
                "sample_url": full_url,
                "requires_auth": operation_requires_auth(spec, operation),
                "summary": operation.get("summary") or operation.get("operationId") or "",
                "sensitive": bool(SENSITIVE_PATH_RE.search(raw_path)),
                "source_url": source_url,
                "title": title,
            })

    return {
        "source_url": source_url,
        "title": title,
        "version": version,
        "base_url": base_url,
        "operations": len(operations),
    }, operations


def collect_candidate_hosts(recon_dir: Path, max_hosts: int) -> list[str]:
    hosts = []
    for rel in (
        "priority/critical_hosts.txt",
        "priority/high_hosts.txt",
        "live/urls.txt",
    ):
        hosts.extend(read_lines(recon_dir / rel))
    return dedupe(hosts)[:max_hosts]


def discover_specs(recon_dir: Path, max_hosts: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    candidates = collect_candidate_hosts(recon_dir, max_hosts)
    discovered_specs = []
    operations = []
    visited = set()
    queued_links = []

    def probe(spec_url: str) -> None:
        if spec_url in visited:
            return
        visited.add(spec_url)

        resp = fetch(spec_url)
        if resp["status"] != 200 or not resp["body"]:
            return

        parsed, fmt = parse_spec(resp["body"])
        if parsed is not None:
            spec_meta, ops = extract_operations(parsed, resp["final_url"])
            spec_meta["format"] = fmt
            spec_meta["content_type"] = resp["content_type"]
            spec_meta["saved_as"] = safe_name(resp["final_url"])
            discovered_specs.append(spec_meta)
            operations.extend(ops)
            return

        body_lower = resp["body"].lower()
        if "swagger-ui" in body_lower or "redoc" in body_lower or "openapi" in body_lower:
            for link in extract_html_spec_links(resp["final_url"], resp["body"]):
                queued_links.append(link)

    for base_url in candidates:
        for path in SPEC_PATHS:
            probe(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))

    for extra in dedupe(queued_links):
        probe(extra)

    return discovered_specs, operations, candidates


def audit_public_operations(operations: list[dict[str, Any]], max_ops: int) -> list[dict[str, Any]]:
    findings = []
    tested = 0
    for op in operations:
        if tested >= max_ops:
            break
        method = op["method"].lower()
        if op["requires_auth"] or method not in SAFE_PROBE_METHODS:
            continue

        tested += 1
        url = op["sample_url"]
        resp = fetch(url)
        body = resp["body"]
        body_size = len(body.encode("utf-8", errors="ignore"))
        content_type = resp["content_type"].lower()
        if resp["status"] in (200, 201, 202, 204):
            looks_interesting = (
                op["sensitive"]
                or "json" in content_type
                or body_size > 300
            )
            if looks_interesting:
                findings.append({
                    "status": resp["status"],
                    "method": op["method"],
                    "url": url,
                    "body_size": body_size,
                    "sensitive": op["sensitive"],
                    "summary": op.get("summary", ""),
                    "title": op.get("title", ""),
                })
    return findings


def write_outputs(
    output_dir: Path,
    discovered_specs: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    spec_urls = [item["source_url"] for item in discovered_specs]
    public_operations = [op for op in operations if not op["requires_auth"]]
    public_gets = [op for op in public_operations if op["method"] == "GET"]
    sensitive_public_ops = [op for op in public_operations if op["sensitive"]]

    (output_dir / "discovered_specs.json").write_text(json.dumps(discovered_specs, indent=2))
    (output_dir / "operations.json").write_text(json.dumps(operations, indent=2))
    (output_dir / "unauth_findings.json").write_text(json.dumps(findings, indent=2))
    (output_dir / "spec_urls.txt").write_text("\n".join(spec_urls) + ("\n" if spec_urls else ""))
    (output_dir / "all_operations.txt").write_text(
        "\n".join(op["sample_url"] for op in operations) + ("\n" if operations else "")
    )
    (output_dir / "public_get_operations.txt").write_text(
        "\n".join(op["sample_url"] for op in public_gets) + ("\n" if public_gets else "")
    )
    (output_dir / "public_operations.txt").write_text(
        "\n".join(f"{op['method']}\t{op['sample_url']}\t{op['source_url']}" for op in public_operations)
        + ("\n" if public_operations else "")
    )
    (output_dir / "sensitive_public_operations.txt").write_text(
        "\n".join(f"{op['method']}\t{op['sample_url']}\t{op['source_url']}" for op in sensitive_public_ops)
        + ("\n" if sensitive_public_ops else "")
    )
    (output_dir / "unauth_api_findings.txt").write_text(
        "\n".join(
            f"{item['status']} {item['body_size']} {item['method']} {item['url']}"
            + (f" [{item['title']}]" if item.get("title") else "")
            for item in findings
        ) + ("\n" if findings else "")
    )

    top_specs = ", ".join(
        f"{(item.get('title') or item['source_url'])} ({item['operations']} ops)"
        for item in discovered_specs[:6]
    ) or "none"
    lines = [
        "# OpenAPI Audit Summary",
        "",
        f"- Specs discovered: {len(discovered_specs)}",
        f"- Parsed operations: {len(operations)}",
        f"- Public operations: {len(public_operations)}",
        f"- Sensitive public operations: {len(sensitive_public_ops)}",
        f"- Unauthenticated findings: {len(findings)}",
        f"- Top specs: {top_specs}",
        "",
        "## Unauthenticated Findings",
    ]
    if findings:
        for item in findings[:20]:
            lines.append(
                f"- {item['status']} {item['method']} {item['url']} "
                f"({item['body_size']} bytes){' [sensitive]' if item['sensitive'] else ''}"
            )
    else:
        lines.append("- None")
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenAPI / Swagger discovery and unauth API audit")
    parser.add_argument("--recon-dir", required=True, help="Recon directory for one target")
    parser.add_argument("--max-hosts", type=int, default=20, help="Maximum hosts to probe for specs")
    parser.add_argument("--max-ops", type=int, default=60, help="Maximum public operations to probe")
    parser.add_argument("--discover-only", action="store_true", help="Discover and parse specs without probing public operations")
    args = parser.parse_args()

    recon_dir = Path(args.recon_dir)
    if not recon_dir.is_dir():
        print(f"[-] Recon dir not found: {recon_dir}", file=sys.stderr)
        return 1

    output_dir = recon_dir / "api_specs"
    discovered_specs, operations, _ = discover_specs(recon_dir, max_hosts=max(1, args.max_hosts))
    findings = [] if args.discover_only else audit_public_operations(operations, max_ops=max(1, args.max_ops))
    write_outputs(output_dir, discovered_specs, operations, findings)

    print(f"[*] OpenAPI specs discovered: {len(discovered_specs)}")
    print(f"[*] Parsed operations:        {len(operations)}")
    print(f"[*] Public operations:        {file_count(output_dir / 'public_operations.txt')}")
    print(f"[*] Unauth API findings:      {file_count(output_dir / 'unauth_api_findings.txt')}")
    print(f"[+] Summary:                  {output_dir / 'summary.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

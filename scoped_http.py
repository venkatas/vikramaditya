"""HTTP GETs whose initial URL and every redirect obey an exact-host allowlist.

The CLI is used by shell/curl callers; ``get`` also returns a normal requests
Response for Python callers. Redirects are never delegated to the HTTP client.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib.parse import urljoin, urlsplit

import requests

from scope_checker import _load_allow_file, scope_lock_allows


class ScopeError(ValueError):
    def __init__(self, source: str, destination: str):
        self.source = source
        self.destination = destination
        super().__init__(f"scope blocked HTTP destination: {destination!r}")


def allows(url: str, exact_hosts) -> bool:
    """Reject parser ambiguities and non-HTTP URLs before the shared matcher."""
    try:
        parsed = urlsplit(url)
        return (parsed.scheme in ("http", "https") and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and not any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url)
                and scope_lock_allows(url, exact_hosts))
    except (ValueError, TypeError):
        return False


def get(url: str, exact_hosts, *, timeout: float = 10, max_redirects: int = 3,
        headers: dict | None = None, max_body: int = 300_000):
    """Fetch a bounded body, following only validated HTTP(S) redirect hops.

    A blocked hop raises ScopeError without requesting it. Returned responses
    retain redirect history/cookies and buffered text after all sockets close.
    """
    if not allows(url, exact_hosts):
        raise ScopeError("", url)
    deadline = time.monotonic() + max(0.01, float(timeout))
    history = []
    request_headers = dict(headers or {})
    with requests.Session() as session:
        for hop in range(max_redirects + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise requests.Timeout("scoped HTTP deadline exceeded")
            response = session.get(url, headers=request_headers, verify=False,
                                   timeout=remaining, allow_redirects=False, stream=True)
            try:
                location = response.headers.get("Location")
                if response.status_code in (301, 302, 303, 307, 308) and location:
                    destination = urljoin(url, location)
                    if not allows(destination, exact_hosts):
                        raise ScopeError(url, destination)
                    if hop == max_redirects:
                        raise requests.TooManyRedirects("scoped HTTP redirect limit exceeded")
                    if urlsplit(url).hostname != urlsplit(destination).hostname:
                        request_headers = {k: v for k, v in request_headers.items()
                                           if k.lower() not in ("cookie", "authorization")}
                    history.append(response)
                    url = destination
                    continue
                body = bytearray()
                if max_body > 0:
                    for chunk in response.iter_content(chunk_size=8192):
                        if time.monotonic() > deadline:
                            raise requests.Timeout("scoped HTTP deadline exceeded")
                        body.extend(chunk[:max_body - len(body)])
                        if len(body) >= max_body:
                            break
                response._content = bytes(body)
                response._content_consumed = True
                response.history = history
                return response
            finally:
                response.close()
    raise requests.TooManyRedirects("scoped HTTP redirect limit exceeded")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-file", required=True)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--max-redirects", type=int, default=3)
    parser.add_argument("--max-body", type=int, default=300_000)
    parser.add_argument("--headers-only", action="store_true")
    parser.add_argument("--include-headers", action="store_true")
    parser.add_argument("--status-marker", action="store_true")
    parser.add_argument("--blocked-log")
    parser.add_argument("url")
    args = parser.parse_args(argv)
    try:
        response = get(args.url, _load_allow_file(args.allow_file), timeout=args.timeout,
                       max_redirects=args.max_redirects,
                       max_body=0 if args.headers_only else args.max_body)
    except ScopeError as exc:
        if args.blocked_log:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(args.blocked_log)), exist_ok=True)
                with open(args.blocked_log, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"source": exc.source, "location": exc.destination}) + "\n")
            except OSError:
                pass
        print(str(exc), file=sys.stderr)
        return 2
    except (requests.RequestException, ValueError) as exc:
        print(f"scoped HTTP failed: {exc}", file=sys.stderr)
        return 1
    if args.headers_only or args.include_headers:
        # CMS author enumeration needs allowed Location evidence from the
        # whole chain; CSP checks deliberately inspect only the final headers.
        header_responses = list(response.history) + [response] if args.include_headers else [response]
        for item in header_responses:
            print(f"HTTP/1.1 {item.status_code}")
            for key, value in item.headers.items():
                print(f"{key}: {value}")
            print()
    if not args.headers_only:
        print(response.text, end="")
    if args.status_marker:
        print(f"\nHTTP_STATUS:{response.status_code}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

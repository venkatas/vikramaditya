"""Local Playwright rendering with exact-host enforcement before every request.

Used for scope-locked screenshots and browser discovery. This is deliberately
separate from browser-use: its navigation allowlist cannot contain subresources
or guarantee that a new agent-controlled browser context uses our policy.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urljoin

from scoped_http import allows
from scope_checker import _load_allow_file


_DISABLE_UNROUTED_TRANSPORTS = """(() => {
  for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection',
                       'WebTransport', 'Worker', 'SharedWorker']) {
    try { Object.defineProperty(globalThis, name, {configurable: false,
      get() { throw new Error('Transport disabled by exact-host scope policy'); }}); }
    catch (_) {}
  }
})();"""


async def install_scope_routes(context, exact_hosts, blocked: list,
                               *, allow_unsafe: bool = False, timeout: float = 12) -> None:
    """Install guards before pages exist; fail closed if any guard is unavailable.

    route.fetch never auto-follows redirects. We validate Location before giving
    the response to Chromium, so its redirect handling cannot escape the policy.
    WebSockets are disabled entirely, as they are not needed for this renderer.
    """
    if not exact_hosts:
        raise ValueError("exact-host browser allowlist is missing or empty")
    if not callable(getattr(context, "route_web_socket", None)):
        raise RuntimeError("Playwright cannot intercept WebSockets; browser not started")

    async def block_websocket(route):
        blocked.append({"url": route.url, "method": "WEBSOCKET", "reason": "websocket disabled"})
        await route.close()

    async def guarded_request(route, request):
        if not allows(request.url, exact_hosts):
            blocked.append({"url": request.url, "method": request.method, "reason": "off-scope request"})
            await route.abort("blockedbyclient")
            return
        if not allow_unsafe and request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            blocked.append({"url": request.url, "method": request.method, "reason": "unsafe method disabled"})
            await route.abort("blockedbyclient")
            return
        response = None
        try:
            response = await route.fetch(max_redirects=0, timeout=max(1, int(timeout * 1000)))
            location = response.headers.get("location")
            if response.status in (301, 302, 303, 307, 308) and location:
                destination = urljoin(request.url, location)
                if not allows(destination, exact_hosts):
                    blocked.append({"url": destination, "source": request.url,
                                    "method": request.method, "reason": "off-scope redirect"})
                    await route.abort("blockedbyclient")
                    return
            await route.fulfill(response=response)
        except Exception as exc:
            blocked.append({"url": request.url, "method": request.method,
                            "reason": f"request failed: {type(exc).__name__}"})
            await route.abort("failed")
        finally:
            if response is not None:
                await response.dispose()

    await context.route("**/*", guarded_request)
    await context.route_web_socket("**/*", block_websocket)
    await context.add_init_script(_DISABLE_UNROUTED_TRANSPORTS)


async def render_pages(urls: list[str], exact_hosts, output_dir: str | Path,
                       *, headed: bool = False, timeout: float = 12,
                       allow_unsafe: bool = False, settle_ms: int = 500) -> dict:
    """Render allowed pages and collect screenshots/forms; never emit vulnerabilities.

    Blocked URLs remain passive evidence in blocked_requests.jsonl. Missing scope
    or interception support fails before the first page request is issued.
    """
    if not exact_hosts:
        raise ValueError("exact-host browser allowlist is missing or empty")
    if any(not allows(url, exact_hosts) for url in urls):
        raise ValueError("browser input contains an off-scope or malformed URL")
    from playwright.async_api import async_playwright

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    blocked: list = []
    pages: list = []
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=not headed, args=[
                "--disable-background-networking", "--disable-component-update",
                "--disable-domain-reliability", "--disable-sync",
                "--disable-features=AutofillServerCommunication,OptimizationHints,MediaRouter",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            ])
            context = None
            try:
                context = await browser.new_context(ignore_https_errors=True,
                                                    service_workers="block", accept_downloads=False)
                await install_scope_routes(context, exact_hosts, blocked,
                                           allow_unsafe=allow_unsafe, timeout=timeout)
                context.set_default_timeout(max(1, timeout * 1000))
                for url in urls:
                    page = await context.new_page()
                    record = {"url": url, "final_url": "", "forms": [], "error": ""}
                    try:
                        await page.goto(url, wait_until="domcontentloaded", timeout=max(1, timeout * 1000))
                        await page.wait_for_timeout(settle_ms)
                        if not allows(page.url, exact_hosts):
                            raise ValueError("final browser URL violates exact-host scope")
                        record["final_url"] = page.url
                        record["title"] = await page.title()
                        forms = await page.locator("form").evaluate_all("""forms => forms.map(f => ({
                            action: f.action, method: f.method,
                            inputs: Array.from(f.elements).map(e => e.name).filter(Boolean)
                        })).slice(0, 100)""")
                        for form in forms:
                            form["scope_allowed"] = allows(form.get("action", ""), exact_hosts)
                        record["forms"] = forms
                        screenshot = directory / (hashlib.sha256(url.encode()).hexdigest()[:16] + ".png")
                        await page.screenshot(path=str(screenshot), full_page=True, timeout=max(1, timeout * 1000))
                        record["screenshot"] = str(screenshot)
                    except Exception as exc:
                        record["error"] = str(exc)[:500]
                    finally:
                        pages.append(record)
                        await page.close()
            finally:
                if context is not None:
                    await context.close()
                await browser.close()
    finally:
        (directory / "blocked_requests.jsonl").write_text(
            "".join(json.dumps(item) + "\n" for item in blocked), encoding="utf-8")
        (directory / "guarded_pages.json").write_text(json.dumps(pages, indent=2), encoding="utf-8")
    return {"pages": pages, "blocked": blocked,
            "completed": sum(not item["error"] for item in pages),
            "failed": sum(bool(item["error"]) for item in pages)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-file", required=True)
    parser.add_argument("--urls-file", required=True)
    parser.add_argument("--output-dir", "--out-dir", dest="output_dir", required=True)
    parser.add_argument("--max-urls", type=int, default=0, help="Optional page cap; 0 renders every supplied URL")
    parser.add_argument("--timeout", type=float, default=12)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--coverage-file", help="Append failed/capped browser coverage to this JSON list")
    args = parser.parse_args(argv)

    def coverage_gap(reason: str) -> bool:
        if not args.coverage_file:
            return True
        try:
            path = Path(args.coverage_file)
            existing = json.loads(path.read_text()) if path.exists() else []
            if not isinstance(existing, list):
                raise ValueError("existing coverage marker is not a JSON list")
            entry = {"tool": "browser", "reason": reason}
            if entry not in existing:
                existing.append(entry)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            return True
        except (OSError, ValueError) as exc:
            print(f"Could not record guarded-browser coverage: {exc}", file=sys.stderr)
            return False

    try:
        urls = [line.strip() for line in Path(args.urls_file).read_text().splitlines() if line.strip()]
        if args.max_urls < 0:
            raise ValueError("--max-urls must be nonnegative")
        if args.max_urls and len(urls) > args.max_urls:
            if not coverage_gap(f"screenshots capped: {args.max_urls} of {len(urls)} supplied URLs rendered"):
                return 2
            urls = urls[:args.max_urls]
        result = asyncio.run(render_pages(urls, _load_allow_file(args.allow_file), args.output_dir,
                                          headed=args.headed, timeout=args.timeout))
    except Exception as exc:
        print(f"Guarded browser unavailable: {exc}")
        coverage_gap(f"guarded browser unavailable: {exc}")
        return 2
    print(f"Guarded browser: {result['completed']} rendered, {result['failed']} failed, "
          f"{len(result['blocked'])} requests blocked")
    if result["failed"]:
        coverage_gap(f"guarded browser failed on {result['failed']} of {len(result['pages'])} page(s)")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

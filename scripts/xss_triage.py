#!/usr/bin/env python3
import argparse
import asyncio
import re
import sys
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import httpx

CANARY = "dX7q9"
MARKERS = ["<", ">", '"', "'", "(", ")", "{", "}"]
PAYLOAD = CANARY + "".join(MARKERS)


def mutate(url: str):
    u = urlparse(url)
    qs = parse_qsl(u.query, keep_blank_values=True)
    if not qs:
        return []
    out = []
    for i, (k, _) in enumerate(qs):
        new_qs = list(qs)
        new_qs[i] = (k, PAYLOAD)
        out.append((k, urlunparse(u._replace(query=urlencode(new_qs, doseq=True)))))
    return out


def classify(body: str):
    m = re.search(re.escape(CANARY) + r"([^a-zA-Z0-9]{0,16})", body)
    if not m:
        return None
    tail = m.group(1)
    hit = [c for c in MARKERS if c in tail]
    return hit or None


async def probe(client, sem, url, param, results):
    async with sem:
        try:
            r = await client.get(url, timeout=10, follow_redirects=True)
            reflected = classify(r.text)
            if reflected:
                line = f"{url}\tparam={param}\treflected={''.join(reflected)}"
                print(line, flush=True)
                results.append(line)
        except (httpx.RequestError, httpx.TimeoutException):
            pass


async def run(urls, concurrency, out_path):
    sem = asyncio.Semaphore(concurrency)
    results = []
    limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency)
    headers = {"User-Agent": "xss-triage/1.0"}
    async with httpx.AsyncClient(verify=False, limits=limits, headers=headers) as client:
        tasks = []
        for u in urls:
            for param, mutated in mutate(u):
                tasks.append(probe(client, sem, mutated, param, results))
        if not tasks:
            print("[!] no URLs with query params", file=sys.stderr)
            return
        await asyncio.gather(*tasks)
    if out_path:
        with open(out_path, "w") as f:
            f.write("\n".join(results) + ("\n" if results else ""))
    print(f"[+] {len(results)} reflective hits / {len(tasks)} param tests", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", help="file with URLs (one per line); stdin if omitted")
    ap.add_argument("-o", "--output", help="output file")
    ap.add_argument("-c", "--concurrency", type=int, default=50)
    args = ap.parse_args()
    src = open(args.input) if args.input else sys.stdin
    urls = [l.strip() for l in src if l.strip() and "?" in l]
    if args.input:
        src.close()
    if not urls:
        print("[!] no URLs with ?param=value", file=sys.stderr)
        sys.exit(1)
    asyncio.run(run(urls, args.concurrency, args.output))


if __name__ == "__main__":
    main()

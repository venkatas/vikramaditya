#!/usr/bin/env python3
"""
Brain Scanner — LLM-driven active vulnerability verification.

Unlike the brain supervisor (which just says CONTINUE/SKIP), this scanner
asks the LLM to WRITE exploit code, EXECUTES it, feeds results back, and
ITERATES until the vulnerability is confirmed or ruled out.

Modes:
  scan       — Full vulnerability scanning (default)
  verify-fix — Developer says "fixed" → brain reads code, analyzes fix, writes bypass
  audit-code — Feed source code → brain finds vulns and writes PoCs

Loop: Briefing → LLM writes test script → Execute → Feed results → LLM decides next

Usage:
    python3 brain_scanner.py --target https://example.com
    python3 brain_scanner.py --target https://example.com --briefing "Test CSRF on /disclaimer.phtml"
    python3 brain_scanner.py --target https://example.com --cookies "Rm=abc; Rl=user@domain"

    # Fix verification: developer claims they fixed file upload
    python3 brain_scanner.py --target https://example.com --verify-fix \
        --fix-claim "File upload validator updated to block .phtml" \
        --code-url "https://example.com/upload-handler.php" \
        --cookies "session=abc"

    # Code audit: feed source code directly
    python3 brain_scanner.py --target https://example.com --audit-code /path/to/source.php
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime

import procutil  # fork-safe subprocess launch (macOS Network.framework atfork SIGSEGV fix)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Context window for the exploit-verification loop. MUST be large: brain_scanner runs a
# MULTI-ITERATION loop (system prompt + each round's code + its output accumulate), so the
# model's small default (~4096) overflows after iteration 1 → Ollama returns EMPTY responses
# → the loop aborts with 0 findings, i.e. the engine silently "backs off" mid-PoC. brain.py
# already sends num_ctx=32768; the scanner must match. Env-overridable for tight-RAM hosts.
_SCANNER_NUM_CTX = int(os.environ.get("BRAIN_SCANNER_NUM_CTX", "32768"))

# v10.6.0 — host-gating: block LLM-authored exploit code from targeting the
# operator's own machine/listener (see scopeguard.py, adapted from xalgorix MIT).
try:
    sys.path.insert(0, SCRIPT_DIR)
    import scopeguard as _scopeguard
except Exception:
    _scopeguard = None

# Colors
G = "\033[0;32m"
R = "\033[0;31m"
Y = "\033[1;33m"
C = "\033[0;36m"
M = "\033[0;35m"
B = "\033[1m"
D = "\033[0;90m"
N = "\033[0m"

MAX_ITERATIONS = 15
MAX_SCRIPT_RUNTIME = 60  # seconds
MAX_EMPTY_STREAK = 3     # abort if the provider returns N empty responses in a row


# ── Stdout-claim corroboration ────────────────────────────────────────────────
# A generated PoC can DECLARE success without it being true. Real example caught
# in the field: a shell PoC ended with
#     echo "[CRITICAL] Shadow file also accessible!" || echo "[-] Only passwd"
# `echo` always exits 0, so the `||` fallback never runs and the CRITICAL line
# prints UNCONDITIONALLY — even though the server returned `404 Not Found`. The
# grounding layer trusts script stdout over model prose (the anti-hallucination
# rule), so that buggy echo became a "confirmed" CRITICAL finding.
#
# Defence: a self-declared file-access / path-traversal / LFI claim is only
# accepted as a finding when the script output actually CONTAINS the file's
# content (proof). A genuine read prints the file (e.g. `root:x:0:0:` from
# /etc/passwd); an unconditional echo prints nothing of the sort. This does NOT
# touch other finding classes (SQLi/XSS/RCE confirmed by real tools), so it
# cannot suppress those.
_ACCESS_CLAIM_RE = re.compile(
    r'accessib|readable|path[\s_-]*traversal|directory traversal|\blfi\b|'
    r'arbitrary[\s_-]*file|file (?:read|disclos|retriev|leak)|local file|'
    r'/etc/passwd|/etc/shadow|win\.ini|boot\.ini|web\.config', re.I)
_FILE_PROOF_RE = re.compile(
    # A real /etc/passwd or /etc/shadow read prints account LINES — user:x:UID:GID:...
    # (passwd) or user:$hash:... (shadow). Anchored near line-start (MULTILINE) but we
    # allow a few leading NON-content characters (quotes, list bullets, an HTTP body
    # offset, leading whitespace) before the passwd shape, since real responses often
    # prefix it (e.g. JSON "data":"root:x:0:0:...", or a leading "> "). We still anchor
    # to a line boundary so a passwd-shaped string mid-error ("No such file") is excluded.
    r'^[\s"\'>\]\)\.,:|*-]{0,8}[a-z_][a-z0-9_-]*:[^:\n]*:\d+:\d+:'
    r'|\[boot loader\]|\[fonts\]|\[mci extensions\]'              # win.ini / boot.ini
    r'|<\?xml\b|<configuration\b|<connectionStrings|<appSettings'   # web.config
    r'|<\?php\b|<\?=\s'                                            # PHP source disclosure
    r'|-----BEGIN [A-Z ]*PRIVATE KEY-----'                        # private keys (covers RSA/OPENSSH/EC/DSA)
    r'|ssh-rsa AAAA|ssh-ed25519 AAAA'                             # public-key material in keyfiles
    r'|\bDB_PASSWORD\s*=|\bAWS_SECRET_ACCESS_KEY\b',              # .env / config leaks
    re.I | re.M)


def _access_claim_unproven(line: str, stdout: str) -> bool:
    """True when an stdout line ASSERTS file/resource access (passwd, shadow,
    traversal, LFI, "accessible"/"readable") but the script output carries NO
    actual file-content signature — i.e. a self-declared, unverified claim that
    must not be recorded as a confirmed finding."""
    if not _ACCESS_CLAIM_RE.search(line):
        return False                       # not an access claim → unaffected
    return not _FILE_PROOF_RE.search(stdout)


# Tool STATUS / progress chatter — NOT retrieved file content. Used to stop a
# fabricated access claim padded with noise (`echo "[*] scanning..."`) from
# being mistaken for a grounded read.
_STATUS_NOISE_RE = re.compile(
    r"^\s*(?:\[[*+\-!#]\]"                                  # [*] [+] [-] [!] [#]
    r"|\[(?:watchdog|info|warn|error|debug|brain|phase|status)\b"   # [Watchdog/..]
    r"|[>$#]\s"                                             # '> ' '$ ' '# '
    r"|\.{3,}"                                              # '...'
    r"|\d{1,3}%(?:\s|$))"                                   # '50%'
    r"|\b(?:scanning|connecting|downloading|fetching|elapsed|payload|"
    r"injecting|trying|progress|requesting|resolving)\b",
    re.IGNORECASE)


def _grounded_read_unproven(line: str, stdout: str) -> bool:
    """Generalized file-access proof gate (superset of _access_claim_unproven).

    An access CLAIM is treated as PROVEN when the output carries EITHER the
    narrow _FILE_PROOF_RE signature OR >=2 substantive lines that plausibly
    carry retrieved file content — i.e. >=8 chars, not the claim/usage banner,
    and not tool-status/progress chatter. This recovers grounded reads of
    NON-whitelisted files (source, YAML/JSON config, /etc/hosts, /proc/self/
    environ) that the narrow signature regex cannot represent, while a bare
    `echo "accessible"` or a claim padded only with progress noise stays
    unproven. Returns True == still unproven (reject as a finding)."""
    if not _ACCESS_CLAIM_RE.search(line):
        return False                       # not an access claim → unaffected
    if _FILE_PROOF_RE.search(stdout):
        return False                       # narrow signature already proves it
    substantive = []
    for ln in (stdout or "").splitlines():
        s = ln.strip()
        if len(s) < 8:
            continue
        if _ACCESS_CLAIM_RE.search(ln):
            continue
        if _USAGE_BANNER_RE is not None and _USAGE_BANNER_RE.search(ln):
            continue
        if _STATUS_NOISE_RE.search(ln):
            continue
        substantive.append(s)
        if len(substantive) >= 2:
            return False                   # enough real content → proven
    return True


def log(level: str, msg: str):
    colors = {"ok": G, "err": R, "warn": Y, "info": C, "brain": M, "phase": "\033[0;34m"}
    sym = {"ok": "+", "err": "-", "warn": "!", "info": "*", "brain": "🧠", "phase": "»"}
    col = colors.get(level, "")
    s = sym.get(level, "*")
    print(f"{col}[{s}]{N} {msg}", flush=True)


def pick_model() -> str:
    """Pick the best available Ollama model for active exploit CODE GENERATION.

    v9.23 — this role WRITES and EXECUTES bash/python PoCs, so it needs a CODER.
    The old default aya-expanse:latest is Cohere's MULTILINGUAL chat model (8B,
    8K ctx) — it produced malformed bash that never ran and the loop then
    concluded "NOT VULNERABLE" from its own crash. Demoted to last resort.
    Order: env override -> Devstral (agentic SWE, if pulled) -> installed qwen
    coders. Override with BRAIN_SCANNER_MODEL=<name>.
    """
    import os as _os
    env = _os.environ.get("BRAIN_SCANNER_MODEL", "").strip()
    prov = _os.environ.get("BRAIN_PROVIDER", "").strip().lower()
    # Cloud / non-ollama provider (gemini/openai/claude/grok/mlx): the model name
    # is the BRAIN_SCANNER_MODEL override or the provider's default — no local
    # pull. MLX has no DEFAULT_MODELS entry (the model is loaded internally and
    # the name arg is ignored), so resolve a truthy id from MLX_MODEL/default
    # rather than refusing to start. Provider availability is enforced in
    # run_brain_scanner so a missing key/server fails fast (not an empty loop).
    if prov and prov != "ollama":
        try:
            from brain import LLMClient, MLX_DEFAULT_MODEL
            if prov == "mlx":
                return env or _os.environ.get("MLX_MODEL") or MLX_DEFAULT_MODEL
            return env or LLMClient.DEFAULT_MODELS.get(prov) or ""
        except Exception:
            return env or ""
    try:
        import ollama
        candidates = ([env] if env else []) + [
            "devstral-small-2:24b",        # agentic SWE coder (68% SWE-bench) if pulled
            "qwen2.5-coder:14b",           # installed, fast, purpose-built coder
            "qwen3-coder:30b",             # installed, stronger MoE coder
            "qwen2.5-coder:14b-instruct",
            "bugtraceai-apex",             # security-tuned fallback
            "aya-expanse:latest",          # LAST resort — not a coder
        ]
        for m in candidates:
            if not m:
                continue
            try:
                ollama.show(m)
                return m
            except Exception:
                continue
    except ImportError:
        pass
    return ""


_SCANNER_LLM = None      # cached cloud LLMClient (lazy; honors BRAIN_PROVIDER)
_SCANNER_LLM_SIG = None   # (provider, key-hash) the cached client was built for


def _get_scanner_llm():
    """Lazily build + cache the multi-provider LLM client for cloud providers.

    The cache is keyed to (BRAIN_PROVIDER, hashed API key) so that if either
    changes in a long-lived process we rebuild instead of reusing a client
    bound to the old provider / stale credentials. The key is hashed, never
    stored raw.
    """
    global _SCANNER_LLM, _SCANNER_LLM_SIG
    import os as _os, hashlib as _hashlib
    prov = _os.environ.get("BRAIN_PROVIDER", "").strip().lower()
    key_env = {"gemini": "GEMINI_API_KEY", "openai": "OPENAI_API_KEY",
               "claude": "ANTHROPIC_API_KEY", "grok": "XAI_API_KEY"}.get(prov, "")
    key_val = _os.environ.get(key_env, "") if key_env else ""
    sig = (prov, _hashlib.sha256(key_val.encode()).hexdigest()[:12] if key_val else "")
    if _SCANNER_LLM is None or _SCANNER_LLM_SIG != sig:
        from brain import LLMClient
        _SCANNER_LLM = LLMClient()  # reads BRAIN_PROVIDER + the matching API key
        _SCANNER_LLM_SIG = sig
    return _SCANNER_LLM


def ask_brain(model: str, messages: list[dict], max_tokens: int = 4000) -> str:
    """Send messages to the active LLM provider and get the response.

    Honors BRAIN_PROVIDER: cloud providers (gemini/openai/claude/grok) route
    through brain.LLMClient.chat_messages (full multi-turn history preserved);
    the default is local Ollama with the repetition guards a small local coder
    needs. The S_S_S degeneration guard below is harmless on cloud output.
    """
    import os as _os
    prov = _os.environ.get("BRAIN_PROVIDER", "").strip().lower()
    if prov and prov != "ollama":
        content = _get_scanner_llm().chat_messages(model, messages, max_tokens=max_tokens)
    else:
        import ollama
        resp = ollama.chat(
            model=model,
            messages=messages,
            options={
                "num_predict": max_tokens,
                "num_ctx": _SCANNER_NUM_CTX,  # else the multi-iteration verify loop overflows
                "temperature": 0.1,           # the default ctx → empty responses → aborts the PoC
                "repeat_penalty": 1.3,   # Prevent S_S_S_S degeneration
                "top_p": 0.9,
            },
        )
        content = resp["message"].get("content", "")
    # Detect and truncate repetition loops (model degeneration)
    if "_S_S_S" in content or len(set(content[-200:])) < 10:
        # Find where repetition starts and truncate
        for i in range(len(content) - 100, 0, -100):
            if len(set(content[i:i+100])) < 15:
                content = content[:i].rstrip() + "\n\n[Brain output truncated — repetition detected]"
                break
    return content


def extract_code_blocks(text: str) -> list[dict]:
    """Extract code blocks from LLM response. Returns [{lang, code}, ...]"""
    blocks = []
    # Match ```python ... ``` or ```bash ... ``` or ```sh ... ```
    for match in re.finditer(r'```(python|bash|sh|curl)\n(.*?)```', text, re.DOTALL):
        blocks.append({"lang": match.group(1), "code": match.group(2).strip()})
    # Also match ```\n ... ``` (no language specified — assume bash)
    if not blocks:
        for match in re.finditer(r'```\n(.*?)```', text, re.DOTALL):
            code = match.group(1).strip()
            if code.startswith("#!") or code.startswith("curl") or code.startswith("for "):
                blocks.append({"lang": "bash", "code": code})
            else:
                blocks.append({"lang": "python", "code": code})
    return blocks


def execute_script(lang: str, code: str, timeout: int = MAX_SCRIPT_RUNTIME) -> dict:
    """Execute a code block and capture output.

    v9.23 — validate syntax BEFORE running. The LLM frequently emits malformed
    shell (e.g. an unterminated quote: --data="username=admin'--) which bash
    aborts with "unexpected EOF" having run nothing. Previously that crash was fed
    back as if it were a target result and the model concluded "NOT VULNERABLE"
    from a script that never executed. We now flag syntax errors distinctly
    (``syntax_error: True``) so the caller can force a rewrite instead of treating
    it as evidence — and never partially execute a broken script.

    v10.6.0 — host-gating: refuse (never execute) any script whose target is the
    operator's own machine/listener (loopback / 0.0.0.0 / our bind:port / a local
    interface). RFC1918 / cloud-metadata SSRF targets are still allowed.
    """
    if _scopeguard is None:
        # FAIL CLOSED: without scopeguard we cannot prove the LLM-authored command is
        # not aimed at the operator's own machine/listener, so refuse to execute it.
        # Escape hatch for environments that knowingly run without it.
        if os.environ.get("BRAIN_SCANNER_NO_SCOPEGUARD") != "1":
            return {"stdout": "",
                    "stderr": "SCOPE BLOCKED (not executed): scopeguard module is "
                              "unavailable, so host-scope cannot be enforced. Refusing "
                              "to run LLM-authored code (fail-closed). Set "
                              "BRAIN_SCANNER_NO_SCOPEGUARD=1 to override.",
                    "returncode": 3, "scope_blocked": True}
    else:
        _hit = _scopeguard.scan_command(code)
        if _hit:
            return {"stdout": "",
                    "stderr": f"SCOPE BLOCKED (not executed): target {_hit} is the operator's "
                              f"own machine/listener — out of scope. Point the exploit at the "
                              f"authorized target host instead.",
                    "returncode": 3, "scope_blocked": True}

    if lang in ("bash", "sh", "curl"):
        cmd = ["bash", "-c", code]
        # `bash -n` parses without executing — catches unbalanced quotes / EOF.
        # Fork-safe launch (procutil): plain subprocess.run forks and SIGSEGVs on macOS
        # once Network.framework is loaded (rc=-11). Keep stderr separate so bash's parse
        # error is read from stderr; a syntax-check TIMEOUT is NOT a syntax error.
        try:
            chk = procutil.run_capture(["bash", "-n", "-c", code], timeout=15,
                                       shell=False, merge_stderr=False)
            if not chk.get("timed_out") and chk["returncode"] != 0:
                return {"stdout": "", "stderr": f"SCRIPT SYNTAX ERROR (not executed): "
                                                f"{(chk['stderr'] or chk['stdout']).strip()[:500]}",
                        "returncode": 2, "syntax_error": True}
        except Exception:
            pass
    elif lang == "python":
        cmd = [sys.executable, "-c", code]
        try:
            compile(code, "<brain_script>", "exec")
        except SyntaxError as e:
            return {"stdout": "", "stderr": f"SCRIPT SYNTAX ERROR (not executed): {e}",
                    "returncode": 2, "syntax_error": True}
    else:
        return {"stdout": "", "stderr": f"Unsupported language: {lang}", "returncode": -1}

    # Fork-safe launch (procutil): plain subprocess.run uses fork()+exec, which SIGSEGVs
    # (rc=-11, EMPTY output) on macOS once Network.framework is loaded — that crash made
    # the brain rule REAL findings false positives (e.g. an exposed /db/ SQL dump).
    # posix_spawn does not run the offending pthread_atfork handler. merge_stderr=False
    # keeps the streams SEPARATE so the tooling-error detector (which scans stderr for a
    # script's own traceback) still distinguishes that from a target-returned traceback.
    try:
        result = procutil.run_capture(
            cmd, timeout=timeout, shell=False, merge_stderr=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            cwd=SCRIPT_DIR,
        )
        if result.get("timed_out"):
            return {"stdout": "", "stderr": f"TIMEOUT after {timeout}s", "returncode": -9,
                    "timed_out": True, "timeout": timeout}
        return {
            "stdout": result["stdout"][:5000],  # Cap output (stderr merged into stdout)
            "stderr": result["stderr"][:2000],
            "returncode": result["returncode"],
        }
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def _is_grounded_run(result: dict) -> bool:
    """True only if a script produced REAL stdout evidence about the target.

    A verdict — especially CONFIRMED — may rest only on grounded runs. A script that timed
    out, hit an internal/syntax error, was 'command not found', printed a Python traceback /
    missing-module / 'no such file' (it never really ran), or exited 0 with EMPTY stdout
    produced ZERO target evidence. Counting those let the model fabricate a confident
    CONFIRMED from nothing (observed: a model invented "18 tables / member,admin" after every
    script failed). Genuine tool runs (sqlmap/dalfox/ffuf, sys.exit(1) PoCs) exit NON-ZERO,
    so rc != 0 still grounds a verdict IF real stdout was produced.
    """
    if result.get("syntax_error") or result.get("timed_out"):
        return False
    if result.get("returncode") in (-9, -1, 127):  # timeout / internal / command-not-found
        return False
    err = (result.get("stderr") or "").upper()
    _FAILED_TO_RUN = (
        "TRACEBACK (MOST RECENT CALL LAST)", "MODULENOTFOUNDERROR", "IMPORTERROR",
        "NAMEERROR", "COMMAND NOT FOUND", "NO SUCH FILE OR DIRECTORY",
    )
    if any(m in err for m in _FAILED_TO_RUN):
        return False
    out = (result.get("stdout") or "").strip()
    if not out:
        return False
    # A tool printed only its USAGE/HELP banner (e.g. `curl` with no URL, `sqlmap -h`,
    # `ffuf` with bad args) — that is the tool describing ITSELF, not target evidence.
    # Counting it as grounding let a verdict rest on a help screen.
    if _is_usage_banner(out):
        return False
    return True


_USAGE_BANNER_RE = re.compile(
    r"^\s*(usage:|usage\s|try '.*--help'|"
    r".*--help.*for (more )?(usage|information)|"
    r"options:\s*$|examples:\s*$)", re.I | re.M)


def _is_usage_banner(stdout: str) -> bool:
    """True when stdout looks like a tool's own usage/help banner rather than target
    evidence. Conservative: requires a usage/help cue AND no obvious target signal."""
    s = stdout.strip()
    if not s:
        return False
    if not _USAGE_BANNER_RE.search(s):
        return False
    # If real target signal is present (HTTP status, a URL, an IP, file-content
    # proof), do NOT classify as a mere banner.
    if re.search(r"https?://|HTTP/\d|\b\d{1,3}(?:\.\d{1,3}){3}\b|"
                 r"<html|root:x:0:0:|set-cookie", s, re.I):
        return False
    return True


def _verdict_findings(response: str, grounded: bool) -> list:
    """Findings to record from an ACCEPTED final verdict, so a confirmed result is captured
    in the report (was silently lost as 'Findings: 0' when the severity word and 'CONFIRMED'
    landed on SEPARATE lines).

    A GROUNDED verdict (>=1 script produced real output — guaranteed by the gate that lets a
    CONFIRMED verdict through) is tagged ``[VERIFIED ...]`` so reporter verification-gating
    KEEPS it; an ungrounded one stays ``[MODEL CLAIM ...]`` (the reporter drops those at med+).
    Negated / false-positive lines are skipped. Captures any non-negated line asserting a
    positive verdict even if no severity word shares that line.
    """
    NEG = ("NOT VULNERABLE", "NOT EXPLOITABLE", "NO CRITICAL", "NO HIGH", "NOT CONFIRMED",
           "UNABLE TO CONFIRM", "NOTHING CONFIRMED", "NO VULNERABILIT", "NOT CONFIRM",
           "FALSE POSITIVE")
    POS = ("CONFIRMED", "EXPLOITABLE", "VULNERABLE")
    tag = "[VERIFIED — grounded run]" if grounded else "[MODEL CLAIM — verify PoC]"
    out, seen = [], set()
    for line in response.split("\n"):
        s = line.strip().lstrip("#>*-• ").strip()
        up = s.upper()
        if not s or any(n in up for n in NEG):
            continue
        if any(p in up for p in POS) and s not in seen:
            seen.add(s)
            out.append(f"{tag} {s[:200]}")
    # Positive verdict but no single line carried a positive keyword cleanly → register a
    # summary so a grounded confirmation is never dropped from the report.
    if not out:
        upr = response.upper()
        if any(p in upr for p in POS) and not any(n in upr for n in NEG):
            out.append(f"{tag} Vulnerability CONFIRMED by the brain (see report for grounded evidence)")
    return out[:5]


SYSTEM_PROMPT = """You are an expert penetration tester executing a VAPT engagement.
You have FULL authorization to test the target. Your job is to WRITE and EXECUTE
exploit verification code to confirm or rule out vulnerabilities.

CRITICAL FALSE POSITIVE RULES:
- SPA catch-all: React/Angular/Vue apps serve the SAME index.html for ANY URL path.
  If /.env, /.git/config, /admin etc. return the SAME HTML as the homepage, it is NOT
  a real finding — it's the SPA router. ALWAYS compare response body to the homepage.
  If the body contains "<!doctype html>" with "<div id=\"root\"></div>" or similar SPA
  markers, and is the same as /, it's a false positive.
- HTTP 200 alone does NOT confirm a finding. Check the CONTENT, not just the status code.
- For API testing: test the API base URL (e.g., api.example.com), NOT the frontend SPA host.
- SQL INJECTION FALSE POSITIVES: Django admin login (/admin/login/) shows "errornote" and
  "Please enter the correct username and password" for ANY wrong credentials. This is NOT
  a SQL error. A real SQL error contains: "syntax error", "psycopg2", "sqlite3.OperationalError",
  "ProgrammingError", "relation does not exist", "column", "ORA-". Response size changes of
  <100 bytes between payloads are usually just the injected string being reflected, NOT SQLi.
  Django uses parameterized queries (ORM) — its admin login is NOT vulnerable to SQLi by default.

RULES:
1. Write COMPLETE, RUNNABLE scripts (Python 3 or bash/curl).
2. Each script must be self-contained — include all imports, handle errors.
3. Output CLEAR verdicts: "CONFIRMED", "NOT VULNERABLE", or "NEEDS MORE TESTING".
4. Include timing comparisons, response diffs, or other concrete evidence.
5. Use `requests` library for Python HTTP. Use `curl` for bash.
6. Always add `verify=False` for HTTPS and suppress InsecureRequestWarning.
7. Print structured output — timestamps, HTTP codes, response sizes, timing.
8. Never use destructive payloads (DROP TABLE, rm -rf, etc.).
9. Test ONE vulnerability per script. Be methodical.
10. After seeing results, decide: write another test, or give final verdict.

OUTPUT FORMAT:
- Explain what you're testing and why
- Write the test script in a ```python or ```bash code block
- After seeing results, analyze and decide next step

Available tools on this system: curl, python3, requests, sqlmap, nuclei, ffuf, dalfox

MANDATORY — YOU MUST USE THESE TOOLS. DO NOT WRITE CUSTOM SQLi/XSS SCRIPTS:

*** SQL Injection: YOU MUST USE sqlmap. NEVER write custom boolean/time-based Python. ***
Write a ```bash block with:
  sqlmap -u "URL" --data="param1=value1&param2=value2" --batch --level=3 --risk=2 --current-db --dbs --random-agent
If you need cookies:
  sqlmap -u "URL" --data="params" --cookie="name=value" --batch --level=3 --risk=2 --current-db
sqlmap is 100x better than any custom script at SQLi. It handles WAF bypass, encoding,
tamper scripts, time/boolean/union/error/stacked injection. DO NOT reinvent this.

*** XSS: YOU MUST USE dalfox. NEVER write custom XSS reflection checks. ***
Write a ```bash block with:
  echo "URL?param=test" | dalfox pipe --silence --skip-bav
  dalfox url "URL?param=test" --silence

*** CVEs/Misconfig: YOU MUST USE nuclei. ***
  nuclei -u "URL" -severity critical,high,medium -silent
  nuclei -u "URL" -tags sqli,xss,lfi,rce,ssrf -silent

*** Directory discovery: USE ffuf — wordlists SHIP IN THIS REPO (paths are relative to cwd);
    /usr/share/seclists is NOT installed here, so do NOT use it (ffuf will error on a missing list) ***
  ffuf -u "URL/FUZZ" -w wordlists/common.txt -mc 200,301,302,403
  (other lists: wordlists/api-endpoints.txt, wordlists/high_value_paths.txt, wordlists/lfi.txt)
  For a KNOWN path/file already named by recon, do NOT ffuf — just `curl` it directly and show the bytes.

ONLY use custom Python for: IDOR (iterating IDs), business logic, timing oracles,
CSRF token analysis, file upload content crafting, session manipulation.
If you find yourself writing "requests.post" with SQL payloads, STOP and use sqlmap instead.

Directory/file discovery → ffuf (use the repo wordlists, NOT /usr/share/seclists which is absent):
  ffuf -u "URL/FUZZ" -w wordlists/common.txt -mc 200,301,302,403

SSTI → use Python requests with math canary payloads:
  {{7*7}} → if response contains "49", SSTI confirmed
  ${7*7} → Freemarker/Thymeleaf variant

IDOR → use Python requests to iterate IDs and compare responses.

ONLY write custom Python for: IDOR testing, business logic, timing oracles,
token analysis, and tests where no specialized tool exists.
"""

SPA_WARNING = """
IMPORTANT — SPA FALSE POSITIVE DETECTION:
React/Angular/Vue apps return the SAME HTML (index.html) for ANY URL path via catch-all routing.
If /.env, /.git/config, /admin return HTML containing "<div id=\\"root\\"></div>" or
"<div id=\\"app\\"></div>", it is NOT a real finding. ALWAYS compare to homepage content.
For SPA targets, test the API backend (e.g., api.example.com), not the frontend host.
"""

CODE_AUDIT_PROMPT = """You are an elite code auditor and exploit developer on an authorized VAPT engagement.
You have FULL authorization. Your job is to READ source code, FIND vulnerabilities,
and WRITE working exploit PoCs.

WORKFLOW:
1. First, FETCH the source code (via curl, LFI, RCE foothold, or accessible URLs).
2. READ the code carefully. Understand the logic, control flow, and data flow.
3. IDENTIFY security flaws: logic bugs, injection sinks, auth bypasses, race conditions,
   type confusion, OR-vs-AND errors, missing validation, unsafe deserialization.
4. For EACH flaw found, WRITE a working PoC script that exploits it.
5. EXECUTE the PoC against the live target.
6. Report: vulnerable code snippet, root cause, PoC, and remediation.

CODE ANALYSIS PATTERNS TO CHECK:
- OR vs AND in validation (if mime_ok OR ext_ok → should be AND)
- Client-controlled values used in server-side decisions (Content-Type, filenames)
- Session tokens that are deterministic or reusable (not per-request)
- Hardcoded secrets, passwords, API keys in source
- SQL queries built with string concatenation
- eval(), exec(), system(), passthru() with user input
- File operations with user-controlled paths (LFI/RFI/upload)
- Crypto using weak algorithms (MD5, DES, ECB mode)
- Race conditions in check-then-act patterns
- Missing access control (function-level, object-level)
- extract($_GET/$_POST) — register_globals equivalent

When analyzing a "fix":
- Read the EXACT code the developer deployed
- Compare against the vulnerability description
- Find the specific line(s) that should prevent the attack
- Test if the fix can be bypassed (encoding, alternate paths, edge cases)
- Write the bypass PoC

RULES:
1. Write COMPLETE, RUNNABLE scripts (Python 3 or bash/curl).
2. Each script must be self-contained — include all imports, handle errors.
3. Use `requests` library for Python HTTP. Use `curl` for bash.
4. Always add `verify=False` for HTTPS and suppress InsecureRequestWarning.
5. Never use destructive payloads (DROP TABLE, rm -rf, etc.).
6. Print the vulnerable code snippet with line numbers.
7. Clearly mark: BYPASS FOUND or FIX IS EFFECTIVE.

OUTPUT FORMAT:
- Show the vulnerable code
- Explain the flaw
- Write the exploit/bypass in a ```python or ```bash code block
- After execution, give verdict
"""

VERIFY_FIX_PROMPT = """You are an elite penetration tester verifying a developer's security fix.
You have FULL authorization. The developer CLAIMS they fixed a vulnerability.
Your job is to PROVE whether the fix actually works or can be bypassed.

YOUR APPROACH:
1. UNDERSTAND the original vulnerability (what was broken and how).
2. FETCH the current code — read the actual fix deployed on the server.
   - Try: direct URL access, JS bundles, error pages that leak code,
     LFI if available, RCE foothold if available, or .bak/.old files.
3. ANALYZE the fix — identify exactly what changed and what remains.
4. FIND BYPASSES — test every possible way around the fix:
   - Encoding bypasses (URL encoding, double encoding, Unicode)
   - Alternate input paths (different parameter names, HTTP methods, headers)
   - Logic flaws in the fix itself (OR vs AND, off-by-one, race conditions)
   - Incomplete fixes (fixed one endpoint but not others)
   - Client-side vs server-side validation mismatch
5. WRITE and EXECUTE bypass PoCs.
6. VERDICT: "FIX IS EFFECTIVE" or "FIX BYPASSED — STILL VULNERABLE"

COMMON FIX FAILURES:
- Blocklist instead of allowlist (attacker finds unlisted extension)
- Client-side validation only (bypass with curl/Burp)
- OR logic: if(mime_ok OR ext_ok) — set fake MIME to bypass ext check
- Checking wrong field (checking Content-Type header instead of actual file bytes)
- Not normalizing before checking (double extensions: .php.jpg, null bytes: .php%00.jpg)
- Fix applied to one code path but not another (upload via API vs upload via form)
- Token validation that's session-scoped not request-scoped (CSRF)
- Rate limiting on frontend but not backend

RULES:
1. Write COMPLETE, RUNNABLE scripts (Python 3 or bash/curl).
2. Always try to READ the actual source code of the fix first.
3. Test at least 3 bypass techniques per fix.
4. Use `verify=False` for HTTPS and suppress InsecureRequestWarning.
5. Never use destructive payloads.
6. Show: original vuln → claimed fix → your bypass → verdict.
"""


def run_brain_scanner(target: str, briefing: str = "", cookies: str = "",
                      output_dir: str = None, max_iterations: int = MAX_ITERATIONS,
                      mode: str = "scan", fix_claim: str = "",
                      code_url: str = "", code_file: str = ""):
    """Main brain scanner loop.

    Modes:
      scan       — general vulnerability scanning (default)
      verify-fix — developer claims fix, brain reads code and finds bypasses
      audit-code — feed source code, brain finds vulns and writes PoCs
    """
    model = pick_model()
    if not model:
        _prov = os.environ.get("BRAIN_PROVIDER", "").strip().lower() or "ollama"
        if _prov == "ollama":
            log("err", "No Ollama model available (pull a coder, e.g. ollama pull qwen2.5-coder:14b)")
        else:
            log("err", f"No model available for provider '{_prov}' "
                       f"(set BRAIN_SCANNER_MODEL or check the API key)")
        return

    # Fail fast: a non-ollama provider with no API key / unloadable backend would
    # otherwise log a model name and then loop on empty responses for every
    # iteration. Verify the client is actually usable before doing any work.
    _prov = os.environ.get("BRAIN_PROVIDER", "").strip().lower()
    if _prov and _prov != "ollama":
        if not _get_scanner_llm().available:
            log("err", f"Provider '{_prov}' selected but not available — "
                       f"check the API key (e.g. GEMINI_API_KEY) or backend")
            return

    log("brain", f"Model: {model}")
    log("info", f"Target: {target}")
    log("info", f"Mode: {mode}")
    if cookies:
        log("info", f"Cookies: {cookies[:50]}...")

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Select system prompt based on mode
    if mode == "verify-fix":
        system_prompt = VERIFY_FIX_PROMPT
    elif mode == "audit-code":
        system_prompt = CODE_AUDIT_PROMPT
    else:
        system_prompt = SYSTEM_PROMPT

    # Build initial briefing based on mode
    if mode == "verify-fix" and not briefing:
        # Fetch the code if URL provided
        code_content = ""
        if code_url:
            log("info", f"Fetching code from: {code_url}")
            fetch_result = execute_script("bash",
                f'curl -sk "{code_url}" --max-time 15')
            code_content = fetch_result["stdout"]

        briefing = f"""TARGET: {target}
COOKIES: {cookies or '(none)'}

DEVELOPER'S CLAIM: {fix_claim}

{'CODE URL: ' + code_url if code_url else ''}
{'FETCHED CODE:' + chr(10) + code_content[:8000] if code_content else 'No code URL provided — you need to find and read the code yourself.'}

YOUR TASK:
1. Read the actual code that implements the "fix"
2. Understand what the developer changed
3. Find bypasses — test OR-vs-AND logic, encoding tricks, alternate paths
4. Write PoC scripts that prove the fix works or doesn't
5. If you can't access the code directly, try:
   - Fetch the file via the target URL
   - Check for .bak, .old, .swp, ~ backup files
   - Trigger verbose error messages that leak code
   - Check JS bundles for client-side validation logic
   - Use any existing RCE/LFI to read server-side code"""

    elif mode == "audit-code" and not briefing:
        code_content = ""
        if code_file and os.path.isfile(code_file):
            with open(code_file, "r") as f:
                code_content = f.read()[:15000]
            log("info", f"Loaded {len(code_content)} chars from {code_file}")
        elif code_url:
            log("info", f"Fetching code from: {code_url}")
            fetch_result = execute_script("bash",
                f'curl -sk "{code_url}" --max-time 15')
            code_content = fetch_result["stdout"]

        briefing = f"""TARGET: {target}
COOKIES: {cookies or '(none)'}

SOURCE CODE TO AUDIT:
```
{code_content[:15000]}
```

YOUR TASK:
1. Read this code carefully line by line
2. Identify ALL security vulnerabilities (injection, auth bypass, logic flaws, crypto issues, etc.)
3. For each vulnerability found:
   a. Show the vulnerable code snippet with line numbers
   b. Explain the root cause
   c. Write a working PoC exploit script
   d. Execute the PoC against the live target
   e. Give remediation advice
4. After testing all findings, give a FINAL ASSESSMENT"""

    elif not briefing:
        # Auto-fingerprint the target
        log("info", "Auto-fingerprinting target...")
        fp_result = execute_script("bash", f'curl -sk -D- "{target}" -o /tmp/brain_fp.html --max-time 15 && head -50 /tmp/brain_fp.html')

        # Load existing upload/file-type evasion findings if available
        upload_findings_brief = ""
        try:
            target_slug = target.replace("https://", "").replace("http://", "").replace("/", "_")
            findings_base = os.path.join(SCRIPT_DIR, "findings", target_slug)
            matrix_candidates = []
            for root, _dirs, files in os.walk(findings_base):
                for fn in files:
                    if fn == "upload_evasion_matrix.json":
                        matrix_candidates.append(os.path.join(root, fn))
            if matrix_candidates:
                # Use the most recent matrix
                matrix_path = sorted(matrix_candidates)[-1]
                with open(matrix_path) as mf:
                    matrix = json.load(mf)
                bypassed = [r for r in matrix if r.get("result") == "VULN"]
                blocked = [r for r in matrix if r.get("result") == "SAFE" and r.get("upload_ok")]
                if bypassed or blocked:
                    upload_findings_brief = "\n\nFILE UPLOAD EVASION RESULTS (from Phase 6b):\n"
                    if bypassed:
                        upload_findings_brief += f"  BYPASSED ({len(bypassed)}):\n"
                        for b in bypassed[:5]:
                            upload_findings_brief += (
                                f"    - {b['technique']}: {b['filename']} → {b['true_type']}\n"
                            )
                    if blocked:
                        upload_findings_brief += f"  BLOCKED ({len(blocked)}):\n"
                        for b in blocked[:3]:
                            upload_findings_brief += (
                                f"    - {b['technique']}: {b['filename']}\n"
                            )
                    upload_findings_brief += (
                        "\nUse this data to craft ADDITIONAL evasion payloads. "
                        "If .php was blocked but .phtml or .pht wasn't tested, try those. "
                        "If magic byte prepend worked for GIF, try PNG/JPEG polyglots too.\n"
                    )
        except Exception:
            pass

        briefing = f"""TARGET: {target}
COOKIES: {cookies or '(none — unauthenticated scan)'}

FINGERPRINT (headers + first 50 lines):
{fp_result['stdout'][:3000]}
{upload_findings_brief}
TASK: Perform a comprehensive vulnerability assessment. Test for:
1. XSS (reflected, stored, DOM-based)
2. SQL injection (error-based, time-based, boolean-based)
3. CSRF (check if tokens are per-request or session-scoped)
4. Authentication flaws (brute force, OTP bypass, username enumeration)
5. Information disclosure (error messages, version leaks, directory listing)
6. Rate limiting on sensitive endpoints
7. Session management issues
8. File upload bypass (try polyglot files, double extensions, MIME mismatch)

Start with reconnaissance — find forms, parameters, JS files, API endpoints.
Then test the most promising attack vectors."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": briefing},
    ]

    findings = []
    iteration = 0
    successful_runs = 0   # scripts that actually executed (no syntax/tooling error)
    empty_streak = 0      # consecutive empty provider responses (see MAX_EMPTY_STREAK)

    mode_labels = {
        "scan": "Active LLM-Driven Vulnerability Testing",
        "verify-fix": "Fix Verification — Does the patch actually work?",
        "audit-code": "Code Audit — Find vulns, write PoCs",
    }
    print(f"\n{M}{'═' * 60}{N}")
    print(f"{M}  BRAIN SCANNER — {mode_labels.get(mode, mode)}{N}")
    print(f"{M}{'═' * 60}{N}\n")

    while iteration < max_iterations:
        iteration += 1
        print(f"\n{B}{'─' * 60}{N}")
        print(f"{B}  Iteration {iteration}/{max_iterations}{N}")
        print(f"{B}{'─' * 60}{N}\n")

        # Ask brain for next test
        log("brain", "Thinking...")
        response = ask_brain(model, messages)

        # Guard: a usable-looking but non-functional provider (revoked / over-quota
        # key, invalid model name, network failure) makes ask_brain return "" every
        # time. Abort after a short streak instead of burning all iterations on
        # empty output. The startup availability gate only checks local config, not
        # a live call, so this catches what the gate cannot.
        if not (response or "").strip():
            empty_streak += 1
            log("warn", f"Brain returned an empty response [{empty_streak}/{MAX_EMPTY_STREAK}]")
            if empty_streak >= MAX_EMPTY_STREAK:
                log("err", "Provider returned empty responses repeatedly — aborting. "
                           "Check the API key validity, quota/billing, and model name.")
                break
            continue
        empty_streak = 0

        # Display brain's reasoning
        # Print non-code parts
        parts = re.split(r'```(?:python|bash|sh|curl)?\n.*?```', response, flags=re.DOTALL)
        for i, part in enumerate(parts):
            part = part.strip()
            if part:
                for line in part.split('\n'):
                    print(f"  {D}{line}{N}")

        # Extract and execute code blocks
        code_blocks = extract_code_blocks(response)

        if not code_blocks:
            # Brain didn't write code — check if it's giving a final verdict
            if any(kw in response.upper() for kw in ["CONFIRMED", "VERDICT:", "FINAL ASSESSMENT", "SUMMARY OF FINDINGS"]):
                # v9.23 — refuse a final verdict that rests on ZERO successful tests.
                # The model used to declare "NOT VULNERABLE" right after its only
                # script died with a syntax error — concluding from a run that never
                # happened. Require at least one script to have actually executed.
                if successful_runs == 0:
                    log("warn", "Verdict rejected — no script has executed successfully yet "
                                "(a script/syntax error is NOT evidence about the target)")
                    messages.append({"role": "assistant", "content": response})
                    messages.append({"role": "user", "content":
                        "You have not run a single SUCCESSFUL test yet — every script so far "
                        "failed to execute (syntax/tooling error), which tells us NOTHING about "
                        "the target's security. Do NOT issue a verdict. Write a corrected, "
                        "self-contained script (mind your quotes) in a ```bash or ```python "
                        "block so it actually runs."})
                    continue
                log("ok", "Brain issued final verdict")
                # Record the verdict so the report captures it. The gate above guarantees
                # successful_runs>0 here, so a positive verdict is GROUNDED → tagged
                # [VERIFIED ...] (reporter keeps it); negated/FP lines are skipped. Fixes the
                # bug where a grounded confirmation vanished as 'Findings: 0' because the
                # severity word and 'CONFIRMED' landed on separate lines.
                findings.extend(_verdict_findings(response, grounded=successful_runs > 0))
                break
            else:
                # Ask brain to write code
                messages.append({"role": "assistant", "content": response})
                messages.append({"role": "user", "content": "Write a test script. Include it in a ```python or ```bash code block. I will execute it and show you the results."})
                continue

        messages.append({"role": "assistant", "content": response})

        # Execute each code block
        all_results = ""
        for i, block in enumerate(code_blocks):
            lang, code = block["lang"], block["code"]
            log("phase", f"Executing {lang} script ({len(code)} chars)...")

            # Show the code
            print(f"\n  {C}┌─ {lang} script ─────────────────────────────────{N}")
            for line in code.split('\n')[:30]:
                print(f"  {C}│{N} {line}")
            if code.count('\n') > 30:
                print(f"  {C}│{N} ... ({code.count(chr(10)) - 30} more lines)")
            print(f"  {C}└─────────────────────────────────────────────────{N}\n")

            # The SYSTEM_PROMPT mandates sqlmap --level/--risk, full-severity nuclei,
            # and ffuf fuzzing — all of which routinely run for minutes. The 60s
            # default kills them mid-run, so scale the budget when a long tool is
            # invoked. Recon curls self-cap (--max-time 15) and stay on the default.
            long_tools = ("sqlmap", "nuclei", "ffuf", "feroxbuster", "gobuster", "dalfox")
            tmo = 600 if any(t in code for t in long_tools) else MAX_SCRIPT_RUNTIME
            result = execute_script(lang, code, timeout=tmo)

            # Show results
            if result["stdout"]:
                print(f"  {G}┌─ stdout ──────────────────────────────────────{N}")
                for line in result["stdout"].split('\n')[:40]:
                    print(f"  {G}│{N} {line}")
                print(f"  {G}└──────────────────────────────────────────────{N}")

            if result["stderr"] and result["returncode"] != 0:
                print(f"  {R}┌─ stderr ──────────────────────────────────────{N}")
                for line in result["stderr"].split('\n')[:10]:
                    print(f"  {R}│{N} {line}")
                print(f"  {R}└──────────────────────────────────────────────{N}")

            all_results += f"\n=== Script {i+1} ({lang}) — exit code {result['returncode']} ===\n"
            if result.get("syntax_error"):
                # Make it unmistakable that this is a SCRIPT defect, not a target result.
                all_results += ("SCRIPT DID NOT RUN — shell/python SYNTAX ERROR in YOUR script "
                                "(e.g. an unterminated quote). This is NOT evidence about the "
                                "target. Rewrite the script correctly and try again.\n")
                all_results += f"STDERR:\n{result['stderr']}\n"
            elif result.get("timed_out"):
                # A timeout TRUNCATED the test — it is NOT a negative result about the
                # target. Tell the model so it never reads an empty/partial stdout as
                # "not vulnerable", and steer it to a narrower scope.
                all_results += (f"SCRIPT TIMED OUT after {result.get('timeout', tmo)}s — the test "
                                "was TRUNCATED, NOT a negative result. Narrow the scope (single "
                                "param / fewer templates / one URL) or it ran out of budget.\n")
                all_results += f"STDERR:\n{result['stderr']}\n"
            else:
                all_results += f"STDOUT:\n{result['stdout']}\n"
                if result["stderr"]:
                    all_results += f"STDERR:\n{result['stderr']}\n"
                # A script that ran (rc 0, or non-zero but not a syntax error) counts
                # as a real test the model may reason from. Exclude TIMEOUT (-9) and
                # internal/tooling errors (-1), which did NOT produce target evidence.
                # Also exclude RUNTIME tooling failures (Python traceback / missing
                # module / command-not-found): these "ran" but produced zero target
                # evidence, so they must not satisfy the gate that lets the model
                # issue a final verdict after no real testing.
                # (sys.exit(1) PoCs, grep/curl --fail pipelines, sqlmap/dalfox/ffuf all
                #  exit non-zero on a genuine run, so rc != 0 must still count.)
                # A run only GROUNDS a verdict if it produced REAL stdout evidence — an
                # empty / failed-to-run / usage-dump script proves nothing, so it must NOT
                # let the model issue a CONFIRMED verdict on no evidence (anti-fabrication
                # gate; the verdict logic below refuses to finish while successful_runs==0).
                if _is_grounded_run(result):
                    successful_runs += 1
                # Grounded findings: only from ACTUAL script stdout. Plain substring
                # matching records negative lines ("NOT VULNERABLE", "No critical ...")
                # as findings — skip any line carrying a negation marker. Markers are
                # kept narrow and unambiguous: broad phrases like "NOT FOUND" / "NO
                # ISSUES" / "NOT AFFECTED" were dropped because they can appear inside
                # a genuinely-confirming stdout line (e.g. "EXPLOITABLE: creds NOT
                # FOUND but RCE works") and would silently suppress a real finding.
                NEG_MARKERS = ("NOT VULNERABLE", "NOT EXPLOITABLE", "NOT VULN", "NO CRITICAL",
                               "0 CRITICAL", "NO VULNERABILIT", "NOT INJECTABLE")
                _unproven_access = False
                for line in result["stdout"].split('\n'):
                    up = line.upper()
                    if any(kw in up for kw in ["VULNERABLE", "CONFIRMED", "CRITICAL", "EXPLOITABLE"]) \
                       and not any(neg in up for neg in NEG_MARKERS):
                        # Reject a self-declared file-access/traversal claim that the
                        # script output does not actually PROVE (no file content) — a
                        # buggy PoC (`echo "...accessible" || echo`) prints it whether
                        # or not the read succeeded. Don't record it as a finding.
                        # Use the GENERALIZED gate so a grounded read of a non-passwd
                        # file (source/YAML/hosts) is KEPT at this primary path, not
                        # dropped before it reaches findings (it printed real content).
                        if _grounded_read_unproven(line, result["stdout"]):
                            _unproven_access = True
                            log("warn", f"Rejected unproven access claim (no file "
                                        f"content in output): {line.strip()[:80]}")
                            continue
                        findings.append(line.strip())
                if _unproven_access:
                    all_results += (
                        "\nNOTE: a file-access/traversal claim was printed WITHOUT the "
                        "retrieved file content as proof, so it was NOT accepted as a "
                        "finding. A real read must print the actual content (e.g. the "
                        "`root:x:0:0:` line from /etc/passwd). Re-test and show the file "
                        "content to confirm, or drop the claim. Note that `echo X || echo Y` "
                        "does NOT make X conditional — echo always succeeds.\n")

        # Feed results back to brain
        had_syntax_error = any(b for b in code_blocks) and "SCRIPT DID NOT RUN" in all_results
        guidance = ("Analyze these results. If a script DID NOT RUN due to a syntax error, that is "
                    "NOT a finding — fix the script and re-run it. " if had_syntax_error else
                    "Analyze these results. ")
        messages.append({
            "role": "user",
            "content": f"Here are the execution results:\n\n{all_results}\n\n{guidance}"
                       "If you genuinely confirmed a vulnerability via script OUTPUT, document it "
                       "with CONFIRMED status. If you need more testing, write the next test script. "
                       "Only give a FINAL ASSESSMENT once at least one script has actually executed."
        })

        # Trim context if getting long (keep system + last 10 messages)
        if len(messages) > 22:
            messages = messages[:1] + messages[-20:]

        # Save progress
        if output_dir:
            with open(os.path.join(output_dir, f"iteration_{iteration:02d}.json"), "w") as f:
                json.dump({
                    "iteration": iteration,
                    "brain_response": response,
                    "code_blocks": code_blocks,
                    "results": all_results,
                    "findings_so_far": findings,
                }, f, indent=2)

    # Final summary
    print(f"\n{M}{'═' * 60}{N}")
    print(f"{M}  BRAIN SCANNER COMPLETE{N}")
    print(f"{M}{'═' * 60}{N}")
    print(f"  Iterations: {iteration}")
    print(f"  Findings:   {len(findings)}")
    for f in findings:
        print(f"    {R}•{N} {f}")
    print(f"{M}{'═' * 60}{N}\n")

    # Save final report
    if output_dir:
        with open(os.path.join(output_dir, "brain_scanner_report.md"), "w") as f:
            f.write(f"# Brain Scanner Report\n\n")
            f.write(f"**Target:** {target}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"**Model:** {model}\n")
            f.write(f"**Iterations:** {iteration}\n\n")
            f.write(f"## Findings\n\n")
            for finding in findings:
                f.write(f"- {finding}\n")
            f.write(f"\n## Full Conversation\n\n")
            for msg in messages:
                f.write(f"### {msg['role'].upper()}\n\n{msg['content']}\n\n---\n\n")
        log("ok", f"Report saved: {output_dir}/brain_scanner_report.md")

    return findings


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(
        description="Brain Scanner — LLM writes and executes exploit verification code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  (default)     General vulnerability scanning
  --verify-fix  Developer claims fix → brain reads code, finds bypasses
  --audit-code  Feed source code → brain finds vulns and writes PoCs

Examples:
  # General scan
  python3 brain_scanner.py --target https://example.com

  # Verify a developer's fix claim
  python3 brain_scanner.py --target https://example.com --verify-fix \\
      --fix-claim "File upload now blocks .phtml extensions" \\
      --code-url "https://example.com/scriptsNew/fileUpload-action.phtml"

  # Audit source code from a file
  python3 brain_scanner.py --target https://example.com --audit-code \\
      --code-file /path/to/source.php

  # Audit source code from a URL (e.g., exposed via LFI/RCE)
  python3 brain_scanner.py --target https://example.com --audit-code \\
      --code-url "https://example.com/vulnerable.php"
        """)
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--briefing", default="", help="Custom briefing/instructions for the brain")
    parser.add_argument("--cookies", default="", help="Session cookies (key=val; key2=val2)")
    parser.add_argument("--output", default="", help="Output directory")
    parser.add_argument("--iterations", type=int, default=MAX_ITERATIONS, help="Max iterations")

    # Mode flags
    parser.add_argument("--verify-fix", action="store_true",
                        help="Fix verification mode — developer claims they fixed a vuln")
    parser.add_argument("--audit-code", action="store_true",
                        help="Code audit mode — analyze source code for vulnerabilities")

    # Code access
    parser.add_argument("--fix-claim", default="",
                        help="What the developer claims they fixed (for --verify-fix)")
    parser.add_argument("--code-url", default="",
                        help="URL to fetch source code from (accessible file, LFI, etc.)")
    parser.add_argument("--code-file", default="",
                        help="Local file path containing source code to audit")
    args = parser.parse_args()

    # Determine mode
    if args.verify_fix:
        mode = "verify-fix"
    elif args.audit_code:
        mode = "audit-code"
    else:
        mode = "scan"

    output_dir = args.output or os.path.join(
        SCRIPT_DIR, "recon", args.target.replace("https://", "").replace("http://", "").replace("/", "_"),
        "brain_scanner", datetime.now().strftime("%Y%m%d_%H%M%S"))

    run_brain_scanner(
        target=args.target,
        briefing=args.briefing,
        cookies=args.cookies,
        output_dir=output_dir,
        max_iterations=args.iterations,
        mode=mode,
        fix_claim=args.fix_claim,
        code_url=args.code_url,
        code_file=args.code_file,
    )


if __name__ == "__main__":
    main()

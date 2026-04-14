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

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

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


def log(level: str, msg: str):
    colors = {"ok": G, "err": R, "warn": Y, "info": C, "brain": M, "phase": "\033[0;34m"}
    sym = {"ok": "+", "err": "-", "warn": "!", "info": "*", "brain": "🧠", "phase": "»"}
    col = colors.get(level, "")
    s = sym.get(level, "*")
    print(f"{col}[{s}]{N} {msg}", flush=True)


def pick_model() -> str:
    """Pick the best available Ollama model for security tasks.

    Priority: bugtraceai-apex (security-tuned, <thinking> blocks, 0% refusal)
    Fallback: gemma4:26b (fast all-rounder)
    """
    try:
        import ollama
        for m in ["bugtraceai-apex", "gemma4:26b", "qwen3:14b", "qwen3:8b", "gemma4:e4b"]:
            try:
                ollama.show(m)
                return m
            except Exception:
                continue
    except ImportError:
        pass
    return ""


def ask_brain(model: str, messages: list[dict], max_tokens: int = 4000) -> str:
    """Send messages to Ollama and get response."""
    import ollama
    resp = ollama.chat(
        model=model,
        messages=messages,
        options={
            "num_predict": max_tokens,
            "temperature": 0.1,
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
    """Execute a code block and capture output."""
    if lang in ("bash", "sh", "curl"):
        cmd = ["bash", "-c", code]
    elif lang == "python":
        cmd = [sys.executable, "-c", code]
    else:
        return {"stdout": "", "stderr": f"Unsupported language: {lang}", "returncode": -1}

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            cwd=SCRIPT_DIR,
        )
        return {
            "stdout": result.stdout[:5000],  # Cap output
            "stderr": result.stderr[:2000],
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"TIMEOUT after {timeout}s", "returncode": -9}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


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
        log("err", "No Ollama model available")
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
        briefing = f"""TARGET: {target}
COOKIES: {cookies or '(none — unauthenticated scan)'}

FINGERPRINT (headers + first 50 lines):
{fp_result['stdout'][:3000]}

TASK: Perform a comprehensive vulnerability assessment. Test for:
1. XSS (reflected, stored, DOM-based)
2. SQL injection (error-based, time-based, boolean-based)
3. CSRF (check if tokens are per-request or session-scoped)
4. Authentication flaws (brute force, OTP bypass, username enumeration)
5. Information disclosure (error messages, version leaks, directory listing)
6. Rate limiting on sensitive endpoints
7. Session management issues

Start with reconnaissance — find forms, parameters, JS files, API endpoints.
Then test the most promising attack vectors."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": briefing},
    ]

    findings = []
    iteration = 0

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
                log("ok", "Brain issued final verdict")
                # Extract findings
                for line in response.split('\n'):
                    if any(sev in line.upper() for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
                        findings.append(line.strip())
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

            result = execute_script(lang, code)

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
            all_results += f"STDOUT:\n{result['stdout']}\n"
            if result["stderr"]:
                all_results += f"STDERR:\n{result['stderr']}\n"

            # Check for findings in output
            for line in result["stdout"].split('\n'):
                if any(kw in line.upper() for kw in ["VULNERABLE", "CONFIRMED", "CRITICAL", "EXPLOITABLE"]):
                    findings.append(line.strip())

        # Feed results back to brain
        messages.append({
            "role": "user",
            "content": f"Here are the execution results:\n\n{all_results}\n\nAnalyze these results. If you found a vulnerability, document it clearly with CONFIRMED status. If you need more testing, write the next test script. If you've tested enough, give your FINAL ASSESSMENT with all findings."
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

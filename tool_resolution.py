"""Resolve healthy assessment executables consistently for Python and Bash.

Only local, bounded identity probes are performed. A healthy Go installation
keeps its precedence; crashed or shadowed binaries fall back to a healthy keg or
later PATH entry. Importing this module never launches a process.
"""
from __future__ import annotations

import argparse
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from urllib.parse import urlsplit


PD_TOOLS = ("httpx", "dnsx", "nuclei", "katana")
RESOLVABLE_TOOLS = PD_TOOLS + ("gf",)
GF_PATTERNS = ("xss", "sqli", "ssrf", "lfi", "redirect", "rce", "idor", "cors")
BREW_PREFIXES = ("/opt/homebrew", "/usr/local")
VERSION_TIMEOUT = 20
GF_TIMEOUT = 30


def env_key(name: str) -> str:
    return f"VIK_{name.upper()}_BIN"


def candidate_paths(name: str, *, preferred: str | None = None,
                    env=None, gobin: str | None = None) -> list[str]:
    """Enumerate explicit, Go, keg and ALL PATH candidates without executing."""
    if name not in RESOLVABLE_TOOLS:
        raise ValueError(f"unsupported health-checked tool: {name}")
    env = os.environ if env is None else env
    gobin = gobin or os.path.join(os.path.expanduser("~"), "go", "bin")
    paths = [env.get(env_key(name), ""), preferred or "", os.path.join(gobin, name)]
    paths.extend(os.path.join(prefix, "opt", name, "bin", name) for prefix in BREW_PREFIXES)
    paths.extend(os.path.join(part, name) for part in env.get("PATH", "").split(os.pathsep) if part)
    unique = []
    seen = set()
    for path in paths:
        if not path:
            continue
        path = os.path.abspath(os.path.expanduser(path))
        # A keg and its bin symlink may identify the same executable. Probe once.
        identity = os.path.realpath(path)
        if identity not in seen:
            seen.add(identity)
            unique.append(path)
    return unique


def _local_version(path: str):
    # The shared launcher avoids macOS Network.framework's unsafe fork path.
    from procutil import run_capture
    result = run_capture([path, "-version"], timeout=VERSION_TIMEOUT, shell=False)
    if result.get("timed_out"):
        raise subprocess.TimeoutExpired(path, VERSION_TIMEOUT)
    return result.get("returncode"), (result.get("stdout") or "") + (result.get("stderr") or "")


def _gf_capture(argv, *, input_path=None):
    """Run local gf without unsafe fork or mixing stderr into URL output."""
    from procutil import run_capture
    if input_path is None:
        return run_capture(argv, timeout=GF_TIMEOUT, shell=False, merge_stderr=False)
    # procutil deliberately defaults stdin to /dev/null. A quoted redirection
    # supplies the URL file without changing its fork-safe process-group cleanup.
    command = " ".join(shlex.quote(str(arg)) for arg in argv)
    command += " < " + shlex.quote(str(input_path))
    return run_capture(command, timeout=GF_TIMEOUT, merge_stderr=False)


def _check_gf(path: str, *, runner=None) -> str | None:
    # Homebrew's `gf` is the unrelated GoFrame CLI. A filename or exit 0 is
    # insufficient; tomnomnom gf exposes these Go flags, on stderr with -h.
    try:
        if runner is None:
            result = _gf_capture([path, "-h"])
            rc = result.get("returncode")
            output = (result.get("stdout") or "") + (result.get("stderr") or "")
            timed_out = result.get("timed_out")
        else:
            result = runner([path, "-h"], capture_output=True, text=True, timeout=GF_TIMEOUT)
            rc, output, timed_out = result.returncode, (result.stdout or "") + (result.stderr or ""), False
    except subprocess.TimeoutExpired:
        return f"{path}: gf help timed out (hanging binary)"
    except OSError as exc:
        return f"{path}: failed to execute gf ({exc})"
    if timed_out:
        return f"{path}: gf help timed out (hanging binary)"
    if rc != 0:
        return f"{path}: gf help exited {rc} (unusable binary)"
    if ("goframe" in output.lower()
            or not all(re.search(r"(?m)^\s*-" + flag + r"(?:\s|$)", output)
                       for flag in ("dump", "list", "save"))):
        return f"{path}: not tomnomnom gf (missing pattern-matcher help flags; possible GoFrame CLI)"
    return None


def check_candidate(name: str, path: str, *, runner=None) -> str | None:
    """None iff this executable returns the expected version banner successfully."""
    if name == "gf":
        return _check_gf(path, runner=runner)
    try:
        if runner is None:
            rc, output = _local_version(path)
        else:
            result = runner([path, "-version"], capture_output=True, text=True,
                            timeout=VERSION_TIMEOUT)
            rc = result.returncode
            output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        return f"{path}: -version timed out (hanging binary)"
    except OSError as exc:
        return f"{path}: failed to execute ({exc})"
    if rc != 0:
        return f"{path}: -version exited {rc} (crash/segfault or unusable binary)"
    low = output.lower()
    if name == "httpx" and ("python-httpx" in low or "python httpx" in low):
        return f"{path}: Python HTTP client, not ProjectDiscovery httpx"
    expected = "projectdiscovery" in low
    if name == "nuclei":
        expected = expected or "nuclei engine version" in low
    if not expected:
        return f"{path}: missing expected ProjectDiscovery {name} version banner"
    return None


@lru_cache(maxsize=128)
def _cached_check(name: str, path: str, fingerprint: tuple) -> str | None:
    return check_candidate(name, path)


def resolve(name: str, *, preferred: str | None = None, env=None,
            gobin: str | None = None, candidates=None, runner=None) -> tuple[str | None, str | None]:
    """Return (healthy absolute executable, last readiness reason).

    Absence yields (None, None); present but unhealthy candidates yield a reason.
    Cache keys include executable identity, size and nanosecond mtime so an
    installation/repair invalidates a previous success OR failure immediately.
    Explicit ``candidates``/``runner`` support isolated tests without host fallback.
    """
    paths = candidate_paths(name, preferred=preferred, env=env, gobin=gobin) if candidates is None else candidates
    reason = None
    for path in paths:
        if not path or not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        path = os.path.abspath(path)
        try:
            stat = os.stat(path)
        except OSError:
            continue
        if runner is None:
            fingerprint = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
            reason = _cached_check(name, path, fingerprint)
        else:
            reason = check_candidate(name, path, runner=runner)
        if reason is None:
            return path, None
    return None, reason


def runtime_env(env=None, *, gobin=None, python_bin=None) -> dict:
    """Export the chosen executable paths and make plain shell names agree.

    Only directories containing a health-checked selected tool move ahead of Go
    and the active interpreter; unrelated Homebrew directories do not win globally.
    Bash callers must retain this PATH or invoke the exported absolute pins.
    """
    result = dict(os.environ if env is None else env)
    healthy_dirs = []
    for name in PD_TOOLS:
        path, _ = resolve(name, env=result, gobin=gobin)
        result[env_key(name)] = path or ""
        if path:
            healthy_dirs.append(os.path.dirname(path))
    current = [part for part in result.get("PATH", "").split(os.pathsep) if part]
    # Keep the invoking interpreter ahead of generic installation prefixes.
    # Managed PD consumers use absolute pins, not ambiguous PATH lookups.
    preferred = [part for part in (python_bin,) if part and os.path.isdir(part)] + healthy_dirs
    preferred += [part for part in (gobin,) if part and os.path.isdir(part)]
    result["PATH"] = os.pathsep.join(dict.fromkeys(preferred + current))
    return result


def _gf_url_allowed(url: str, exact_hosts=None) -> bool:
    """Only complete unambiguous HTTP URLs can be classified as URL matches."""
    try:
        parsed = urlsplit(url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url)):
            return False
        _ = parsed.port  # Reject malformed/out-of-range ports as well.
        if exact_hosts is not None:
            from scope_checker import scope_lock_allows
            return scope_lock_allows(url, exact_hosts)
        return True
    except (TypeError, ValueError):
        return False


def _gf_coverage(path, reasons):
    if not path or not reasons:
        return
    destination = Path(path)
    existing = json.loads(destination.read_text(encoding="utf-8")) if destination.exists() else []
    if not isinstance(existing, list):
        raise ValueError("existing coverage marker is not a JSON list")
    for reason in dict.fromkeys(reasons):
        entry = {"tool": "gf", "phase": "recon", "reason": reason}
        if entry not in existing:
            existing.append(entry)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")


def match_gf(urls_file, output_dir, *, coverage_file=None, allow_file=None,
             patterns=GF_PATTERNS, candidates=None, env=None, gobin=None):
    """Classify supplied URLs locally, failing closed on tool/pattern failures.

    Only exact members of the validated input may become URL matches. Raw stdout,
    stderr and return codes stay in diagnostics, never in the URL artifacts.
    Returns counts and explicit coverage gaps, including an absent/wrong gf.
    """
    patterns = tuple(dict.fromkeys(patterns))
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", name) and name not in (".", "..")
               and not name.startswith("-") for name in patterns):
        raise ValueError("invalid gf pattern name")
    output = Path(output_dir)
    diagnostics = output / "diagnostics"
    diagnostics.mkdir(parents=True, exist_ok=True)
    counts = dict.fromkeys(patterns, 0)
    gaps = []
    for pattern in patterns:
        (output / f"{pattern}.txt").write_text("", encoding="utf-8")

    def save_diagnostic(name, result):
        (diagnostics / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    def finish(binary=None):
        summary = {"binary": binary, "counts": counts, "coverage_gaps": list(dict.fromkeys(gaps))}
        save_diagnostic("summary", summary)
        _gf_coverage(coverage_file, summary["coverage_gaps"])
        return summary

    try:
        exact_hosts = None
        if allow_file is not None:
            from scope_checker import _load_allow_file
            exact_hosts = _load_allow_file(allow_file)
            if not exact_hosts:
                raise ValueError("scope allowlist missing, empty or unreadable")
        raw_urls = [line.strip() for line in Path(urls_file).read_text(encoding="utf-8").splitlines()
                    if line.strip()]
    except (OSError, ValueError) as exc:
        gaps.append(f"gf input unavailable: {exc}")
        return finish()
    urls = list(dict.fromkeys(url for url in raw_urls if _gf_url_allowed(url, exact_hosts)))
    if len(urls) != len(set(raw_urls)):
        gaps.append("gf input contained invalid or out-of-scope URLs; excluded before matching")
    # This is also the actual stdin: rejected input cannot influence a custom
    # pattern, and original collection files are never rewritten here.
    validated_input = diagnostics / "input_urls.txt"
    validated_input.write_text("".join(url + "\n" for url in urls), encoding="utf-8")
    if not urls:
        return finish()
    binary, reason = resolve("gf", candidates=candidates, env=env, gobin=gobin)
    if not binary:
        gaps.append("gf pattern matching unavailable: " + (reason or "tomnomnom gf is not installed"))
        return finish()
    try:
        listed = _gf_capture([binary, "-list"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        listed = {"returncode": None, "stdout": "", "stderr": str(exc), "timed_out": isinstance(exc, subprocess.TimeoutExpired)}
    save_diagnostic("list", listed)
    if listed.get("timed_out") or listed.get("returncode") != 0 or (listed.get("stderr") or "").strip():
        gaps.append("gf pattern list failed; no pattern matches accepted (see diagnostics/list.json)")
        return finish(binary)
    # Custom filenames may contain spaces/Unicode; only requested names are
    # executed. An empty list is a valid gf with no installed pattern packs.
    available = {line.strip() for line in (listed.get("stdout") or "").splitlines() if line.strip()}
    input_set = set(urls)
    for pattern in patterns:
        if pattern not in available:
            gaps.append(f"gf[{pattern}] pattern is not installed")
            continue
        try:
            result = _gf_capture([binary, pattern], input_path=validated_input)
        except (OSError, subprocess.TimeoutExpired) as exc:
            result = {"returncode": None, "stdout": "", "stderr": str(exc), "timed_out": isinstance(exc, subprocess.TimeoutExpired)}
        save_diagnostic(pattern, result)
        stdout = result.get("stdout") or ""
        stderr = result.get("stderr") or ""
        rc = result.get("returncode")
        # grep returns 1 for no matches. gf can also swallow grep errors and
        # return 0, so stderr and full-line URL validation are mandatory.
        no_match = rc == 1 and not stdout.strip() and not stderr.strip()
        if result.get("timed_out") or stderr.strip() or (rc != 0 and not no_match):
            gaps.append(f"gf[{pattern}] command failed (rc={rc}); output excluded (see diagnostics/{pattern}.json)")
            continue
        matches = [line.strip() for line in stdout.splitlines() if line.strip()]
        if any(url not in input_set for url in matches):
            gaps.append(f"gf[{pattern}] emitted non-input/non-URL output; excluded (see diagnostics/{pattern}.json)")
            continue
        matches = list(dict.fromkeys(matches))
        (output / f"{pattern}.txt").write_text("".join(url + "\n" for url in matches), encoding="utf-8")
        counts[pattern] = len(matches)
    return finish(binary)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", nargs="?", choices=RESOLVABLE_TOOLS)
    parser.add_argument("--shell-env", action="store_true")
    parser.add_argument("--gf-match", action="store_true", help="Guarded local gf URL pattern matching")
    parser.add_argument("--urls-file")
    parser.add_argument("--output-dir")
    parser.add_argument("--coverage-file")
    parser.add_argument("--allow-file")
    parser.add_argument("--pattern", action="append", help="gf pattern name (repeatable)")
    args = parser.parse_args(argv)
    if args.gf_match:
        if not args.urls_file or not args.output_dir:
            parser.error("--gf-match requires --urls-file and --output-dir")
        try:
            result = match_gf(args.urls_file, args.output_dir, coverage_file=args.coverage_file,
                              allow_file=args.allow_file, patterns=args.pattern or GF_PATTERNS)
        except (OSError, ValueError) as exc:
            print(f"gf pattern matching failed: {exc}", file=sys.stderr)
            return 2
        for pattern, count in result["counts"].items():
            if count:
                print(f"gf[{pattern}]: {count} validated input URLs")
        for gap in result["coverage_gaps"]:
            print(f"Coverage gap: {gap}", file=sys.stderr)
        return 2 if result["coverage_gaps"] else 0
    if args.shell_env:
        env = runtime_env(gobin=os.path.join(os.path.expanduser("~"), "go", "bin"),
                          python_bin=os.path.dirname(sys.executable))
        for key in [env_key(name) for name in PD_TOOLS] + ["PATH"]:
            print(f"export {key}={shlex.quote(env[key])}")
        return 0
    if not args.name:
        parser.error("a tool name, --shell-env or --gf-match is required")
    path, reason = resolve(args.name)
    if path:
        print(path)
        return 0
    print(reason or f"{args.name}: no executable found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

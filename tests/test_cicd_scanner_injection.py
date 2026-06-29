"""Regression tests for cicd_scanner.sh command-injection hardening.

The wrapper previously built a string command and ran it through `eval`,
allowing shell metacharacters in the target/option arguments to execute
arbitrary commands. These tests verify:

  1. A malicious target containing shell metacharacters does NOT execute an
     injected command (and is rejected by the input validator).
  2. Numeric options are validated and reject metacharacter payloads.
  3. A benign target still drives the underlying tool with the right argv.

All data here is SYNTHETIC.
"""
import os
import subprocess
import tempfile
import textwrap
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "cicd_scanner.sh")


def _run(target, *opts, stub="argv"):
    """Run cicd_scanner.sh in an isolated workdir with a fake sisakulint on PATH.

    The stub records its argv (one per line) to $ARGV_FILE so we can assert
    exactly what was passed. A separate $PWNED file is created only if an
    injected `id`/`touch` command executes.
    """
    tmp = tempfile.mkdtemp()
    bindir = os.path.join(tmp, "bin")
    os.makedirs(bindir)
    argv_file = os.path.join(tmp, "argv.txt")
    pwned_file = os.path.join(tmp, "PWNED")

    stub_path = os.path.join(bindir, "sisakulint")
    with open(stub_path, "w") as fh:
        fh.write(textwrap.dedent("""\
            #!/bin/bash
            for a in "$@"; do printf '%s\\n' "$a" >> "$ARGV_FILE"; done
            exit 0
        """))
    os.chmod(stub_path, 0o755)

    env = dict(os.environ)
    env["PATH"] = bindir + os.pathsep + env["PATH"]
    env["ARGV_FILE"] = argv_file
    env["PWNED"] = pwned_file

    proc = subprocess.run(
        ["bash", SCRIPT, target, *opts],
        cwd=tmp, env=env, capture_output=True, text=True,
    )
    argv = []
    if os.path.exists(argv_file):
        with open(argv_file) as fh:
            argv = fh.read().splitlines()
    return proc, argv, os.path.exists(pwned_file)


class TestCicdScannerInjection(unittest.TestCase):
    def test_target_command_injection_blocked(self):
        # Classic eval-breakout payload that would create $PWNED via `touch`.
        payload = 'x";touch "$PWNED";"'
        proc, argv, pwned = _run(payload)
        self.assertFalse(pwned, "injected command executed -- eval breakout!")
        # Validator rejects the metacharacter target before running the tool.
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(argv, [], "tool ran with a metacharacter target")

    def test_command_substitution_blocked(self):
        proc, argv, pwned = _run('$(touch "$PWNED")')
        self.assertFalse(pwned)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(argv, [])

    def test_numeric_option_injection_blocked(self):
        proc, argv, pwned = _run("acme/repo", "-d", '3;touch "$PWNED"')
        self.assertFalse(pwned)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(argv, [])

    def test_benign_target_passes_argv(self):
        proc, argv, pwned = _run("acme/repo", "-d", "5", "-l", "10", "-p", "2", "-r")
        self.assertFalse(pwned)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # argv array must contain the target verbatim and the numeric options.
        self.assertIn("-remote", argv)
        self.assertIn("acme/repo", argv)
        self.assertIn("5", argv)
        self.assertIn("10", argv)
        self.assertIn("2", argv)
        self.assertIn("-r", argv)

    def test_github_url_normalized_and_accepted(self):
        proc, argv, pwned = _run("https://github.com/acme/repo.git")
        self.assertFalse(pwned)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("acme/repo", argv)


if __name__ == "__main__":
    unittest.main()

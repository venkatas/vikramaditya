---
description: Scan GitHub Actions workflows for security issues (pwn_request, tag-pinning, script-injection) via sisakulint. Usage: /cicd owner/repo | org:name
---

# /cicd

Audit GitHub Actions workflows for the CI/CD bug classes that have paid 5-figure bounties on H1 / Bugcrowd / Intigriti over the last two years.

## What This Does

Wraps `sisakulint -remote` to scan a single repo or an entire organization for:

- `pwn_request` — `pull_request_target` + write perms + checkout of untrusted code
- Unpinned 3rd-party actions (`uses: someone/action@main` instead of `@<sha>`)
- Script injection via `${{ github.event.* }}` in `run:` blocks
- Missing `permissions:` (default write-all)
- Reusable-workflow chains with elevated privileges
- Shell-string interpolation in expressions

## Usage

```
/cicd owner/repo                              # single repo
/cicd "org:kubernetes"                        # whole org (up to --limit repos)
/cicd https://github.com/actions/runner       # GitHub URL (auto-normalized)
```

## Options

```
-r, --recursive     Scan reusable workflows recursively
-d, --depth N       Max recursion depth (default: 3)
-l, --limit N       Max repos for org search (default: 30)
-p, --parallel N    Parallel scan count (default: 3)
-o, --output-dir D  Override output directory
```

## Examples

```bash
# Single repo, fast
./cicd_scanner.sh torvalds/linux

# Deep org audit
./cicd_scanner.sh "org:kubernetes" --recursive --depth 5

# Custom output location for a hunt session
./cicd_scanner.sh rails/rails --output-dir findings/rails/cicd/
```

## Prerequisites

- `sisakulint` installed — `go install github.com/ultra-supara/sisakulint/cmd/sisakulint@latest`
- `gh` CLI authenticated (`gh auth login`) — required for `org:` batch mode to enumerate repos

## Output

Findings are written to `findings/<target>/cicd/` (or `--output-dir`):
- `scan_results.txt` — raw sisakulint output
- `summary.txt` — vuln class counts + highest-severity issues

## Pairing with the hunt workflow

`/cicd` is usually a **Phase 0** check before `/recon` — a CI/CD pwn_request against a public repo is often a faster path to ATO than webapp recon. Findings here can be chained with source-code audits in `/hunt <target> --vuln-class cicd`.

## Ported from

Upstream `shuvonsec/claude-bug-bounty` — `tools/cicd_scanner.sh`.

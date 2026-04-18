# Changelog

## v6.1.0 — /remember + /surface + recon-ranker (2026-04-18)

### Added
- `commands/remember.md` — `/remember` turns the current hunt's findings into reusable patterns (writes to both `journal.jsonl` and `patterns.jsonl`).
- `commands/surface.md` — `/surface` produces a P1 / P2 / Kill-List prioritization of the attack surface from the existing `recon/` cache.
- `agents/recon-ranker.md` — the agent `/surface` dispatches to. Reads recon + memory, ranks, justifies each tier.

### Why
Vikramaditya has a massive `recon/` cache from 20+ engagements and a growing `hunt-memory/journal.jsonl` from v5.3.0 — but no prioritization step between "I ran recon" and "I started hunting." This trio closes that gap: `/surface` ranks, `/remember` captures learnings, and the ranker agent coordinates them with the existing `prioritize.py`.

### Conflict resolution
Vikramaditya's existing `prioritize.py` continues to do raw scoring; recon-ranker sits *on top*, consuming its output and layering in hunt-memory context.

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `commands/remember.md`, `commands/surface.md`, `agents/recon-ranker.md`.

---

## v6.0.0 — meme-coin / Solana / DEX LP security (2026-04-18)

**Major:** adds an entire new web3 sub-domain to Vikramaditya.

### Added
- `token_scanner.py` (root, 783 lines) — deterministic regex scanner for rug-vector patterns in EVM + Solana token contracts. Detects: unrestricted mint, unbounded fee/tax, trading toggles, hidden transfer hooks, blacklist/whitelist, owner privileges, paused/freezable, honeypot logic. `--chain evm|solana` + `--recursive` + `--json` + `--output` modes.
- `web3/10-meme-coin-bugs.md` — 8 meme-coin-specific bug classes with grep arsenal and Immunefi paid examples.
- `web3/11-solana-token-audit.md` — SPL / Token-2022 / freeze-authority / transfer-hook attack surface.
- `web3/12-dex-lp-attacks.md` — LP / AMM / concentrated-liquidity attacks + sandwich/JIT vectors.
- `skills/meme-coin-audit/SKILL.md` — workflow skill for auditing meme coin launches.
- `agents/token-auditor.md` — specialist agent that runs token_scanner.py + routes findings to the appropriate skill.
- `commands/token-scan.md` — `/token-scan <contract>` slash command.

### Why
Vikramaditya's web3 coverage stopped at generic DeFi (contracts/ roles / oracles / reentrancy). Meme coin launches, Solana SPL tokens, Token-2022 transfer hooks, and DEX LP concentrated-liquidity bugs pay 5–7 figures on Immunefi and are not reachable via the existing skill set. This bundle closes the gap.

### Verified
`token_scanner.py` detected `critical` unrestricted-mint, `critical` unbounded-fee, and `medium` trading-toggle + pause-authority patterns on a handcrafted rug contract — regex arsenal intact.

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `tools/token_scanner.py`, `web3/10/11/12.md`, `skills/meme-coin-audit/`, `agents/token-auditor.md`, `commands/token-scan.md` (PR #9).

---

## v5.6.0 — /intel engine (2026-04-18)

### Added
- `intel_engine.py` — on-demand intel orchestrator. Combines `intel.py` (CVE / NVD / GitHub Advisory / Hacktivity fetchers) + HackerOne MCP (preferred when registered) + hunt-memory cross-reference. Flags untested CVEs on the current target and new endpoints since the last hunt.
- `commands/intel.md` — `/intel <target>` slash command with tech-stack and program-handle flags.

### Changed
- `intel_engine.py` imports `intel` (Vikramaditya's module) instead of upstream's `learn`. Same function signatures, clean swap.
- MCP import path adjusted for Vikramaditya's flat layout: `mcp/hackerone-mcp/` at repo root, not `tools/../mcp/`.

### Why
`intel.py` already fetches raw CVEs/advisories but dumps them flat. `intel_engine.py` adds the "what haven't I tested yet on this target?" layer — cross-references against hunt-memory to surface new attack surface on a warm re-engagement. Depends on v5.1.0 HackerOne MCP for richer program context.

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `tools/intel_engine.py` + `commands/intel.md` (PR #9 Bionic Hunter).

---

## v5.5.0 — bb-methodology master skill (2026-04-18)

### Added
- `skills/bb-methodology/SKILL.md` — master orchestrator skill (352 lines). Describes the 5-phase non-linear hunting flow, developer-psychology framing, and "What If" framework for lateral thinking.

### Why
Vikramaditya has focused skills (`bug-bounty`, `triage-validation`, `report-writing`, `security-arsenal`, `web2-recon`, `web2-vuln-classes`, `web3-audit`) but no *where do I start / what's next* router. bb-methodology fills that gap — it decides which skill to invoke at each phase of a hunt.

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `skills/bb-methodology/` (PR #12).

---

## v5.4.0 — secure credential store (2026-04-18)

### Added
- `credential_store.py` — loads credentials from `.env`, exposes `.get()`, `.has()`, `.keys()`, `.get_masked()`, and `.as_headers(key, header_type=bearer|cookie|api_key)`. Never logs raw values; `__str__` auto-masks.

### Why
Hunt artifacts in `findings/<target>/session*.json` have historically captured raw cookies and Bearer tokens. CredentialStore provides a single import surface for `auth_utils.py`, `autopilot_api_hunt.py`, and HAR-based flows so secrets live in a `.gitignored` `.env` instead of being passed as CLI args (which end up in shell history).

### Usage
```python
from credential_store import CredentialStore

store = CredentialStore(".env")
headers = store.as_headers("TARGET_COOKIE", header_type="cookie")
# -> {"Cookie": "session=xyz"}
print(store)  # CredentialStore(TARGET_COOKIE=ses***)
```

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `tools/credential_store.py` (PR #10).

---

## v5.3.0 — /pickup session resume + auto-logged summaries (2026-04-18)

### Added
- `memory/schemas.py::make_session_summary_entry()` — builds a validated `session_summary` journal entry for auto-logging at session end.
- `memory/hunt_journal.py::log_session_summary()` — safe wrapper that appends one, swallows errors so auto-logging never crashes the hunt loop.
- `commands/pickup.md` — `/pickup <target>` slash command that reads the journal and surfaces untested endpoints, prior findings, and warm-restart context for a target.

### Why
Vikramaditya already has rich `findings/` and `recon/` history across 20+ engagements (adani, rediff, scm.ap.gov.in, mailpoc.in, etc.) but no resume UX. `/pickup target.com` gives a 30-second warm restart instead of re-reading stale md files. Auto-summaries close the loop by populating memory without needing a manual `/remember`.

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `commands/pickup.md` + `memory/hunt_journal.py::log_session_summary()` (PR #9 auto-memory follow-up).

---

## v5.2.0 — CI/CD workflow scanner (2026-04-18)

### Added
- `cicd_scanner.sh` — sisakulint wrapper for GitHub Actions workflow auditing. Single repo, org batch, and URL modes. Detects `pwn_request`, unpinned actions, script injection, missing `permissions:`, reusable-workflow privilege escalation.
- `commands/cicd.md` — `/cicd` slash command exposing the scanner with the full option set.

### Output
Findings land in `findings/<target>/cicd/{scan_results.txt, summary.txt}` — same layout as other Vikramaditya scanners.

### Why
Vikramaditya had zero GitHub Actions / CI-pipeline auditing. `pwn_request` + unpinned-action supply-chain bugs have paid 5-figure bounties on H1 / Intigriti / Immunefi over the last 2 years — a surface the existing web2/web3 scanners don't touch.

### Prerequisites (runtime)
- `sisakulint` — `go install github.com/ultra-supara/sisakulint/cmd/sisakulint@latest`
- `gh` CLI authenticated — needed for `org:` batch mode to enumerate repos

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `tools/cicd_scanner.sh` (PR #13).

---

## v5.1.0 — HackerOne MCP server (2026-04-18)

### Added
- `mcp/hackerone-mcp/server.py` — MCP server exposing HackerOne public GraphQL endpoints as Claude Code tools. No API key required.
- `mcp/hackerone-mcp/config.json` — reference config for `.claude/settings.json`.
- `.claude/settings.json` — registers the MCP server at project level (was absent before; only `settings.local.json` for permissions existed).

### Tools exposed via MCP
- `search_disclosed_reports` — Hacktivity search by keyword/program (⚠️ currently broken upstream — HackerOne renamed `hacktivity_items` in their public schema; tracked for upstream fix)
- `get_program_stats` — bounty ranges, response times, resolved counts
- `get_program_policy` — safe harbor, response SLA, excluded vuln classes ✅ verified working (returns real policy text)

### Why
Vikramaditya's `/triage`, `/validate`, `/scope` flows previously had no way to consult live HackerOne data (program scope, safe-harbor policy, response SLA). With the MCP registered, Claude can now fetch program context on-demand during hunting. Unlocks future port of `intel_engine.py` which layers this with `learn.py` + hunt memory.

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `mcp/hackerone-mcp/` (v3.0 Bionic Hunter release).

---

## v5.0.0 — CVSS 4.0 scoring (2026-04-18)

**Breaking:** replaces CVSS 3.1 with CVSS 4.0 in `validate.py`.

### Changed
- `calculate_cvss(av, ac, pr, ui, s, c, i, a)` → `calculate_cvss40(av, ac, at, pr, ui, vc, vi, va, sc, si, sa)` — 11 params, macro-vector lookup, CVSS:4.0/... vector strings.
- Interactive `score_cvss()` now prompts for the 4.0 metrics:
  - **AT** (Attack Requirements) — new in 4.0
  - **UI** {N/P/A} — Passive vs Active (was N/R in 3.1)
  - **VC/VI/VA** (Vulnerable System CIA) + **SC/SI/SA** (Subsequent System CIA)
  - **SI/SA** support "S" (Safety) impact
- Report skeleton default vector: `CVSS:3.1/...` → `CVSS:4.0/...`
- Every scored report links to https://www.first.org/cvss/calculator/4.0 for verification.

### Why
CVSS 3.1 is deprecated. Modern programs (H1, Bugcrowd, Intigriti) reward 4.0 scoring with AT/SC/SI/SA supply-chain and downstream impact axes. Self-XSS submissions that used to score MEDIUM in 3.1 now correctly show LOW in 4.0.

### Ported from
Upstream `shuvonsec/claude-bug-bounty` PR #10 (CVSS 4.0 scoring, recon adapter, TODO fixes).

---

## v4.1 — HAR-based authenticated VAPT (prior release, undocumented)

See commit log `bc6b025`..`c57f448`:
- HAR file support for authenticated testing
- Legacy app crawler for PHP/CGI/JSP targets
- False-positive elimination in HAR VAPT engine
- Empty HTML report fix (issue #2)

## v4.0 — Fully autonomous mode (prior release, undocumented)

See commit log `003b3a1`..`afdc74d`:
- Zero prompts when LLM present
- `--creds` always routes to autopilot
- Dual-model brain (BugTraceAI + gemma4)
- Google Magika file classifier

## v3.0 — Auto-verification with specialized tools (prior release, undocumented)

See commit log `aedcfea`..`180c765`:
- sqlmap / dalfox / nuclei auto-verification on confirmed candidates
- SQLi false positive guard
- Cross-origin API detection
- Pattern-based URL dedup
- katana + arjun timeout caps

---

## v2.0.0 — ECC-Style Plugin Architecture (Mar 2026)

Major restructure into a full Claude Code plugin with multi-component architecture.

### Added
- `skills/` directory with 7 focused skill domains (split from monolithic SKILL.md)
  - `skills/bug-bounty/` — master workflow (unchanged from v1)
  - `skills/web2-recon/` — recon pipeline, subdomain enum, 5-minute rule
  - `skills/web2-vuln-classes/` — 18 bug classes with bypass tables
  - `skills/security-arsenal/` — payloads, bypass tables, never-submit list
  - `skills/web3-audit/` — 10 smart contract bug classes, Foundry template
  - `skills/report-writing/` — H1/Bugcrowd/Intigriti/Immunefi templates
  - `skills/triage-validation/` — 7-Question Gate, 4 gates, always-rejected list
- `commands/` directory with 8 slash commands
  - `/recon` — full recon pipeline
  - `/hunt` — start hunting a target
  - `/validate` — 4-gate finding validation
  - `/report` — submission-ready report generator
  - `/chain` — A→B→C exploit chain builder
  - `/scope` — asset scope verification
  - `/triage` — quick 7-Question Gate
  - `/web3-audit` — smart contract audit
- `agents/` directory with 5 specialized agents
  - `recon-agent` — runs recon pipeline, uses claude-haiku-4-5 for speed
  - `report-writer` — generates reports, uses claude-opus-4-6 for quality
  - `validator` — validates findings, uses claude-sonnet-4-6
  - `web3-auditor` — audits contracts, uses claude-sonnet-4-6
  - `chain-builder` — builds exploit chains, uses claude-sonnet-4-6
- `hooks/hooks.json` — session start/stop hooks with hunt reminders
- `rules/hunting.md` — 17 critical hunting rules (always active)
- `rules/reporting.md` — 12 report quality rules (always active)
- `CLAUDE.md` — plugin overview and quick-start guide
- `install.sh` — one-command skill installation

### Content Added to Skills
- SSRF IP bypass table: 11 techniques (decimal, octal, hex, IPv6, redirect chain, DNS rebinding)
- Open redirect bypass table: 11 techniques for OAuth chaining
- File upload bypass table: 10 techniques + magic bytes reference
- Agentic AI ASI01-ASI10 table: OWASP 2026 agentic AI security framework
- Pre-dive kill signals for web3: TVL formula, audit check, line-count heuristic
- Conditionally valid with chain table: 12 entries
- Report escalation language for payout downgrade defense

---

## v1.0.0 — Initial Release (Early 2026)

- Monolithic SKILL.md (1,200+ lines) covering full web2+web3 workflow
- Python tools: `hunt.py`, `learn.py`, `validate.py`, `report_generator.py`, `mindmap.py`
- Vulnerability scanners: `h1_idor_scanner.py`, `h1_mutation_idor.py`, `h1_oauth_tester.py`, `h1_race.py`
- AI/LLM testing: `hai_probe.py`, `hai_payload_builder.py`, `hai_browser_recon.js`
- Shell tools: `recon_engine.sh`, `vuln_scanner.sh`
- Utilities: `sneaky_bits.py`, `target_selector.py`, `zero_day_fuzzer.py`, `cve_hunter.py`
- Web3 skill chain: 10 files in `web3/` directory
- Wordlists: 5 wordlists in `wordlists/` directory
- Docs: `docs/payloads.md`, `docs/advanced-techniques.md`, `docs/smart-contract-audit.md`

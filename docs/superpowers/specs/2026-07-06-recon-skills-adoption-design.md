# Vikramaditya — recon-skills Adoption Batch 1 Design

**Date:** 2026-07-06
**Author:** Venkata Satish Guttula
**Status:** Draft — pending user review

## Summary

Adds 7 new clean-room Python modules to Vikramaditya, each closing a confirmed capability gap surfaced by evaluating `uphiago/recon-skills` (155-skill MIT-claimed repo, no LICENSE file in root). No code or prose is copied from that repo — only the technique/idea is reused, per the standing clean-room rule. The batch: `tls_impersonation.py`, `xxe_hunt.py`, `open_redirect_hunt.py`, `saml_xsw_tester.py`, `jwt_kid_injection.py`, `springboot_actuator_probe.py`, `ldap_injection_tester.py`.

`smuggling_hunt.py` (HTTP request/response smuggling) is explicitly **excluded from this batch** — see "Cut from scope" below.

## Background

A 7-cluster parallel research pass (Workflow) surveyed all 155 skills against Vikramaditya's ~100 existing modules and produced an 8-item adopt shortlist. Two independent adversarial review rounds with codex/grok/agy (one on the shortlist, one on this design) each caught real, code-verified errors:

- **Shortlist round**: the survey's "zero coverage" claims for SAML/JWT/actuator were wrong — `scanner.sh` Check 7, `hunt.py --jwt-audit`, and `recon.sh` Phase 9 already do shallow versions of each. Corrected to "extend existing, deepen the gap" rather than "build from scratch."
- **Design round**: caught that `reporter.py`'s `NON_FINDING_PREFIXES` and `SUBDIR_VTYPE` are explicit hardcoded allowlists (new prefixes/subdirs silently drop or unsuppress otherwise), `run_oob_setup()` is a print-only stub not real OOB infra, `pii_detector.py` is Indian-PII-only (not a secret-pattern source), `probe.py` is an unrelated HackerOne-copilot tool, and `requirements.txt` doesn't formally declare 4 already-locally-installed deps. All corrections below are verified against the current code, not just asserted by a reviewer.

Full evaluation detail lives in memory (`project_repo_evaluations_vikramaditya.md`), not duplicated here.

## Decisions locked during brainstorming

| # | Decision | Choice |
|---|---|---|
| D1 | Batch scope | All 8 shortlist items minus smuggling (cut) = **7 modules** |
| D2 | Build process | Parallel-author (one agent per module, TDD, new files only) → one sequential integration pass → one combined friends review → one PR |
| D3 | Module placement | Repo-root standalone `.py` files, matching the existing convention (`nomore403_audit.py`, `nuclei_dast.py`, `bac_matrix.py`, etc.) — not a new plugins subdirectory |
| D4 | Shared-file ownership | Parallel agents touch **only** their own new module + test file. All shared-file edits (`hunt.py`, `reporter.py`, `recon.sh`, `scanner.sh`, `requirements.txt`) are done by the integrator (me) sequentially, afterward — zero parallel writes to any shared file |
| D5 | Anti-fabrication | Every unproven lead uses an `[X-CANDIDATE]` prefix explicitly registered in `reporter.py`'s `NON_FINDING_PREFIXES`, matching the existing `[403-BYPASS-CANDIDATE]` pattern and comment style |
| D6 | Destructive-risk items | Excluded from this batch entirely (not opt-in-flagged) if the risk is in the *act of probing* rather than the *reporting* — applies to smuggling only, this round |
| D7 | New dependency policy | `curl_cffi` (new) wrapped in try/except with a graceful degrade to stock `httpx` if the native wheel is unavailable (air-gapped/ARM boxes); `lxml`/`PyJWT`/`ldap3`/`h2` (already installed locally) get formal `requirements.txt` entries |

## Architecture

| # | Module | Priority | New dep | Integration model |
|---|---|---|---|---|
| 1 | `tls_impersonation.py` | P0 | `curl_cffi` (graceful-degrade) | Shared HTTP client the other 6 modules import; emits a non-critical `[WAF-BLOCK-DETECTED]` coverage lead (not silent) |
| 2 | `xxe_hunt.py` | P0 | none | New `hunt.py` phase; reuses a small shared interactsh helper extracted from `run_rce_scan()`'s real spawn/monitor logic |
| 3 | `open_redirect_hunt.py` | P1 | none | New `hunt.py` phase; requires a new `SUBDIR_VTYPE["redirects"]` mapping |
| 4 | `saml_xsw_tester.py` | P1 | none (lxml) | New `hunt.py` phase, consumes Check 7's existing `findings/saml/` artifacts |
| 5 | `jwt_kid_injection.py` | P1 | none (PyJWT) | Folds into `hunt.py`'s existing `run_jwt_audit()`, not a new top-level phase |
| 6 | `springboot_actuator_probe.py` | P1 | none | New `hunt.py` phase, consumes `recon.sh` Phase 9's existing actuator-path discoveries; imports `whitebox/secrets/detectors.py::DETECTORS` for `/actuator/env` parsing |
| 7 | `ldap_injection_tester.py` | P2 | none (ldap3) | New `hunt.py` phase, gated on a stack-fingerprint check (AD/Java/PHP enterprise login) before activating |

### Per-module design detail

**1. `tls_impersonation.py`** — `get_client(fingerprint="chrome124"|"firefox133"|"safari18"|"okhttp4", proxy=None)` wrapping `curl_cffi`; `select_fingerprint(url)` heuristic (mobile-API path patterns → `okhttp4`, else `chrome124`). On `ImportError` for `curl_cffi`, falls back to a stock `httpx.Client` and logs a coverage degradation note — never a hard crash. When any of modules 2–7 hit a 403 alongside a `cf-ray`/`akamai`/`x-iinfo` (F5) header, they retry once through this client; on a proven bot-management block, write a single `[WAF-BLOCK-DETECTED]` line to `findings/misconfig/` (info-severity, not a vuln) so coverage stays visible instead of silently degrading.

**2. `xxe_hunt.py`** — `probe_content_type_swap(url, json_body)` (JSON→XML content-type + external entity, checks for in-band file-marker content) and `probe_upload_xxe(endpoint, doc_type)` (SVG/DOCX/XLSX XXE payloads). Blind confirmation extracts the real interactsh spawn+`interactsh_log.jsonl`-monitor logic currently inlined in `run_rce_scan()` (hunt.py ~5850) into a small shared `_interactsh_session()` helper both callers use — not `run_oob_setup()`, which only prints instructions. FP gate: emits `[XXE-CANDIDATE]` unless in-band file content or an OOB callback is proven, in which case it emits a real finding.

**3. `open_redirect_hunt.py`** — fuzzes crawled `urls.txt` for redirect-shaped params (`next`, `url`, `return`, `return_to`, `redirect`, `redirect_uri`, `goto`, `continue`, `dest`, `destination`, `u`, `r`) with an attacker-controlled external host plus common bypass encodings (double-encoding, `//`, `\/\/`, `@`, backslash tricks). Confirms only via a real `Location:` header pointing at the attacker host. Writes to `findings/redirects/`, which requires adding `"redirects": "open_redirect"` to `reporter.py`'s `SUBDIR_VTYPE` (currently unmapped, so findings would silently drop).

**4. `saml_xsw_tester.py`** — reads Check 7's existing `findings/saml/endpoints.txt` and `certs.txt`. If no valid captured `SAMLResponse` is available (v1 requires the operator to supply one manually, e.g. from a HAR — no automatic HAR extraction is built in this batch, that's a separate future item), the module logs "manual capture required" and skips XSW forgery entirely rather than attempt it against a synthetic/unsigned assertion. When a real assertion is supplied, generates XSW1–8 variants via `lxml` (assertion duplication, signature relocation, comment-boundary splitting, namespace-prefix aliasing) and confirms success only by fetching an actual protected/identity resource with the resulting session — not just a cookie + non-login redirect. Explicitly out of scope: fixing Check 7's own pre-existing synthetic-unsigned-assertion → CRITICAL-ATO labeling path (a separate, already-existing item, not touched by this module).

**5. `jwt_kid_injection.py`** — authored in parallel as its own standalone module (like the other 6) exposing discovery/injection/replay functions; the integrator wires those functions into `hunt.py`'s existing `run_jwt_audit()` during the sequential integration pass, rather than the module editing `hunt.py` directly — this is not a new top-level phase, just a new import + a few extra calls inside the existing function. Discovers JWKS via common `.well-known` paths, iterates **every** key in the `keys[]` array (not just the first/cached one), and attempts PKCS#1/PKCS#8/DER PEM conversions of each candidate key for RS256→HS256 confusion. Also attempts `kid`-header injection (path traversal, SQLi-shaped values) where the token's `kid` looks like it could resolve to an attacker-influenced path. Replay confirmation requires a 3-way baseline diff — original-token response, unauthenticated response, and forged-token response — and only confirms when the forged-token response diverges from both baselines in the direction of "authenticated as," not merely "200 with some body."

**6. `springboot_actuator_probe.py`** — consumes `recon.sh` Phase 9's existing actuator/h2-console path hits. `check_spel_injection()` starts with an arithmetic-only oracle but only escalates past `[SPEL-CANDIDATE]` when a benign system-metadata read (e.g. `T(java.lang.System).getProperty('java.version')`) is also confirmed — arithmetic alone reads as theoretical. `check_jolokia_reachability()` confirms reachability + MBean listing without executing anything (proves precondition only). `parse_actuator_env_secrets()` imports `whitebox/secrets/detectors.py::DETECTORS` rather than `pii_detector.py` (which is Indian-PII-only, not a secret-pattern source). A bare `/actuator/health` 200 is never a finding.

**7. `ldap_injection_tester.py`** — only activates when a stack-fingerprint check suggests LDAP-backed auth (AD/Java/PHP enterprise login patterns), to avoid wasted cycles and FPs on unrelated stacks. Fuzzes the RFC 4515 special-character set with **baseline-diff** detection (compares against a captured baseline response, not raw error-string matching) to avoid FPs on generic login pages. Attempts always-true auth-bypass filters with correct paren-balancing. Blind true/false-oracle attribute exfiltration is gated behind a stable-FALSE control plus 3x-repeat confirmation before reporting. Severity is gated separately for AD-specific claims (`memberOf`/`sAMAccountName` enumeration) vs generic-LDAP claims (`userPassword` hash exfiltration).

## Integration plan (single sequential pass, after all 7 modules + tests exist)

1. **`hunt.py`**: add `run_xxe_hunt()`, `run_open_redirect_hunt()`, `run_saml_xsw()`, `run_actuator_probe()`, `run_ldap_injection()` phase functions (using the existing `_brain_phase_complete()` convention); extend `run_jwt_audit()` in place for module 5. Add entries to both `_phase_tool_map` and `_phase_requested` for every new phase so the dashboard reports ran/skipped/error correctly (not just an appended function).
2. **`reporter.py`**: add `[XXE-CANDIDATE]`, `[SPEL-CANDIDATE]`, and any other new candidate prefixes to `NON_FINDING_PREFIXES` with the same rationale-comment style as the existing 11 entries. Add `"redirects": "open_redirect"` to `SUBDIR_VTYPE`. Add/verify `VULN_TEMPLATES` entries exist for XXE (currently only `finding_schema.py` has XXE metadata).
3. **`requirements.txt`**: add explicit `lxml`, `PyJWT`, `ldap3`, `h2` entries (already installed locally, now formalized) and `curl_cffi` with a comment noting the graceful-degrade path.
4. **Test coverage gate**: add `redirects` and `xxe` (and any other new subdirs) to whatever test currently enumerates known subdirs (`tests/test_reporter_subdir_coverage.py`-class test), so the coverage gate doesn't regress.
5. No `scanner.sh` `DEFAULT_SKIP_SET` changes — all 7 are `hunt.py` Python phases, orthogonal to the bash skip-set, same as `nomore403_audit.py`/`nuclei_dast.py` today.

## Testing plan

One `tests/test_<module>.py` per module, written alongside implementation (TDD) by each parallel-authoring agent, following existing fixture/naming conventions (see `test_nomore403_audit.py`, `test_nuclei_dast.py`). Full suite run after the integration pass. One combined codex+grok+agy adversarial review of the complete change set before any commit, with every finding verified against live code before being folded in (standing rule) — not a rubber-stamp pass.

## Process / sequencing

1. 7 parallel agents, one per module, each writes only its own `.py` + `tests/test_*.py` (no shared-file edits).
2. Integrator (me) does the 5-step integration pass above, sequentially, in one commit.
3. Full test suite run.
4. Combined friends review of the whole diff; fix real findings in a follow-up commit.
5. Branch `feat/recon-skills-adoption-batch1` off `main`; hand off to `finishing-a-development-branch` for a PR at the end (not merged without explicit go-ahead).

## Cut from scope

- **`smuggling_hunt.py`** — unanimous 3/3 friends: the risk is in the act of sending a desync probe (can poison a shared connection pool / hijack a real concurrent user's request on a live production system), not in how the result is reported. An opt-in flag + timing-only confirmation doesn't mitigate that. Needs a separately-scoped future effort with per-host allowlisting, single-connection isolation, hard rate limits, and explicit maintenance-window language.
- **`exchange_owa_hunt.py`, SharePoint hunter, active Java-deserialization gadget testing, Citrix/VPN perimeter CVEs, host-header/cache-poisoning** — real gaps per the shortlist, held back by the P0/P1/P2 cut line, not by any design flaw. Candidates for a batch 2.

## Risks & guardrails carried into implementation

- `curl_cffi` native-wheel install may fail on air-gapped/ARM/hardened client boxes → must degrade gracefully, never hard-fail a scan.
- XXE blind-OOB egress filtering in gov/BFSI networks → document as a known false-negative risk in the module docstring, not a bug to "fix."
- SAML/JWT/actuator all ship with proof-gates specifically because their false-positive modes were called out by name in review (synthetic assertions, arithmetic-only SpEL, weak replay-shape matching) — do not loosen these gates during implementation for convenience.
- `ldap_injection_tester.py`'s stack-fingerprint gate exists specifically to avoid FPs on non-LDAP login pages — do not remove it to "increase coverage."

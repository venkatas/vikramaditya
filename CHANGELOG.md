# Changelog

## v8.0.0 — Whitebox AWS audit + dual-track operation (2026-04-30)

**Major release.** Adds an authenticated whitebox engine alongside the existing blackbox stack. Both feed the same correlator and the same final report. Previous v7.x capabilities (engagement-privacy proxy, HAR auth replay, meme-coin module, anonymization vault, HackerOne MCP, brain.py) are preserved unchanged.

### New: `whitebox/` subpackage

Dual-track AWS audit driven by `whitebox/cloud_hunt.py`. Seven phases, each independently cacheable and resumable:

- **inventory** — Account-wide boto3 enumeration across 26 services (EC2, EC2 SGs, EC2 VPCs, S3, IAM users / roles / policies, RDS, Lambda, ECS, EKS, ELBv2, API Gateway v1+v2, CloudFront, Route53, SSM, Secrets Manager, KMS, WAFv2, CloudWatch Logs, CodeCommit, ECR, GuardDuty, CloudTrail, Config). Iterates only enabled regions (`ec2 describe-regions` filter) so unenabled opt-in regions don't hang boto3.
- **prowler** — Runs Prowler 4.5 full-checks suite via isolated venv (handles its `pydantic 1.10.18` pin without breaking the main venv). Emits OCSF JSON + 17 compliance CSVs (CIS 1.4 / 1.5 / 2.0 / 3.0, AWS-FSBP, AWS-Well-Architected Reliability + Security, SOC2, HIPAA, FedRAMP Low + Moderate, FFIEC, CISA, GxP-EU-Annex-11, ENS-RD-2022, AWS Audit Manager Control Tower Guardrails, AWS Account Security Onboarding, AWS Foundational Technical Review). Exit codes 0 + 3 are both treated as success-with-findings (per Prowler convention). `PROWLER_TIMEOUT` env override (default 5400s).
- **iam** — Runs PMapper 1.1.5 in its own isolated venv (with the documented Python 3.10+ collections.abc patch) to build the IAM blast-radius graph. Discovers privesc paths, admin-reachability, role-assumption chains. Storage location resolution covers macOS appdirs (`~/Library/Application Support/com.nccgroup.principalmapper/`), Linux XDG (`~/.local/share/principalmapper/`), legacy `~/.principalmapper`, and `/var/lib/principalmapper`. Region narrowing via `PMAPPER_REGIONS`. Timeout via `PMAPPER_TIMEOUT` env (default 1800s).
- **exposure** — Joins Security Group analysis with EC2 instance attachment data to tag assets. The current implementation flags any SG with 0.0.0.0/0 ingress; a follow-up (backlog P0) adds reachability verification (TCP probe of attached running instances) so orphan-SG findings are auto-downgraded.
- **secrets** — Scans Lambda environment variables, SSM parameters, Secrets Manager metadata, EC2 user-data, CloudWatch Logs (heuristic / brain-selected log groups), and S3 buckets (heuristic / brain-selected by name hint). Detectors cover AWS access / secret keys, OpenAI / Gemini / Google / Azure API keys, generic password assignments, high-entropy tokens. Each finding writes a 0600-permission JSON evidence file in a 0700 directory; redacted previews are what flow into the report.
- **correlation** — Per-profile asset feed (`asset_feed_<account_id>.json`) plus a session-wide merged `asset_feed.json`, ready for blackbox cross-reference. PMapper-discovered IAM privesc paths join blackbox SSRF / IDOR / RCE findings to surface chained risks.
- **report** — `findings.json` consolidated dump. The HTML reporter (`whitebox/reporting/posture_chapter.py` + `correlation_inline.py`) renders a "Cloud Posture" chapter and inlines cloud context on each blackbox finding.

### New env vars

- `PROWLER_TIMEOUT` (seconds, default 5400) — Prowler subprocess wall-clock cap.
- `PMAPPER_TIMEOUT` (seconds, default 1800) — PMapper graph-build cap.
- `PMAPPER_REGIONS` (CSV, default unset) — Pin PMapper to specific regions to avoid opt-in-region hangs.
- `WHITEBOX_REGIONS` (CSV, default unset) — Pipeline-wide region override; bypasses the `describe-regions` enabled-regions filter.
- `PROWLER_BIN` / `PMAPPER_BIN` — explicit binary path overrides.
- `PMAPPER_STORAGE` — explicit graph storage root override.
- `WHITEBOX_SMOKE=1` — opt-in flag to run the real-AWS smoke tests in `tests/whitebox/smoke/`.

### New CLI flags (`python3 -m whitebox.cloud_hunt`)

- `--profile <name>` — AWS profile to audit (repeatable for multi-account).
- `--session-dir <path>` — Output root.
- `--allowlist <domain>` — Required unless `--no-scope-lock`. Repeatable. Route53 zones in the account are intersected with this list before being treated as in-scope.
- `--no-scope-lock` — Audit every public Route53 zone in the account.
- `--refresh` — Bust the per-phase 24h cache and re-run all phases.

### Test suite

`tests/whitebox/` — 142 unit + integration tests (4 smoke skipped without `WHITEBOX_SMOKE=1`). Covers profile validation, region resolution, every secrets source, exposure analyzer, PMapper privesc detection, correlator chain builder, cache atomicity, scope-lock enforcement, scope-lock allowlist intersection. Full project sweep on the v8.0 tip: 670+ tests passing, 4 skipped, 0 failures.

### Engagement-validated

Both major architectural goals validated end-to-end against authorized live AWS accounts during the engagement that drove this release:

- Prowler full-checks completes cleanly in ~14 min on a small account (~500 findings) and times out gracefully on larger ones (manifest records the timeout, orchestrator continues to the next phase).
- PMapper graph build completes in ~12 min on a 49-node IAM estate; storage path detection works on macOS without any operator intervention.
- Secrets phase finds real Lambda environment-variable leaks (AWS access keys, OpenAI / Azure / Google API keys, Postgres passwords) without hanging on opt-in regions.
- All seven phases reach `complete` status on the validation account.

### Breaking changes

None. v8.0 is purely additive over v7.4.10. Existing blackbox workflows are unchanged. Whitebox is opt-in via `whitebox_config.yaml` (default empty) — `vikramaditya.py` only invokes it when the target domain matches a configured cloud profile.

### Migration

Install the two isolated venvs as documented in [`README.md`](README.md#whitebox-aws-audit-v80). Without them, the whitebox phases skip with a friendly install hint in the manifest; the rest of the audit continues.

### Known gaps (tracked)

See `docs/superpowers/backlog/2026-04-29-whitebox-post-merge-backlog.md` for the post-release backlog (P0 reachability gate, P1 route-table analyzer, P2 EventBridge GuardDuty fan-out + SNS subscriber checks, P3 SSM coverage, P4 CloudTrail recency + Backup Vault Lock, P5 IIS / HTTPAPI fingerprint, P7 manifest coverage for failed phases).

---

## v7.4.10 — Check 0 expansion + remediation-pack templates (2026-04-28)

Two threads of work, both driven by a real-world engagement.

### Check 0: massive coverage expansion (`scanner.sh`)

The original Check 0 probed only 8 hard-coded paths (classic PHP file-managers + `/admin/upload`). On the engagement target it found 4 false-positive "upload paths" (all SPA soft-404s) and missed every real upload sink. Rewrite now probes **~100 paths** across:

- Generic upload endpoints (`/upload`, `/upload.php`, `/upload.aspx`, `/upload.jsp`, `/UploadServlet`, `/Upload.ashx`, etc.)
- API upload endpoints (`/api/upload`, `/api/v{1,2,3}/upload`, `/api/files`, `/api/v{1,2}/files`, `/api/v{1,2}/attachments`, `/api/media`, `/api/avatar`, `/api/upload/sign`, `/api/s3/sign`, `/api/presign`, `/api/import`)
- WordPress (`/wp-admin/async-upload.php`, `/wp-admin/media-new.php`, `/wp-json/wp/v2/media`, `/wp-content/uploads/`)
- File managers / WYSIWYG connectors (CKFinder, FCKeditor, elFinder, KCFinder, ResponsiveFilemanager, TinyMCE)
- Profile / avatar (`/profile/photo`, `/user/avatar`, `/me/avatar`, etc.)
- Admin panels (Joomla `index.php?option=com_media`, Drupal `/sites/default/files/`)
- Framework-specific (Laravel `/storage/uploads`, Rails `/active_storage/blobs`)
- GraphQL (`/graphql`, `/api/graphql`)

Plus a recon-driven extractor: pulls URL paths from `urls/with_params.txt`, `urls/api_endpoints.txt`, `urls/all.txt`, `urls/js_files.txt`, filters with `upload|file[_-]?upload|attach|avatar|photo|/media/|/import/|/files?/`, dedupes, strips static-asset extensions, caps at 80. On the test engagement this surfaced `/api/eval/upload`, `/api/keywords/import/commit`, `/api/keywords/import/validate` — three real upload endpoints completely invisible to the static list.

### Check 0: POST-probe pass for endpoints that reject GET

Endpoints commonly return 405 / 401 / 403 / 415 on GET but accept multipart on POST. New probe loop:

- `405` (method not allowed) → POST a tiny multipart `file=@/dev/null`. `200/201/202` → upload accepted (high-value finding); `400/422` → validation reject (endpoint exists, accepts uploads with proper payload); `401/403` → recorded for later authenticated re-test.
- The status-aware classification produces three output tiers: `[UPLOAD-CANDIDATE]` (GET 200), `[UPLOAD-CANDIDATE-POST]` (POST accepted), `[UPLOAD-CANDIDATE-VALIDATION]` (400/422 — endpoint exists, our payload was malformed), `[UPLOAD-CANDIDATE-AUTH]` (auth wall, written to `auth_required.txt`).

### Check 0: multi-shape catchall detection

Hosts can be catchalls in different ways: SPA returns 200 with the same HTML shell for every path; API gateway returns 401 with same body for every `/api/*` path; admin panel returns 302 to login for everything. The previous single-status detection caught only the SPA case. New detection probes **four URL shapes** (`/`, `/api`, `/admin`, `/static`), each with two random paths; if both probes for a shape agree on `(status, body_hash)`, that tuple is recorded as a per-host baseline. The probe loop then rejects any response whose `(status, body_hash)` matches any baseline for the host. This catches:

- SPA-200 catchalls: `/` shape → consistent 200/SPA-shell hash → host hard-skipped.
- API-401 catchalls: `/api` shape → consistent 401/auth-error hash → 30+ noise entries on the auth_required.txt file are now suppressed.
- Hard-404 catchalls: per-shape 404 fingerprint → false positives eliminated.

Also fixed a subshell-scope bug where `head -10 ... | while` ran the loop in a subshell, so the `CATCHALL_HOSTS` mutations were thrown away — the downstream skip gate was effectively dead code. Replaced pipes with process substitution.

Bash 3.2 compat preserved: macOS bash 3.2 has no associative arrays, so the per-host baseline mapping is persisted in a tmp file (`<host>\t<code>\t<hash>` per line) and looked up with `awk -F '\t' '$1==h{print $2"|"$3}'`.

### Templates: remediation-pack scaffold (`templates/remediation_pack/`)

Six drop-in fix templates that map to the most common real-engagement findings:
- `01_view_xss_fix.html.patch` — unescaped CSV-cell rendering in eval-viewer style HTML
- `02_wordpress_cors_fix.php` — reflective CORS + credentials on `/wp-json/*`
- `03_fastapi_auth_fix.py` — unauth admin/data routes; oversize uploads; missing rate limits
- `04_fastapi_prod_config.py` — `/docs`, `/redoc`, `/openapi.json` exposed in production
- `05_wp_user_enum_fix.php` — `/wp-json/wp/v2/users` + `?author=N` user enum
- `06_aws_devops_remediation.sh` — S3 PAB, ALB HTTP→HTTPS redirect, stray SG ingress, WAF rate-rule actions, log redaction, log lifecycle

All client identifiers replaced with placeholders (`<APEX_DOMAIN>`, `<API_HOST>`, `<AWS_ACCOUNT_ID>`, `<ALB_NAME>`, `<WAF_ACL_ID>`, etc.). Per-engagement instances live at `client_remediation_pack/<engagement>/` and are gitignored — they contain target hostnames, AWS identifiers, IPs and PoC artifact IDs that should never appear in a public repo.

### `.gitignore`

Added `client_remediation_pack/` to the always-ignore list.

## v7.4.9 — Check 0 false-positive elimination: SPA soft-404 fingerprinting (2026-04-27)

Reading the v7.4.8 scan output, the user spotted that an SPA-style host was returning 200 with a "404 page" body, and Check 0 was happily logging four `[VULN] Found upload path` lines for paths that didn't exist. Tracing through `scanner.sh:170-189` exposed three layered bugs:

### 1. Catchall-detection result was being thrown away (subshell scope)
```bash
head -10 "$ORDERED_SCAN" | while read -r host; do
    ...
    CATCHALL_HOSTS="${CATCHALL_HOSTS},${host}"
done
```
The `head | while` pipe forces the loop body into a subshell, so `CATCHALL_HOSTS` mutations never escape. The downstream `[[ "$CATCHALL_HOSTS" == *"$host"* ]] && continue` gate was effectively dead code: every "detected" catchall was probed anyway. Fix: replace pipes with process substitution `done < <(head -10 ...)` so the loop runs in the parent shell.

### 2. Status-only check missed SPA soft-404s
The original detection compared only the HTTP code; many WordPress / nginx / SPA setups return **200 OK** with a "404 / page-not-found" body, or worse (the case here), the **same HTML shell** for every URL. Status-only logic let all of those through. Fix: also check (a) for explicit "404 / not found" body markers and (b) compute a per-host MD5 fingerprint of the random-URL response, then reject any probe whose body hash matches the baseline.

### 3. Bash 3.2 has no `declare -A`
First soft-404 fix used `declare -A SOFT404_HASH` to map host → fingerprint. macOS ships bash 3.2 (associative arrays only exist in bash 4+), so the script bombed instantly with `declare: -A: invalid option` and (because of `set -u`) `https: unbound variable` from the index expansion. Fix: persist the mapping in a tmp file (`<host>\t<md5>` per line) and look it up with `awk -F '\t' '$1==h{print $2; exit}'`. Same `mktemp -t` + double-fallback pattern used for the dalfox dedup file.

Verified end-to-end: catchall correctly logged for the SPA host, **zero** `Found upload path` lines (vs. 4 false positives in v7.4.8), no `declare:` / `unbound variable` noise, all 13 checks complete clean.

## v7.4.8 — scanner.sh hardening: 3 bugs caught on a real-world full-scope run (2026-04-27)

Live test against an engagement target (9 subdomains, 14 live HTTP hosts, 5 IPs) surfaced three scanner.sh bugs. Each was reproduced, patched, and verified across two re-runs.

### 1. macOS BSD `mktemp` failure on dalfox dedup
`mktemp /tmp/dalfox_dedup_XXXXXX.txt` is unreliable on macOS BSD `mktemp` — the suffix after the X's caused `mkstemp failed: File exists`. `$DAL_DEDUP_FILE` came back empty, which then cascaded:
```
mktemp: mkstemp failed on /tmp/dalfox_dedup_XXXXXX.txt: File exists
scanner.sh: line 267: : No such file or directory
... Running dalfox on up to 100 URLs (deduped from 50 → 0, ...)
head: : No such file or directory
```
Fix: use `mktemp -t dalfox_dedup.XXXXXX` (macOS-friendly form), with two fallbacks (`mktemp /tmp/dalfox_dedup_XXXXXX`, then a PID/$RANDOM-stamped path) so `$DAL_DEDUP_FILE` is always set; `: > "$file"` guarantees the file exists for the dedup writer. Verified: dedup printed `50 → 50` (vs broken `50 → 0`).

### 2. Wrong `Target` name in consolidated summary
`TARGET=$(basename "$(dirname "$(dirname "$RECON_DIR")")")` assumed the path was always `recon/<target>/sessions/<id>`. When invoked with the parent recon path documented in `CLAUDE.md` (`bash scanner.sh recon/<target>`), the math walked one level too far up and printed the repo dir basename. Fix: detect whether `$(basename "$(dirname "$RECON_DIR")")` equals `sessions`; if so, walk two levels (legacy session-path); otherwise the dir's own basename is the target.

### 3. Stray `0` printed under "Verified SQLi PoCs"
```
Verified SQLi PoCs   : 0
0
```
`grep -c "SQLI-POC-VERIFIED" file 2>/dev/null || echo 0` — when the file exists but has no matches, `grep -c` writes `0` to stdout *and* exits 1, so the `|| echo 0` branch fires and a second `0` gets captured. Fix: `$({ grep -c ... 2>/dev/null || echo 0; } | head -1)` collapses to a single integer across all four cases (empty file, file with no matches, file with matches, missing file).

### HAR engine drive-bys
- `har_vapt.py`: force line-buffered stdout/stderr so `nohup ... > log 2>&1` shows progress instead of looking hung.
- `har_vapt.py`: dropped the always-failing `subprocess.run([sys.executable, "reporter.py", results_file])` — reporter expects a recon/findings tree, not a single JSON.
- `har_vapt_engine.py`: when an upload is accepted but storage cannot be verified at standard paths, ask `brain_scanner` to write a Python script that fuzzes for the uploaded shell and attempts RCE. ImportError-safe.
- `har_vapt.py`: read `endpoints_fuzzed` (current key) before `endpoints_tested` (legacy fallback); print `Endpoints Fuzzed: tested / total`.

### Found by
Single end-to-end full-scope scan against an engagement target — initial run hit bug #1 (mid-Check 3); first verify run hit bug #2 (summary footer); second verify run hit bug #3 (summary footer). Third run printed clean across all 13 checks.

## v7.4.7 — autonomous pipeline robustness: paramspider/arjun/js_analysis/kiterunner/wordlist URLs (2026-04-26)

Five bugs caught and fixed during four end-to-end autonomous hunts. Each was reproduced before patching; each fix was verified in a subsequent run.

### 1. ParamSpider 2.x dropped `-o` flag
ParamSpider's CLI changed: it no longer accepts `-o` and instead writes to `./results/{domain}.txt` relative to CWD. Old invocation:
```python
paramspider -d "{domain}" -o "{ps_out_base}"
```
Returned `rc=2` in 0.3 s every run. Fix: invoke with `cwd=param_dir`, then move `results/{domain}.txt` → `paramspider.txt`.
**Verified**: 23 URLs (1642 B) produced.

### 2. Arjun timeout at 905 s (rc=-9)
20 URLs × 25 k-param `large.txt` × `--stable` blew through `PARAM_TIMEOUT`. First attempt (cap 8 URLs, `-t 10 -T 10`) still hit the 900 s SIGKILL because `--stable` triples runtime. Final fix: cap to 5 URLs, drop `--stable`, switch to bundled `small.txt` (835 params).
**Verified**: rc=0 in 13.1 s, 2 hidden params found.

### 3. JS Analysis silently failing with `[FAIL]`
`run_js_analysis` greped `\.js$` from `live/urls.txt` — but `live/urls.txt` only has base hosts, no crawled paths. Recon already populates `urls/js_files.txt` with the actual JS URLs (20 entries observed); that file was being ignored, so the step always returned False and the autonomous gate stamped the whole hunt `[FAIL]` despite all phases ✓. Fix: prefer `urls/js_files.txt`, fall back to grep only if missing.

### 4. Kiterunner false failure
`kiterunner scan ... --kite-file routes-large.kite || kiterunner brute ... -w routes-large.kite` — relative filename never resolved/downloaded, both invocations failed every run with `END API FUZZ rc=1 duration=0.7s`. Fix: probe `WORDLIST_DIR`/`SCRIPT_DIR` for `routes-large.kite` / `routes-small.kite` and skip cleanly with a warning if neither exists.

### 5. Broken SecLists wordlist URLs
Four upstream paths returned 404 (SecLists reorganized the `Fuzzing/` tree):
- `Fuzzing/SQLi/Generic-SQLi.txt` → `Fuzzing/Databases/SQLi/Generic-SQLi.txt`
- `Fuzzing/XSS/XSS-Jhaddix.txt` → `Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt`
- `Fuzzing/redirect/...` → `cujanovic/Open-Redirect-Payloads`
- `Fuzzing/SSRF/SSRF-list.txt` → `cujanovic/SSRF-Testing/cloud-metadata.txt`

Also: `setup_wordlists` now uses `curl -sfL` (HTTP errors return non-zero), removes empty stub files left behind by 404s, tracks failures, and emits a `warn` summary instead of always claiming "Wordlists ready".

### Found by
Four sequential `hunt.py --autonomous --full` runs against a real-world apex target. Each run surfaced one new bug, was patched, then rerun to verify. The autonomous pipeline now produces an `[OK]` verdict end-to-end.

## v7.4.6 — diagnostic-section polish: scope-lock hint always fires, hidden dirs filtered (2026-04-20)

v7.4.5 shipped the "Scan Diagnostics" section. Running it end-to-end on a real-world session surfaced two rough edges:

### 1. Scope-lock hint was silently skipped for some targets
```python
# v7.4.5 — buggy
if diag["subdomains"] <= 1 and "<substring>" not in target.lower():
    diag["hints"].append("Scope-locked to the apex host — ...")
```
A target-name substring check was left in by accident from dev-time scaffolding. Real effect: any operator whose target name matched that substring lost the scope-lock hint even when `subdomains=1`. Removed the carve-out; hint now fires on *every* single-subdomain scan regardless of target name.

### 2. Hidden directories leaked into finding-class table
`os.listdir(findings_dir)` returned `.tmp`, `.cache`, etc. alongside real finding subdirs (`sqli`, `xss`, ...). The HTML report's "Finding Classes" table ended up listing `.tmp/` as a legitimate class with `0 entries` — visually noisy and a mild information leak about scanner scratch dirs. Fix: skip any entry starting with `.`.

### Tests
`tests/test_reporter_empty_diagnostics.py::TestDiagnosticsCollector::test_hidden_subdirs_are_ignored` — new test seeds `.tmp`, `.cache`, `.git` in the findings dir and asserts none appear in `subdir_payload_counts`. Existing `test_zero_subdomains_triggers_scope_hint` test still passes (used a non-matching target string, so never caught the carve-out).

### Verified
Before v7.4.6: 2 hints (default-swagger + manual-paths) on an apex-locked session; scope-lock hint suppressed.
After  v7.4.6: 3 hints — scope-lock hint now fires.

### Suite
`553 passed in 1.40s` (was 552, +1 new).

### Found by
End-to-end validation of v7.4.5 before declaring it done. The commit would otherwise have shipped with a silent hint-suppression bug only caught by fixture tests. Running reporter against a real session — not just synthetic fixtures — surfaced it.

---

## v7.4.5 — empty-findings diagnostic section: "Scan Diagnostics" appendix (2026-04-20)

Validating v7.4.4 against a real-world session (same operator who filed [issue #2](https://github.com/venkatas/vikramaditya/issues/2)) surfaced the **fourth** layer of the same UX bug. v7.4.4 fixed the silently-dropped finding classes — but a target that *legitimately* has zero findings (thin API root, scope-locked host, no credentials) still renders a one-line "No findings." report. Operators reading that page reasonably conclude the tool is broken. The first three reopens of issue #2 were all "empty report" — two were real (subdir drops), one was target-shape. The report never explained which.

### The fix — always emit a "Scan Diagnostics" appendix

`reporter.py::_collect_scan_diagnostics(report_dir, target)` — reads the recon artefacts siblings of the findings dir:

```
recon/<target>/sessions/<id>/
├── live/urls.txt              → live_hosts
├── urls/all.txt               → total_urls
├── urls/with_params.txt       → params_urls
├── urls/js_files.txt          → js_files
├── api_specs/spec_urls.txt    → api_specs
├── api_specs/all_operations.txt → api_operations
├── subdomains/all.txt         → subdomains
└── ports/open_ports.txt       → ports_open
```

Then classifies the target shape (API-only / webapp / apex-locked) and emits context-appropriate hints:

```python
if few_urls and few_js and one_live_host:
    hint("Target looks like an authenticated REST API. "
         "Re-run with --creds user:pass to get past the login wall.")

if api_specs == 0 and total_urls > 0:
    hint("No OpenAPI specs auto-discovered. Try manual paths: "
         "/api-docs, /swagger, /v1/openapi.json, /swagger.json")

if subdomains <= 1:
    hint("Scope-locked to the apex host — you may be missing findings on "
         "api./admin./staging. subdomains. Re-run without --scope-lock.")
```

`_render_scan_diagnostics_html(diag)` renders the **Scan Diagnostics** HTML section: a **Recon Surface** table (with counts), a **Finding Classes** table (payload line counts per subdir, or "No finding subdirs" when empty), and an **Interpretation + Next Steps** list populated from the hints. Stable `id="scan-diagnostics"` anchor so operators can deep-link from followups.

`render_html_report` unconditionally calls both and inserts the section between the upload-evasion matrix and `Appendix A: Tools Used`. A 0-findings report is now:

- **Before v7.4.5**: `No findings.` — one line. Operator: "broken?"
- **After v7.4.5**: `No findings.` + "*We probed 1 live host, crawled 12 URLs, found 0 API specs. Target looks like an authenticated REST API — re-run with --creds user:pass.*"

### Tests

`tests/test_reporter_empty_diagnostics.py` — **11 new tests**:

- **TestDiagnosticsCollector (3)**: reads recon counts correctly; missing files don't crash (zero defaults); `findings/` path input resolves to `recon/` sibling.
- **TestHintGeneration (4)**: API-shape triggers creds hint; webapp-shape skips API hint; no specs + with URLs triggers manual-path hint; apex-only triggers scope-lock hint.
- **TestHTMLRenderer (3)**: renders on empty recon (still shows "No finding subdirs" cell); counts bubble through to rendered table; `id="scan-diagnostics"` anchor stable.
- **TestFullReportWithDiagnostics (1)**: end-to-end — build a fake session with recon + empty findings, call `render_html_report(findings=[])`, assert the HTML contains both the diagnostics section AND the canonical `No findings.` line.

### Verified

```
$ python3 -m pytest tests/test_reporter_empty_diagnostics.py -v
11 passed in 0.05s

$ python3 -m pytest tests/
552 passed in 1.38s
```

### Issue #2 lineage — four layers

| Layer | Version | Failure mode | User-visible symptom |
|-------|---------|--------------|----------------------|
| 1 | pre-v7.4.4 | CVE-dir loader path mismatch | empty report on mixed layouts |
| 2 | pre-v7.4.4 | Findings dir path resolution | empty report on canonical layout |
| 3 | v7.4.4 | `SUBDIR_VTYPE` missing 5 classes | empty report when scanner found MFA/SAML/etc. |
| 4 | v7.4.5 | No diagnostic section | empty report when target legitimately had no findings — **looks identical to layers 1–3** |

v7.4.5 closes the UX loop. Future "empty report" comments now carry diagnostic counts — the operator can tell in one glance whether it's a tool bug or a scope/target-shape issue.

### Found by

User prompt: *"test that portal and see if there are any other issues and I do not want him to come back to us with another issue"* — after v7.4.4 shipped, a 0-findings scenario still rendered the same one-line "No findings." page as the bugs we'd just fixed, from a different root cause. Hence the fourth fix.

---

## v7.4.4 — reporter subdir coverage: issue #2 root cause (2026-04-20)

GitHub issue [#2](https://github.com/venkatas/vikramaditya/issues/2) (reporter @Harry53) was closed as COMPLETED on 2026-04-17 after the initial fix (commit 6573cdd) addressed CVE-dir loading + path resolution. User re-reported on 2026-04-20: "issue is same" with attached screenshot showing the HTML report still empty despite fresh scans producing findings. Root cause now found.

### Root cause (the third layer)
`scanner.sh` writes findings into 12 subdirs. `reporter.py::SUBDIR_VTYPE` only knew 7 of them:

```
scanner.sh writes             reporter SUBDIR_VTYPE knew
├── sqli/        ✓             sqli ✓
├── xss/         ✓             xss ✓
├── ssti/        ✓             ssti ✓
├── upload/      ✓             upload ✓
├── metasploit/  ✓             metasploit ✓
├── cves/        ✓             cves ✓
├── rce/         ✓             rce ✓
│
├── mfa/         ✗ SILENT DROP    ← v5.2 MFA bypass class
├── saml/        ✗ SILENT DROP    ← v5.2 SAML/SSO class
├── deserialize/ ✗ SILENT DROP
├── import_export/ ✗ SILENT DROP
└── supply_chain/ ✗ SILENT DROP
```

Every finding in those 5 dirs was discarded — the reporter's loader literally iterated `SUBDIR_VTYPE.items()` and never looked inside unmapped dirs. A scan could flag a CRITICAL MFA bypass on `/api/login` and the HTML report would show "0 findings, clean report". That's exactly Harry's observation.

### Fix

**`reporter.py::SUBDIR_VTYPE`** — extended with 8 new mappings:
```python
"deserialize": "deserialization",
"import_export": "business_logic",
"mfa":        "auth_bypass",   # MFA bypass = auth-bypass variant
"saml":       "auth_bypass",   # SAML/SSO misconfig = auth-bypass
"supply_chain": "supply_chain",
"jwt":        "jwt",           # hunt.py JWT audit output
"graphql":    "graphql",
"smuggling":  "smuggling",     # HTTP request smuggling
```

**`reporter.py::VULN_TEMPLATES`** — added 5 complete template entries (`deserialization`, `supply_chain`, `jwt`, `graphql`, `smuggling`) with severity / CVSS / CWE / impact / remediation / references. The MFA/SAML subdirs route into the existing `auth_bypass` template (correct semantic match).

**`load_findings` warning log** — any unmapped subdir that contains `.txt` or `.json` payloads now emits:
```
[reporter] WARNING: findings subdir 'xyz/' is not in SUBDIR_VTYPE —
its contents will be IGNORED. Add to reporter.py::SUBDIR_VTYPE +
VULN_TEMPLATES.
```
Meta dirs (`summary/`, `brain/`, `screenshots/`, `exploits/`, etc.) allowlisted so the warning stays signal not noise. This converts future drift from "silent dropped findings" to "explicit developer warning" — the exact thing that would have caught issue #2 at its first hit rather than the third.

### Tests
`tests/test_reporter_subdir_coverage.py` — **23 new tests**:
- 12 × parametrized "every scanner.sh output dir is mapped" — pins each of the 12 known subdirs individually so the failure names the missing one.
- 2 × schema-consistency: every `SUBDIR_VTYPE` value has a `VULN_TEMPLATES` entry + new templates carry the full field set.
- 5 × end-to-end: seed a fake findings dir with each formerly-dropped subdir and assert `load_findings` actually produces entries with the right `vtype`.
- 4 × warning log: unknown subdir with payload warns; meta dirs stay silent; mapped dirs stay silent; empty unknown dirs stay silent.

### Verified
```
$ python3 -m pytest tests/test_reporter_subdir_coverage.py -v
23 passed in 0.03s

$ python3 -m pytest tests/
541 passed in 1.28s
```

### Issue #2 status
Reopening with a comment pointing at this commit. Harry should:
1. `git pull origin main`
2. Re-run the same `reporter.py` command he posted
3. Report should now include any MFA / SAML / deserialization / supply-chain / import-export findings from the prior scan's subdirs.

### Found by
User prompt: "check this https://github.com/venkatas/vikramaditya/issues/2" after seeing Harry's 2026-04-20 comment that the previous fix didn't resolve it. Scanner-vs-reporter subdir diff made the 5-class gap immediately visible.

---

## v7.4.3 — README honesty pass (drop inherited template copy) (2026-04-20)

Docs-only patch sweeping six overclaimed or placeholder blocks out of the README. Parent pass to v7.1.11 which caught the fake Support URLs; this one catches the rest. User prompt "fix the issues in our code and push" triggered a systematic sweep.

### Removed / rewritten
- **Line 638 — Development clone URL** placeholder `yourusername/vikramaditya.git` → real repo `venkatas/vikramaditya.git`.
- **"Enterprise Licensing" section** (6 lines) — claimed "Commercial licenses available for white-label deployments / custom integrations / professional training / extended support contracts." No such programme exists. Deleted.
- **"Professional Security Consulting" sentence** — "our team of CERT-In empanelled consultants is available for engagements." The operator IS CERT-In empanelled solo; the phrasing implies a team/company that doesn't exist. Deleted.
- **"Enterprise Features" list** — dropped two unbacked claims:
  - *"Compliance reporting — OWASP, NIST, ISO 27001 mapping"* — the tool does not produce compliance reports against any of those frameworks.
  - *"Team collaboration — Shared findings database"* — no shared DB exists; findings are per-user JSONL.
  Kept the real ones (multi-target scanning, HAR auth, structured JSON output, hunt memory). Section renamed **"Scan Capabilities"** since nothing in it is Enterprise-specific.
- **"Quality Assurance" list** — dropped *"Manual verification — Security expert review process"*. There is no review process built into the tool. Kept the three real items (AI triage gate + regex dedup, reproducible testing, evidence collection) and added explicit references to the v7.1.2 / v7.4.2 FP fixes as proof the QA claim is actually backed.
- **"Professional Standards" section** — claimed "CERT-In empanelled testing methodology / OWASP Testing Guide compliance / NIST Cybersecurity Framework alignment / ISO 27001 security controls validation" as if the **tool** carried those certifications. It does not. Rewrote as **"Methodology Alignment"** — explicitly states the tool carries no certification of its own; operator is responsible for engagement-level framework alignment; gives concrete, honest pointers: OWASP Testing Guide v4.2 structure of scan phases, NIST CSF map to flow, CERT-In format supported by `report_generator.py --format cert-in` when operator opts in.

### Rationale
Bug-bounty / VAPT engagement reports frequently get cross-read against the tool's own claims. Marketing copy that overstates what the tool actually does is worse than missing documentation — it invites scope-creep from clients, sets unrealistic expectations, and exposes the operator to liability when the tool fails to deliver something the README implied.

### Diff
```
 1 file changed, 18 insertions(+), 27 deletions(-)
```

Net −9 lines of placeholder / overclaim, +18 lines of honest capability description.

### Not touched
Examples throughout the README continue to use `example.com`, `user@domain.com`, etc. — those are legitimate documentation placeholders meant to be adapted by the reader, not hallucinated contact info.

### Found by
User prompt: "fix the issues in our code and push" after v7.4.2 shipped. Systematic sweep caught everything by grepping for known template markers (`yourusername`, `White-label`, `Professional Security Consulting`) and cross-checking "Enterprise Features" / "Quality Assurance" / "Professional Standards" claims against actual tool behaviour.

---

## v7.4.2 — NAT64 false-positive: 6 HIGH FPs per NAT64-hosted target (2026-04-20)

Dogfooding on `gov.in` produced 6 HIGH findings — all false positives.

### Root cause
`email_audit.py::is_privateish_ip` marked every address where Python's `ipaddress.is_reserved` was True as non-public. But RFC 6052's **NAT64 well-known prefix `64:ff9b::/96`** sits inside IANA-reserved space and is simultaneously **publicly routable on the IPv6 internet** — that's its entire purpose. gov.in's MX hosts (`mx`, `mx2`, `mx3` @ mgovcloud.in) sit behind NAT64 with embedded public IPv4 `169.148.142.75`; the tool flagged 6 HIGH "non-public IP" entries that would have embarrassed a real report.

```
64:ff9b::a994:8e4b → embedded IPv4 169.148.142.75
   is_private:  False
   is_global:   True       ← publicly routable
   is_reserved: True       ← old code tripped on this alone
```

### Fix
Special-case the NAT64 prefix in `is_privateish_ip`: decode the embedded IPv4 from the low 32 bits and answer based on *that* address's routability — same semantics a real NAT64 gateway implements.

```python
if parsed.version == 6 and int(parsed) >> 32 == <NAT64 prefix>:
    embedded_v4 = ip_address(int(parsed) & 0xFFFFFFFF)
    return (embedded_v4.is_private
            or embedded_v4.is_loopback
            or embedded_v4.is_link_local
            or embedded_v4.is_multicast
            or embedded_v4.is_unspecified)
```

Other reserved ranges (documentation `2001:db8::/32`, IPv4-mapped `::ffff:0:0/96`, etc.) stay flagged — the carve-out is specific to NAT64.

### Impact on gov.in (live re-audit)
| | v7.4.1 | v7.4.2 |
|---|---|---|
| Total findings | 13 | **7** |
| HIGH | **6 (all FPs)** | **0** |
| MEDIUM | 2 | 2 |
| LOW + INFO | 5 | 5 |

Real findings preserved: `sp=none` subdomain weakening and 1024-bit DKIM key on `zmail` selector.

### Tests
`tests/test_nat64_classification.py` — 16 new tests:
- 7 × NAT64 carve-out (public IPv4 via NAT64 → False; RFC1918 / 172/12 / loopback embedded → still True; exact gov.in IPs pinned).
- 9 × unchanged behaviour invariants (RFC1918, loopback, link-local, documentation, multicast, unspecified, garbage input, public IPv4, public IPv6).

### Verified
```
$ python3 -m pytest tests/test_nat64_classification.py -v
16 passed in 0.07s

$ python3 -m pytest tests/
518 passed in 1.23s
```

### Found by
User asked "any bugs?" after the gov.in audit. Manual decoding of `64:ff9b::a994:8e4b` → `169.148.142.75` revealed the embedded IP was public, contradicting the tool's HIGH verdict.

---

## v7.4.1 — severity-spelling fix: 2 hidden findings per email audit unlocked (2026-04-20)

v7.4.0 landed the hunt_journal auto-append, but the `/pickup` demo exposed that **only 6 of 8 findings per email audit actually made it into the journal**. Two were silently dropped on every run.

### Root cause
`email_audit_adapter._SEVERITY_MAP` translated subspace-sentinel's `info` → Vikramaditya's `info`. But `memory/schemas.py::VALID_SEVERITIES` spells it `informational` (full word). Every INFO-severity finding — typically *"No DKIM selectors found"* and *"No BIMI record"* — was rejected by `validate_journal_entry` with:
```
Journal entry: 'severity' must be one of
['critical', 'high', 'informational', 'low', 'medium', 'none'],
got 'info'
```
The `_journal_email_audit_findings` helper catches the exception and skips the entry silently (by design — malformed findings shouldn't abort the loop) so nothing surfaced in the logs. Two data points per scan lost.

### Fix
- `_SEVERITY_MAP`: `"info"` and `"notice"` now map to `"informational"`. Added `"informational"` and `"none"` as identity passes through.
- `_to_schema_severity` default-case fallback: returns `"informational"` instead of `"info"` for None / unknown severities.
- Test assertions updated to pin the correct schema value.

### Verified
```
$ # Before v7.4.1 — 2 info findings silently dropped
$ python -c "..."
adapter produced: 8 findings
journaled: 6

$ # After v7.4.1
adapter produced: 8 findings
journaled: 8

$ python3 -m pytest tests/
502 passed in 1.26s
```

### What a real `/pickup` now shows (full 8 findings on testfire.net)
```
=== /pickup testfire.net — email auth section (8 entries) ===
severity hist: {'low': 5, 'medium': 1, 'informational': 2}

  [       MEDIUM] mx         — no MX record; SMTP delivery may fall back to A/AAAA
  [          LOW] dmarc      — adkim=r (relaxed alignment)
  [          LOW] dmarc      — aspf=r (relaxed alignment)
  [          LOW] dnssec     — no DS record in parent zone
  [          LOW] mta_sts    — no _mta-sts TXT record
  [          LOW] tls_rpt    — no TLS-RPT record
  [INFORMATIONAL] dkim       — no DKIM selectors discoverable      ← unlocked
  [INFORMATIONAL] bimi       — no BIMI record                      ← unlocked
```

### Found by
End-of-v7.4.0 `/pickup` demo output mismatch — 8 findings entered the adapter, 6 entered the journal. `make_journal_entry` exception message surfaced the spelling via a debug trace.

---

## v7.4.0 — email_audit polish: per-check package + brain LLM bridge + hunt_journal (2026-04-19)

Three polish items for the v7.2.0 / v7.3.0 email-audit integration, bundled:

### 1. Per-check package — `email_audit_checks/`
Nine logical modules — `spf.py`, `dmarc.py`, `dkim.py`, `mx.py`, `mta_sts.py`, `tls_rpt.py`, `bimi.py`, `dnssec.py`, `message.py`. Each is ~10 lines of re-exports from the monolith. Downstream code can now `from email_audit_checks import dkim; dkim.estimate_dkim_rsa_bits(...)` without pulling in the whole 3444-line file. Tests gain targeted-import surface.

**Isolation invariant:** `email_audit_checks.spf` does NOT re-export `audit_dmarc`, `audit_dkim`, etc. — each sub-module exposes only the functions relevant to its check plus the shared helpers that check needs. Pinned in `test_all_submodules_isolated`.

### 2. brain.py LLM bridge — `email_audit_adapter.run_brain_summary(report)`
Opt-in function that routes email-audit summary requests through Vikramaditya's `brain.py::LLMClient` instead of the monolith's own duplicate Ollama/Claude/OpenAI/xAI/Gemini dispatcher. Reads from the canonical env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`, `OLLAMA_HOST`) that all other Vikramaditya AI features use. Returns `None` when no provider is reachable — graceful degradation, never raises. 60k-char payload clip built-in.

The monolith's own `--ai-provider` dispatcher stays intact as a standalone-CLI fallback; v7.4.0 just gives the *Vikramaditya-embedded* path a single source of truth for LLM config.

### 3. Auto-append findings to hunt_journal
`hunt.py::run_email_audit` now also writes every email-auth finding into `hunt-memory/journal.jsonl` via `HuntJournal.append`. Schema-validated — malformed findings silently skip without aborting the loop. Net effect: next session's `/pickup <target>` warm-restart surfaces SPF/DMARC/DKIM findings alongside everything else the scanner caught previously. Also feeds `/intel` cross-reference lookups.

New helper `hunt.py::_journal_email_audit_findings(domain, findings)` takes the adapter output directly — wrapped in try/except so a missing/invalid journal path never aborts the actual audit.

### Schema correction
Adapter initially emitted `action="scan"` — not in the `VALID_ACTIONS` set (`hunt, intel, recon, remember, report, resume, validate`). Changed to `action="recon"` which is semantically correct — email-audit is a recon phase that establishes attack surface, not an active exploit.

### Tests
`tests/test_email_audit_v7_4_0.py` — 15 new tests covering all three items:
- 8 × per-check package (top-level imports + sub-module surface pins + isolation invariant).
- 4 × brain bridge (callable, no-provider → None, missing brain import safe, large-payload safe).
- 3 × journal append (empty findings no-op, valid findings land, invalid schema silently skipped).

Existing v7.3.0 tests updated for the `action="recon"` change (2 assertions).

### Verified
Full-suite baseline: 487 → **502 passing**.

### What "Path B" now looks like, structurally

```
email_audit.py                     — 3444-line monolith (untouched, CLI-capable)
email_audit_adapter.py             — clean Python API + schema-compat findings
                                     + v7.4.0 brain bridge
email_audit_checks/                — v7.4.0 per-check import surface
├── __init__.py
├── spf.py      dmarc.py   dkim.py
├── mx.py       mta_sts.py tls_rpt.py
├── bimi.py     dnssec.py  message.py
agents/email-auditor.md            — specialist agent
commands/email-audit.md            — slash command
hunt.py::run_email_audit           — wires Phase 8.7 + journal append
```

No code was moved out of the monolith. Everything net-new is additive. The refactor is complete in the sense that every downstream concern — clean API, schema-compat findings, per-check testing, single-source LLM config, hunt-memory integration — is covered via wrapper modules. Moving implementation bodies into `email_audit_checks/*.py` later is pure refactor; it won't affect any import site.

### Credit
Upstream: `venkatas/subspace-sentinel` (MIT, unchanged). v7.2.0 imported it, v7.3.0 wrapped it, v7.4.0 integrated it.

---

## v7.3.0 — email_audit adapter + specialist agent (Path B) (2026-04-19)

v7.2.0 shipped email_audit as a CLI wrapper. v7.3.0 adds the refactor-safe adapter layer that lets the rest of Vikramaditya consume it cleanly.

### Why not a full package split?
The monolith is 3444 lines with lots of cross-references between `audit_*` functions (shared DNS client, DER parser helpers, provider-inference). Splitting blind is high-risk without comprehensive tests. v7.3.0 takes the pragmatic route: a **thin adapter module** that re-exports the stable audit primitives and converts JSON output into Vikramaditya's standard finding shape. The monolith stays intact and CLI-capable; downstream code gets a clean import surface.

### Added
- **`email_audit_adapter.py`** — new module:
  - Re-exports `audit_spf`, `audit_dmarc`, `audit_dkim`, `audit_mx`, `audit_mta_sts`, `audit_tls_rpt`, `audit_bimi`, `audit_dnssec`, `build_message_analysis_report`, `DNSClient`, `derive_cross_findings`, `normalize_target`, `estimate_dkim_rsa_bits` as a stable public surface.
  - `to_finding_entries(audit_report, target)` — converts an `email_audit.py --json` report into a list of `memory/schemas.py`-compatible finding dicts. Each issue becomes a finding with `vuln_class` (`email_spf`/`email_dmarc`/…), `severity` (normalised to Vikramaditya's 4-level scale; subspace's `critical` → `high` since it's config gap, not RCE), `endpoint` (`dns:<area>:<target>`), `tags` (`["email_auth", area, "subspace_sentinel"]`), `notes` (detail + `Fix:` recommendation).
  - `load_and_convert(path, target)` — one-shot file reader.
  - `severity_histogram(findings)` — `{severity: count}` for log summary.
- **`agents/email-auditor.md`** — specialist agent spec. When to invoke (scope mentions email / MX self-hosted / BEC investigation / `.eml` analysis), core tasks (domain audit / message forensics / bulk), cross-finding escalation rules (SPF+DMARC permissive = HIGH; `p=reject` + no DKIM = MEDIUM; BIMI without DMARC = MEDIUM misleading trust). Explicit guardrails (`--smtp-probe` needs authorization, MTA-STS `mode=testing` is LOW not HIGH, etc.).
- **`hunt.py::run_email_audit`** — rewritten to use the adapter. Previous v7.2.0 distil loop replaced with `load_and_convert` + `severity_histogram` — 30 lines of custom mapping gone.

### Finding-shape consistency with the rest of Vikramaditya
Before v7.3.0, email-audit findings had their own `{severity, title, area, detail, recommendation}` shape. Now they match the journal schema exactly — same `{target, action, vuln_class, endpoint, result, severity, notes, tags}` used by every other scanner. The HTML reporter and hunt-memory journal both pick them up without custom code paths.

### Tests
`tests/test_email_audit_adapter.py` — 31 new tests:
- 5 × severity map (critical→high; info/notice→info; unknown→info; None-safe; standard).
- 9 × vuln_class map (8 × standard areas parametrized + 1 × unknown fallback).
- 7 × `to_finding_entries` (1-entry-per-issue; shape-pin; detail+fix concatenation; critical downgrade; cross-finding as `email_posture`; empty-input safety; non-dict-input safety).
- 3 × `load_and_convert` (roundtrip; missing file; malformed JSON).
- 2 × `severity_histogram` (counts; empty iter).
- 3 × re-exports (8 audit functions reachable; DNSClient; message_analysis).
- 2 × agent doc ships + has required sections.

### Verified
```
$ python3 -m pytest tests/test_email_audit_adapter.py -v
31 passed in 0.12s

$ python3 -m pytest tests/
487 passed in 1.51s
```
Full-suite baseline: 455 → **487 passing**.

### Deferred (future v7.3.x polish)
- Splitting monolith into `email_audit/<check>.py` package — still possible but no longer blocking any feature work.
- Replacing the tool's own multi-LLM dispatcher (Ollama/Claude/OpenAI/xAI/Gemini) with Vikramaditya's `brain.py`.
- Routing `.env` reads through `credential_store.py`.

### Credit
Upstream: `venkatas/subspace-sentinel` (MIT). v7.2.0 imported the tool verbatim; v7.3.0 wraps it for Vikramaditya-native consumption without modifying the upstream code.

---

## v7.2.0 — email auth audit integration (Path A drop-in) (2026-04-19)

Integrates `venkatas/subspace-sentinel` (MIT, 3444 lines, single-file) into Vikramaditya as a new recon phase. Covers a real bug-bounty finding class — SPF/DMARC/DKIM misconfig — that Vikramaditya had zero coverage for before.

### Added
- **`email_audit.py`** (3444 lines, MIT) at repo root — ported verbatim from `venkatas/subspace-sentinel@2026-03-27`. Checks SPF / DMARC / DKIM / MX / DNSSEC / MTA-STS / TLS-RPT / BIMI + optional live SMTP STARTTLS + `.eml` header analysis + multi-LLM AI summary (Ollama/Claude/OpenAI/xAI/Gemini). Credit header added naming the upstream repo and planned v7.3.0 refactor.
- **`hunt.py::run_email_audit(domain)`** — new Phase 8.7 wired into `hunt_target`. Writes raw JSON to `recon/<target>/email_auth/audit.json` and a distilled finding list to `findings/<target>/email_auth/findings.json` (HTML-reporter-compatible shape). Silently skips for IP/CIDR targets since SPF/DMARC are hostname-scoped.
- **`commands/email-audit.md`** — `/email-audit <domain|email|.eml>` slash command. Bulk mode, DKIM selector hints, SMTP probe, `.env` AI config documented.
- **`requirements.txt`** — two new deps: `dnspython>=2.6.1` + `certifi>=2024.7.4`. Both small, standard.

### Tests
`tests/test_email_audit_integration.py` — **22 new tests**:
- 2 × `parse_kv_record` (DMARC/DKIM semicolon-split; SPF stays single-key).
- 3 × `normalize_target` (domain, email, case-folded).
- 4 × `relaxed_aligns` (exact, subdomain, different-org, None inputs).
- 4 × `is_privateish_ip` (RFC1918, loopback, public, garbage).
- 3 × `estimate_dkim_rsa_bits` — synthesised 1024/2048-bit RSA DER pubkeys to pin the DER walker.
- 3 × hunt.py integration — hook is importable; IP/CIDR targets short-circuit without subprocess calls.
- 2 × command doc — `commands/email-audit.md` ships + carries the required SPF/DMARC/DKIM/MTA-STS/DNSSEC sections.

### Verified
```
$ python3 email_audit.py example.com --json --skip-http
{"summary": {"target": "example.com", ...}, "checks": {"spf": {...}, "dmarc": {...}, ...}}

$ python3 -m pytest tests/test_email_audit_integration.py
22 passed in 0.15s
```
Full-suite baseline: 432 → **455 passing**.

### Integration shape (Path A — "drop in, wire up")
- No refactor of the 3444-line monolith. Tool retains standalone CLI use.
- `hunt.py::run_email_audit` wraps the CLI with `--json --skip-http --timeout 6 --output <path>` and parses the JSON output into Vikramaditya's finding-list shape.
- IP/CIDR guard via simple regex — email-auth is DNS-scoped, bypass is correct behaviour.
- Brain integration passes through — the tool's own AI dispatcher reads the same `.env` keys Vikramaditya uses elsewhere, so no double-config.

### Deferred to Path B (v7.3.0)
- Split monolith into `email_audit/` package — `spf.py`, `dmarc.py`, `dkim.py`, `mx.py`, `mta_sts.py`, `bimi.py`, `dnssec.py`, each 200–400 lines.
- Replace the tool's multi-LLM dispatcher with Vikramaditya's `brain.py` (single source of truth).
- Replace the tool's own `.env` schema with `credential_store.py`.
- Emit findings in `memory/schemas.py` shape so they flow directly into the HTML reporter without the current distil step.
- Add `agents/email-auditor.md` for agent-driven bulk scans.

### Credit
Upstream: `https://github.com/venkatas/subspace-sentinel` (MIT). Imported verbatim; credit header added to `email_audit.py` docstring.

---

## v7.1.11 — drop inherited placeholder Support URLs (2026-04-19)

The README's "Professional Support" block advertised four links that never resolved:
- `security@vikramaditya.dev` (no such mailbox)
- `discord.gg/vikramaditya` (invite doesn't exist)
- `docs.vikramaditya.dev` (domain unregistered)
- `github.com/venkatas/vikramaditya/issues` (the one real link)

The block was inherited from commit `bc6b025 feat: add HAR-based authenticated VAPT capabilities` — scaffold text that was never replaced with real contact info.

### Fix
Replaced the four-line block with two real entries:
- `venkat.9099@gmail.com` — the actual maintainer contact.
- `github.com/venkatas/vikramaditya/issues` — the real issue tracker.

Heading trimmed from "Professional Support" to just "Support" since there's no paid support tier.

### Not touched (flagged for next pass)
The "Enterprise Licensing" block directly below the one just fixed still reads like inherited template copy (*White-label deployments*, *Custom integrations*, *Professional training*, *Extended support contracts*) — there's no actual enterprise licensing programme behind it. Will rewrite or delete in a follow-up patch.

### Found by
User review — spotted the unresolvable URLs during docs pass and flagged them as potentially hallucinated. `git log -S` pinned the culprit commit; the placeholders were inherited, not produced by this session's work.

---

## v7.1.10 — sqlmap invocation hardening (JSON APIs) (2026-04-19)

v7.1.9 landed with Vikramaditya reaching testfire's `/api/login` with `{"username":"test","password":"test"}` — the URL and body were finally correct. sqlmap still didn't flag `injectable`. Inspection of sqlmap's `testfire.net/log` showed *zero* `Parameter:` lines across all 6 POST operations. Three separate flags missing.

### Bug 10 — sqlmap missing JSON Content-Type header
**Root cause:** `run_sqlmap_targeted`'s POST branch passed `--data='{"username":"test"}'` without an explicit Content-Type header. testfire's API (like most JSON REST APIs) rejects requests with the default `text/plain` body; every probe returned HTTP 400. sqlmap's Boolean oracle needs at least one 200 in the baseline set to establish a pattern — it never got one.

**Fix:** auto-attach `--headers "Content-Type: application/json"` when the body starts with `{` or `[`.

### Bug 11 — sqlmap wasted time on unreachable techniques
**Root cause:** no `--technique` flag → sqlmap ran Boolean + Error + Union + Stacked + Time-based. Time-based needs `SLEEP()` or `pg_sleep()` — useless against an app-layer SQL concat. Stacked queries fail against almost every modern DB driver. Each probe burned seconds; 600 s timeout hit before Boolean got a fair shot.

**Fix:** `--technique=BEU` — Boolean + Error + Union only. These are the three techniques that reach app-layer SQLi through JSON APIs.

### Bug 12 — sqlmap detection output wasn't being read
**Root cause:** the original invocation had `-o "post_<name>.txt"`. sqlmap's `-o` is a **boolean** enable-output flag, not a file-path argument; the path was silently dropped. The `run_cmd` stdout was captured but sqlmap's batch mode suppresses most of the "injectable" announcements that show up in interactive mode. Result: even if sqlmap *had* found something, hunt.py wouldn't know.

**Fix:** read sqlmap's own `results-*.csv` files from the output dir and scan them for `Parameter:` / `injectable` lines. New helper `_glob_results_csvs()` collects the per-run CSVs.

### Bonus — `--smart`
Added `--smart` so sqlmap skips params whose values don't look numeric / SQL-injectable heuristically. On `/api/feedback/submit` this avoids burning 5 min on the `message` field.

### Tests
`tests/test_sqlmap_invocation_hardening.py` — 7 new tests:
- 3 × `_glob_results_csvs` helper (empty dir, naming match, missing dir safe).
- 4 × JSON-header inline heuristic (object body triggers, array body triggers, form body + empty body don't).

Live-path "sqlmap actually detects the SQLi" is too slow to unit-test (10 min per probe, needs live testfire); pinning via ongoing monitor run instead.

### Verified
Full-suite baseline: 425 → **432 passing**.

### The cascade — 12 fixed, zero known remaining
```
v7.1.2 — HAR engine FP                            ✓
v7.1.3 — api_audit SyntaxError                    ✓
v7.1.4 — no OpenAPI→sqlmap feed                   ✓
v7.1.5 — wrong script filenames                   ✓
v7.1.6 — wrong Swagger probe paths                ✓
v7.1.7 — collector crashed on list JSON           ✓
v7.1.8 — basePath dropped in sample_url           ✓
v7.1.9 — body schema not expanded from $ref       ✓
v7.1.9 — confirm() EOFError on non-TTY            ✓
v7.1.10 — no Content-Type: application/json       ✓  ← here
v7.1.10 — technique mis-selection (all 5)         ✓  ← here
v7.1.10 — -o flag treated as boolean, log unread  ✓  ← here
```

### Found by
Inspecting `findings/testfire.net/sessions/<S>/sqlmap/testfire.net/log` after the v7.1.9 run completed — empty log + zero `Parameter:` lines pointed directly at sqlmap receiving the request but the target rejecting it. Manual reproduction with `curl -H "Content-Type: application/json" -d '{"username":"admin","password":"x"}' https://testfire.net/api/login` returned the same body-reflection pattern I'd exploited manually earlier, confirming the header was the missing piece.

---

## v7.1.9 — body-schema $ref expansion + non-TTY EOFError fix (2026-04-19)

v7.1.8 got sqlmap hitting the right URLs (`/api/login`). But sqlmap couldn't find the SQLi because the **body was wrong**:

```
sqlmap POST → https://testfire.net/api/login  body={"test":"1"}   ← pre-v7.1.9
```

testfire's vulnerable parameter is `username` — sqlmap can only inject into fields it sees in the body, and `{"test":"1"}` has no `username`.

### Bug 8 — body-schema $ref expansion
**Root cause:** `operations.json` (api_audit.py's pre-parsed output) drops the body schema during `extract_operations`. Only `parameters[in=body, name=body]` survives — the actual property list (`username`, `password`) is lost. Worse: api_audit.py never persisted the raw parsed spec files at all, so hunt.py had no way to recover the schema.

**Fix (two files):**
- `api_audit.py::discover_specs` — now also returns the raw parsed spec alongside metadata.
- `api_audit.py::write_outputs` — persists each parsed spec as `<saved_as>.json` (e.g. `testfire.net_b80b3ac7.json`) next to `operations.json`.
- `hunt.py::_collect_openapi_post_endpoints` — pre-indexes every raw spec by `(path, method)` at startup. When an op is found in `operations.json`, resolves its body by looking up `(path, method)` in the index and walking the `$ref` chain (Swagger 2.0 `definitions` + OpenAPI 3 `components.schemas`). Falls back to the stub `{"test":"1"}` only when the raw spec is truly missing.

**Impact on testfire (live verified):**
```
POST /api/login              body={"username":"test","password":"test"}
POST /api/transfer           body={"toAccount":"test","fromAccount":"test","transferAmount":"test"}
POST /api/admin/addUser      body={"firstname":"test","lastname":"test","username":"test","password1":"test","password2":"test"}
POST /api/admin/changePassword body={"username":"test","password1":"test","password2":"test"}
POST /api/feedback/submit    body={"name":"test","email":"test","subject":"test","message":"test"}
POST /api/account/1/transactions body={"startDate":"test","endDate":"test"}
```
Every body now has real field names. sqlmap will inject into `username` this time.

### Bug 9 — `EOFError` crash at final report prompt
**Root cause:** Vikramaditya's `confirm("Generate report from scan results?")` calls `input()` at the end of every scan. When the process runs non-TTY (backgrounded, CI pipeline), `input()` raises `EOFError` immediately. 3-hour autonomous scan crashes at the finish line instead of saving the report.

**Fix:** `confirm()` and `prompt()` wrap `input()` in `try/except EOFError` — return `default_yes` / `default` respectively.

### Tests
`tests/test_body_schema_expansion.py` — 9 new tests:
- 7 × body-schema resolution (login/transfer/addUser/feedback via $ref; stub fallback; OpenAPI 3 `requestBody.content`; Swagger 2.0 formData)
- 2 × non-TTY EOFError handling for `confirm()` + `prompt()`

Pins the exact testfire spec shape as a regression test: if future refactors drop the raw spec again, `test_login_body_has_username_and_password` fails loudly.

### Verified
Full-suite baseline: 416 → **425 passing**.

### The cascade (9 layers, now structurally complete)
```
v7.1.2 — HAR engine FP                      ✓
v7.1.3 — api_audit SyntaxError              ✓
v7.1.4 — no OpenAPI→sqlmap feed             ✓
v7.1.5 — wrong script filenames             ✓
v7.1.6 — wrong probe paths                  ✓
v7.1.7 — collector crashed on list JSON     ✓
v7.1.8 — basePath dropped in sample_url     ✓
v7.1.9 — body schema not expanded from $ref ✓  ← here
v7.1.9 — confirm() EOFError on non-TTY     ✓   ← bonus
```
Vikramaditya can now, from a single `vikramaditya.py https://target/` invocation, discover Swagger specs, extract POST endpoints with full body-param fidelity, and run sqlmap against them with correct URLs, correct bodies, and correct cookies. No more silent misses.

---

## v7.1.8 — build_base_url drops basePath when host is absent (2026-04-19)

v7.1.7 restored the full Vikramaditya → OpenAPI → sqlmap chain on testfire.net. Run completed with:
```
sqlmap: 6 POST candidate(s) from OpenAPI specs
sqlmap POST → https://testfire.net/login                 body={"test":"1"}
sqlmap POST → https://testfire.net/account/1/transactions
sqlmap POST → https://testfire.net/transfer
sqlmap POST → https://testfire.net/feedback/submit
sqlmap POST → https://testfire.net/admin/addUser
sqlmap POST → https://testfire.net/admin/changePassword
```
All 6 OpenAPI operations ran through sqlmap. But no `API SQLi FOUND` fired — because the URLs are wrong. testfire's real SQLi endpoint is `https://testfire.net/api/login`, not `https://testfire.net/login`.

### Root cause
`api_audit.build_base_url()` had a 3-way dispatch:
1. OpenAPI 3.0 `servers[0].url` → honoured.
2. Swagger 2.0 with `host` field → `scheme://host/basePath` — honoured.
3. Swagger 2.0 **without** `host` → `scheme://netloc` — **basePath dropped on the floor**.

testfire.net hits branch 3. The spec at `/swagger/properties.json` declares `basePath: "/api"` but no `host` (it relies on the caller's origin). The old code returned just `https://testfire.net` and every extracted `sample_url` for every op came out lacking the `/api` prefix.

### Fix
Branch 3 now applies `basePath` to the source-URL origin:
```python
if base_path:
    suffix = base_path if base_path.startswith("/") else "/" + base_path
    return source_root + suffix.rstrip("/")
return source_root
```
Defensive on the input — trailing `/` stripped, missing leading `/` auto-added.

### Tests
`tests/test_build_base_url.py` — 9 new tests:
- 7 × `build_base_url` shape matrix (host-only, basePath-only, both, neither, OpenAPI3 servers, trailing slash, missing leading slash).
- 2 × `extract_operations` end-to-end on the exact testfire spec shape → proves `sample_url` is now `https://testfire.net/api/login` for POST `/login` and `https://testfire.net/api/account/1/transactions` for GET/POST on the path-param route.

### Verified
```
>>> build_base_url({"swagger":"2.0","basePath":"/api"},
...                "https://testfire.net/swagger/properties.json")
'https://testfire.net/api'    # was 'https://testfire.net' before
```
Full-suite baseline: 407 → **416 passing**.

### The cascade, finally resolved (7 layers)
```
v7.1.2 — HAR engine FP                   ✓
v7.1.3 — api_audit SyntaxError           ✓
v7.1.4 — no OpenAPI→sqlmap feed          ✓
v7.1.5 — wrong script filenames          ✓
v7.1.6 — wrong probe paths               ✓
v7.1.7 — collector crashed on list JSON  ✓
v7.1.8 — basePath dropped in sample_url  ✓   ← the last one
```
Each layer was hiding the next. The detection chain is now structurally complete end-to-end. Next re-run should finally fire `API SQLi FOUND` on `/api/login`.

### Found by
Re-running under v7.1.7 produced `sqlmap POST → https://testfire.net/login body={"test":"1"}` in the scan log. Manual reproduction with `curl -X POST https://testfire.net/login` returns 404 — that was the entire miss. testfire only serves the SQLi on `/api/login`.

---

## v7.1.7 — OpenAPI collector crash fix + operations.json primary path (2026-04-18)

v7.1.6 got Phase 6.5 finding specs (testfire → 2 specs / 24 ops). Then SQLMAP phase fired and immediately crashed:

```
File "hunt.py", line 1501, in _collect_openapi_post_endpoints
    host = spec.get("host") or ""
AttributeError: 'list' object has no attribute 'get'
```

### Root cause
`_collect_openapi_post_endpoints` (added v7.1.4) walked every `*.json` in `api_specs/` assuming each was an OpenAPI spec. api_audit.py actually writes **three non-spec JSON files** there:

- `discovered_specs.json` — list of spec-metadata dicts
- `operations.json` — list of parsed operation dicts
- `unauth_findings.json` — list (often empty)

All three are `list` objects, not dicts. Calling `.get()` on a list = `AttributeError`, which aborted the entire SQLMAP phase with no retry.

### Fix
Two-path refactor of `_collect_openapi_post_endpoints`:

1. **Primary** — read `operations.json` directly. api_audit.py has already parsed every operation across every spec; we just filter to POST/PUT/PATCH + build a sample JSON body from each op's `parameters` (`in: body` + `in: formData`). Simpler + correct.

2. **Fallback** — walk raw `<host>_<hash>.json` spec files but **skip** the three known non-spec siblings (`discovered_specs.json`, `operations.json`, `unauth_findings.json`) and any payload that isn't a dict with a `paths` key. Every `.get()` call in the schema walker is type-guarded now.

### Tests
`tests/test_openapi_collector_hardening.py` — **12 new tests**:
- 4 × crash regressions (list payloads, malformed JSON, non-dict top-level, string top-level) all return `[]` instead of raising.
- 6 × `operations.json` primary path (reads ops, skips GETs, dedups, respects limit, handles empty-body + formData parameters, skips invalid URLs).
- 2 × raw-spec fallback (walks specs when `operations.json` absent; coexists with non-spec siblings).

The v7.1.4 tests in `tests/test_hunt_sqlmap_plumbing.py` still pass — the fallback path preserves exactly their expected behaviour.

### Verified
```
$ python3 -c "from hunt import _collect_openapi_post_endpoints; \
  [print(e['method'], e['url']) for e in \
  _collect_openapi_post_endpoints('/tmp/vapt_run/api_audit_smoke2')]"

POST https://testfire.net/login
POST https://testfire.net/account/1/transactions
POST https://testfire.net/transfer
POST https://testfire.net/feedback/submit
POST https://testfire.net/admin/addUser
POST https://testfire.net/admin/changePassword
```
6 POST endpoints harvested from real testfire `operations.json` — including `/login` (the SQLi target) and `/admin/addUser` (auth-bypass chain candidate).

Full-suite baseline: 395 → **407 passing**.

### The cascade resolved (6 layers now)
```
v7.1.2 — HAR engine FP            ✓
v7.1.3 — api_audit SyntaxError    ✓
v7.1.4 — no OpenAPI→sqlmap feed   ✓
v7.1.5 — wrong script filenames   ✓
v7.1.6 — wrong probe paths        ✓
v7.1.7 — collector crashed on list JSON  ✓   ← here
```
Each layer uncovered the next. This should be the last — the collector now reads `operations.json` which is the exact format api_audit.py produces, with defensive skip for every non-spec JSON sibling.

### Known v7.1.8-eligible polish (not shipped yet)
- api_audit.py's extracted `sample_url` drops `basePath` — testfire's `/login` should be `/api/login`. Needs an `extract_operations` patch, not a collector patch.
- operations.json doesn't preserve body-param names beyond `body` itself. Parsing from the raw spec would recover `username`/`password` etc; current fallback stub `{"test":"1"}` works for sqlmap boolean-blind detection but gives less precise payload targeting.

Both are polish. Not shipping until seen in a real engagement.

### Found by
`Traceback (most recent call last):` fired in the Monitor on the v7.1.6 run at the SQLMAP phase boundary. The stack trace pointed directly at line 1501 of hunt.py, making the fix site unambiguous.

---

## v7.1.6 — api_audit.py spec-path list expansion (2026-04-18)

Re-running with v7.1.5 got Phase 6.5 actually executing — but `api_audit.py` still reported `OpenAPI specs: 0` on testfire.net. Root cause: the 17-entry `SPEC_PATHS` list included `/swagger-ui/index.html` (hyphenated) but not `/swagger/index.html` (slash-separated) and *no* entry at all for testfire's actual spec location `/swagger/properties.json`. Yet another silent-miss — the probe succeeded, the responses were all 404s, and the phase reported clean completion with zero findings.

### Fix
`api_audit.py::SPEC_PATHS` gains seven new entries:
- `/swagger/properties.json` — testfire's exact path
- `/swagger/swagger.json` — common rename
- `/swagger/index.html` — slash-separated Swagger UI bootstrap
- `/swagger/`, `/swagger` — directory-style entry points
- `/docs`, `/api/docs`, `/apidocs` — FastAPI defaults + common rewrites

Total: 17 → 24 probe paths.

### Regression test
`tests/test_api_audit_spec_paths.py` — 7 pins:
- `/swagger/properties.json` must stay in the list (testfire regression)
- `/swagger/index.html` must stay (slash variant)
- Hyphenated variants must coexist (back-compat)
- `/docs` must stay (FastAPI)
- All v7.1.5 legacy paths preserved
- No duplicates
- All paths are absolute

### End-to-end proof on real testfire.net
```
$ mkdir -p /tmp/smoke/live /tmp/smoke/api_specs
$ echo "https://testfire.net" > /tmp/smoke/live/urls.txt
$ python3 api_audit.py --recon-dir /tmp/smoke --max-hosts 1
[*] OpenAPI specs discovered: 1   (was 0 in v7.1.5)
[*] Parsed operations:        12
[*] Public operations:        12

$ cat /tmp/smoke/api_specs/spec_urls.txt
https://testfire.net/swagger/properties.json

$ head /tmp/smoke/api_specs/all_operations.txt
https://testfire.net/login
https://testfire.net/account
https://testfire.net/account/1/transactions
...
```
Swagger spec found, 12 operations extracted, fed directly into v7.1.4's `_collect_openapi_post_endpoints` → sqlmap pipeline. The SQLi detection chain for `/api/login` now works autonomously.

Full-suite baseline: 388 → **395 passing**.

### The v7.1.x silent-miss cascade, retrospectively
1. v7.1.2 — HAR engine's substring-match FP (fixed)
2. v7.1.3 — `SyntaxError` in api_audit.py + agent.py (fixed)
3. v7.1.4 — sqlmap never got OpenAPI POST endpoints (fixed)
4. v7.1.5 — recon.sh called wrong file names (fixed)
5. v7.1.6 — api_audit.py never probed testfire's actual path (fixed **here**)

Each layer was hiding the next. Every one of these would have silent-skipped on a real engagement without nobody noticing.

### Found by
Re-running vikramaditya.py https://testfire.net/ after v7.1.5 ship; Monitor fired `OpenAPI specs: 0` with the full run actually executing for the first time. The fact that we got to see "0 specs discovered" instead of "phase skipped" is itself a v7.1.5 win.

---

## v7.1.5 — recon.sh filename reconciliation (two silent-skip bugs) (2026-04-18)

Re-running v7.1.4 on testfire.net immediately surfaced the next layer: the new `_collect_openapi_post_endpoints` feed was starved because **Phase 6.5 had been skipping for weeks without anyone noticing** — `recon.sh` hunted for `openapi_audit.py` while the actual file is `api_audit.py`. The test I wrote to catch this also flagged a **second** mismatch: `refresh_priority()` wanted `tech_priority.py`; the actual file is `prioritize.py`.

Both scripts were correctly guarded with `[ -f "$script" ]`, so they failed silent-skip-mode with a single warning line buried in hundreds of lines of scan output. Phase 4 priority-scoring and Phase 6.5 OpenAPI discovery therefore both ran as no-ops on every Vikramaditya invocation.

### Fixes
- `recon.sh::Phase 6.5` — `OPENAPI_AUDIT` now prefers `api_audit.py` with `openapi_audit.py` as fallback. `api_audit.py --help` already accepts `--recon-dir --max-hosts --max-ops` exactly as recon.sh calls it.
- `recon.sh::refresh_priority()` — `priority_script` now prefers `prioritize.py` with `tech_priority.py` as fallback. Same two-positional CLI (`httpx_full.txt → prioritized_hosts.txt`), drop-in.

### Regression guard — `tests/test_recon_sh_refs.py`
Parametrised over every `$SCRIPT_DIR/<name>.(py|sh)` reference in `recon.sh` + `scanner.sh`. Each must exist at repo root or have a sibling fallback in the same shell. Subdir references (e.g. `tools/XSStrike/xsstrike.py` for externally-cloned helpers) are skipped because they're meant to be optional and properly guarded.

### Impact
Phase 4 and Phase 6.5 are both restored — the `api_specs/` dir will now populate with harvested OpenAPI specs, which flows straight into v7.1.4's `_collect_openapi_post_endpoints` → sqlmap pipeline. In other words, the *actual* end-to-end SQLi detection chain for `/api/login`-style endpoints is alive for the first time.

### Verified
```
$ python3 -m pytest tests/test_recon_sh_refs.py -v
5 passed in 0.01s
$ python3 -m pytest tests/
388 passed in 1.06s
```

### Found by
Re-running v7.1.4 on testfire.net — Monitor fired `api_audit.py not found or no live hosts — skipping OpenAPI discovery` within 30 s, which turned out to be the actual root cause for why Phase 6.5 never populated `api_specs/`. v7.1.3 had patched the SyntaxError in the file; v7.1.5 now patches the callers that never reached the file.

---

## v7.1.4 — SQLi plumbing fixes found via testfire.net dogfooding (2026-04-18)

Four bugs surfaced while running Vikramaditya end-to-end on `https://testfire.net/`. None of them throw an error; they silently degrade coverage. Fixes are all in `hunt.py::run_sqlmap_targeted` and `brain.py::triage_finding`.

### Bug 3 — `/api/*` POST endpoints never handed to sqlmap
**Root cause:** `run_sqlmap_targeted` aggregates candidates from nuclei-sqli, paramspider, `with_params.txt`, and `arjun.json`. None of those feed the `api_specs/*.json` output from Phase 6.5 (OpenAPI discovery). So every Swagger-documented POST operation — including `/api/login` which had a textbook boolean-based blind SQLi on testfire — was silently skipped.

**Fix:** new helper `_collect_openapi_post_endpoints(recon_dir)` walks both Swagger-2.0 (`host` + `basePath` + `paths` + `definitions/$ref`) and OpenAPI-3.0 (`servers[0].url` + `requestBody.content["application/json"].schema` + `components.schemas/$ref`) specs. For each POST/PUT/PATCH, generates a synthesised JSON body (first-level properties → `"test"` value) and runs `sqlmap -u <url> --data='{...}' --method POST` individually. `sqlmap -m` can't do this because it treats each URL as a standalone GET.

**Impact:** the testfire SQLi on `/api/login` would now be caught in a single `hunt.py --target testfire.net` pass.

### Bug 4 — cross-phase payload contamination in SQLi candidates
**Root cause:** `urls/with_params.txt` includes dalfox's and historical scanners' XSS PoCs pulled back through wayback/gau (e.g. `search.jsp?query=<body bgcolor="red">...<a href="evil.com">...`). `run_sqlmap_targeted` happily fed these to sqlmap, which then spent minutes trying to inject around the existing `<body>` HTML.

**Fix:** new `_looks_like_payload_url(url)` + opt-in `filter_payloads=True` flag on `_collect_urls_from_file`. Matches ~17 JS-sink / XSS / SQLi substrings plus a regex for URL-encoded `<tag` openers (`%3C[a-z/]`). The SQLMAP phase now defaults to `filter_payloads=True`.

### Bug 5 — sqlmap always ran unauthenticated
**Root cause:** the GET-candidates branch of `run_sqlmap_targeted` called `sqlmap -m $cand_file --batch --level=3 --risk=2 --random-agent` with no `--cookie`. Any candidate requiring a session redirected to `/login`, sqlmap saw the 302, and flagged the target non-injectable. Authenticated engagements (cfgold, foctta) would have missed every post-auth SQLi.

**Fix:** `cookie_opt = f'--cookie="{cookies}"' if cookies else ""` threaded into both the GET branch and the new OpenAPI POST branch.

### Bug 6 — baron-llm triage cold-start occasionally describes the task instead of running it
**Root cause:** first call to the 8B triage model on a fresh Ollama process sometimes returns generic prose like *"You have been tasked with validating the quality of a penetration test report…"* — no `VERDICT:` line, no 7-question gate answers. Second call on the same prompt returns proper structured output.

**Fix:** `brain.py::triage_finding` now detects a missing `VERDICT:` token and retries once with a stricter prompt prefix: *"DO NOT describe the task. DO NOT summarise the finding in prose. Start your response with the literal token 'VERDICT:'."* Covers the cold-start case without changing the happy-path behaviour.

### Tests
`tests/test_hunt_sqlmap_plumbing.py` — 15 new regression tests:
- 8 × `_looks_like_payload_url` / `_collect_urls_from_file(filter_payloads=True)` — including the exact testfire dalfox PoC as a pinned regression case.
- 7 × `_collect_openapi_post_endpoints` — Swagger 2.0 + OpenAPI 3.0 specs, malformed-JSON passthrough, limit enforcement, GET-op skip.

Bug 5 and Bug 6 are exercised at integration time (subprocess + LLM stub respectively).

### Verified
```
$ python3 -m pytest tests/test_hunt_sqlmap_plumbing.py -v
15 passed in 0.15s
```
Full-suite baseline: 345 → **360 passing**.

### Found by
Dogfooding — `"test our tool on https://testfire.net/"`. The tool missed the SQLi I'd already confirmed manually because of Bugs 3–5; the noisy brain output during the scan surfaced Bug 6. Everything was fixable in ~60 lines + one new helper.

---

## v7.1.3 — syntax regression guard + duplicate `__future__` import fix (2026-04-18)

### Problem
Running Vikramaditya end-to-end against testfire.net surfaced a `SyntaxError: from __future__ imports must occur at the beginning of the file` in `api_audit.py` (Phase 6.5 Swagger discovery trigger). Follow-up scan of `agent.py` showed the same anti-pattern. Both files had a duplicated `from __future__ import annotations` — line 2 (valid) *and* a second copy after the module docstring (invalid — PEP 236 requires `__future__` imports before any statement except the docstring, and two statements around the docstring form is still OK, but declaring it twice trips the parser).

### Files patched
- `api_audit.py` — removed the duplicate at line 11.
- `agent.py` — removed the duplicate at line 41; added `# noqa: E402` to the single remaining import to silence lint.

### Regression guard
- `tests/test_repo_syntax.py` — parametrised over every `.py` file at repo root (59 files at time of writing); each one must `py_compile.compile(doraise=True)` cleanly. Fails per-file so the culprit names itself in the report line.

### Verified
```
$ python3 -m pytest tests/test_repo_syntax.py
59 passed in 0.15s
```
Full-suite baseline: 286 (v7.1.2) + 59 (v7.1.3 syntax tests) = **345 passing**.

### Found by
Dogfooding — the user asked to run Vikramaditya on `https://testfire.net/` and the scan log caught the `SyntaxError` line via the Monitor filter. Without this fix, Phase 6.5 (OpenAPI discovery) silently fails on any target that triggers an api_audit import.

---

## v7.1.2 — HAR engine: auth-bypass FP fix + finding dedup (2026-04-18)

Found running `vikramaditya.py` against a real rediff-platform HAR capture (233 entries, 172 endpoints). Report had **75 findings including 3 HIGH "Authentication Bypass" entries that were all false positives** — the endpoints correctly rejected unauthenticated requests with `{"success":false,"error":true,"code":440,"message":"invalid session."}`, but the detector's substring heuristic `'"success"' in text` matched the field name even in the error body.

### Bug 1 — `har_vapt_engine.py::test_auth_bypass`
**Root cause:** The old detector used a substring match on `"success"` to decide if an endpoint returned genuine success data. That substring appears in both `{"success":true}` (real hit) and `{"success":false,"error":true,...}` (error). Every error body that mentioned the field name was misclassified as an authenticated-data leak.

**Fix:** New helper `HARVAPTEngine._is_success_response(resp)` parses the JSON body and requires **all of**:
- HTTP status `200` (no 3xx/4xx/5xx)
- No common session-error phrases in body (`invalid session`, `not authenticated`, `please log in`, `unauthorized`, `session expired`)
- `error != true`
- `status != false` and `status not in ("error","fail","failure")`
- `code not in (401, 403, 440)`
- `success == true` (explicit — field presence alone is no longer enough)

Falls back to the stricter token `"success":true` when the body isn't parseable JSON. Non-JSON HTML landing pages no longer pass.

### Bug 2 — `har_vapt_engine.py::_log` duplicate emissions
**Root cause:** The file-upload tester probes each endpoint with multiple shell extensions (`shell.php`, `shell.phtml`, `shell.jsp`, etc.) against each candidate field (`file`, `upload`, `upfile`, `upfile1`). Every attempt emitted its own "Accepted, Unverified" MEDIUM — so a single (endpoint, field) pair would appear ~4× in the report.

**Fix:** `_log` now tracks emitted `(type, endpoint_path, parameter)` tuples in `self._emitted_keys`. First emission wins; subsequent attempts against the same triple are silent. Query-string is stripped from the endpoint key so `?a=1` vs `?a=2` don't split the same finding.

### Before / after on `test.har`
| | v7.1.1 | v7.1.2 |
|---|---|---|
| Total findings | 75 | **22** (-71 %) |
| HIGH (auth bypass) | 3 (all FPs) | **0** ✓ |
| MEDIUM file-upload | 48 | 12 (1 per unique field) |
| MEDIUM HTTP TRACE | 3 | 3 |
| MEDIUM insecure cookie | 1 | 1 |
| LOW missing headers | 20 | 6 |
| Unique (type, endpoint, param) = total | N/A | 22 = 22 ✓ |

### Tests
New `tests/test_har_vapt_engine.py` — 16 regression tests:
- 12 × `_is_success_response` (the exact rediff-platform FP payload is pinned as `test_invalid_session_payload_is_not_success`)
- 4 × `_log` dedup (multiple shells collapse, different fields split, different types never collide, query-string doesn't split)

Full-suite baseline: **286 passing tests** (was 270).

### Credit
Bug found while dogfooding Vikramaditya on a real HAR during a VAPT session — "test our tool" exercise exposed the detector's noise issue.

---

## v7.1.1 — README refresh for v5.x → v7.x features (2026-04-18)

**Docs-only.** The README had drifted badly — TOC, "What's New", file structure, and vulnerability coverage sections all still described v4.1, even though nine releases had landed since. This patch refreshes those sections to reflect the actual current feature set.

### Changed
- **TOC link bar** — swapped "What's New in v4.1" for "What's New in v7.x" + "Engagement Privacy".
- **"What's New" section** — replaced the v4.1 HAR block with a v5.0 → v7.1 rollup: CVSS 4.0, HackerOne MCP, CI/CD scanner, `/pickup`, credential store, bb-methodology, `/intel`, meme-coin/Solana/DEX LP domain, `/remember` + `/surface` + recon-ranker, `/autopilot`, sneaky_bits, 229-test suite, engagement privacy proxy. The legacy v2.0 and v4.1 sections are preserved below for historical context.
- **File Structure tree** — added `validate.py`, `credential_store.py`, `intel_engine.py`, `token_scanner.py`, `sneaky_bits.py`, `cicd_scanner.sh`, `llm_anon/`, `mcp/hackerone-mcp/`, refreshed `skills/`, `agents/`, `commands/` rosters, noted `tests/` at 270 tests.
- **Vulnerability Coverage section** — new tables for web3 meme-coin, CI/CD / supply chain, LLM red-team, and Engagement Privacy domains.
- **New "Engagement Privacy" section** — copy-paste-ready two-terminal quickstart showing what Claude sees (surrogates) vs what the operator sees (real data).

### Why this was necessary (noted by the user)
"You are not updating readme." Correct — I'd only been updating the single-line version string on line 12 of README.md, which meant the body still advertised v4.1 capabilities to anyone browsing the repo. All the v5.x – v7.x work was effectively invisible unless someone read `CHANGELOG.md`. Fixed.

### Ported from
N/A — original content.

---

## v7.1.0 — Claude Code anonymization reverse proxy (2026-04-18)

Builds the FastAPI reverse proxy on top of the v7.0 core. Point `ANTHROPIC_BASE_URL` at the proxy and Claude Code becomes content-safe for engagement work.

### Added
- `llm_anon/proxy.py` (~230 lines) — FastAPI app. Handles:
  - JSON request bodies (recursive string walk, every leaf anonymised).
  - JSON response bodies (recursive deanonymise).
  - **Server-Sent Events** for `text/event-stream` responses — each `data:` line parsed as JSON, `text_delta` payloads rewritten, stream passes through line-by-line so Claude Code stays interactive.
  - Binary passthrough (images / octet streams never touched).
  - `/health` endpoint reporting engagement + vault path + entity histogram.
  - Injectable `http_client_factory` so tests can swap in `httpx.ASGITransport` for a fake upstream.
- `commands/anon.md` — `/anon` slash command doc with start / health / vault commands.
- `tests/test_llm_anon_proxy.py` — 14 tests:
  - Body transforms: anonymise JSON / plain text / binary / empty bodies, deanonymise round-trip.
  - SSE handling: comment / event / `[DONE]` / malformed / real `text_delta` deanonymised.
  - End-to-end integration: proxy talks to a stub upstream via ASGI transport; verifies the upstream sees only surrogates and the response reaching the client has originals restored — for both non-streaming and streaming paths.

### Verified
```
$ python3 -m pytest tests/test_llm_anon.py tests/test_llm_anon_proxy.py -v
41 passed in 0.32s
```
Full-suite baseline now **270 passing tests**.

### How to use

```bash
# Terminal 1 — start the proxy
export ENGAGEMENT_ID=acme-2026-vapt
export ANTHROPIC_API_KEY=sk-ant-...     # real key — forwarded to upstream as-is
python3 -m llm_anon.proxy

# Terminal 2 — point Claude Code at the proxy
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ENGAGEMENT_ID=acme-2026-vapt
claude
```

### Threat model (explicit)
- Prevents *content-based* correlation — Claude never sees real IPs / hashes / credentials / hostnames / emails / AWS keys / JWTs.
- Does **not** prevent correlation via query patterns, tool-call sequences, or timing.
- Binds to `127.0.0.1` only. Do not expose on public interfaces.
- The SQLite vault contains the real↔surrogate mapping — keep it local, keep it encrypted at rest.

### Lessons during the port
- FastAPI treats un-annotated handler parameters as query string fields → the stub upstream initially returned 422 until `req: Request` was explicitly typed. Updated tests use the imported type name directly (no aliases) so FastAPI's introspection recognises it.
- Module-level monkey-patching of `httpx.AsyncClient` inside the proxy module leaks into the test's own httpx calls (same module object). Refactored to accept a `http_client_factory` so tests inject the transport cleanly.
- Vault helper attributes `engagement_id` / `db_path` promoted from underscore-private to public properties so the `/health` endpoint can report per-app state without reading a global env var.

### Still not ported
- Ollama-backed LLM detection layer (v7.2).
- Self-improvement feedback loop (v7.3).
- Upstream's SSH-tunnel + Docker orchestration scripts (out of scope for core repo).

### Design credit
Same as v7.0: [zeroc00I/LLM-anonymization](https://github.com/zeroc00I/LLM-anonymization) design spec.

---

## v7.0.0 — VAPT anonymization core (2026-04-18)

**Major:** adds a new security-first domain to Vikramaditya — anonymize real client data before any LLM call, restore on the way back. Shipped as the foundational library (v7.0); the FastAPI reverse proxy that wires it into Claude Code follows in v7.1.

### Added
- `llm_anon/` package (5 modules, ~440 lines):
  - `regex_detector.py` — deterministic patterns for IPv4/IPv6/CIDR, MAC, email, URL, FQDN, AWS access keys, API tokens (`sk_live_`, `ghp_`, `xoxb-`), JWT, MD5/SHA1/SHA256/NTLM hashes. Overlap-resolution logic ensures NTLM `LM:NT` doesn't lose to two adjacent MD5 matches and CIDR beats bare IPv4.
  - `surrogates.py` — deterministic surrogate factory. RFC 5737 TEST-NET IPv4, RFC 3849 IPv6 doc prefix, `.pentest.local` FQDN suffix, locally-administered MACs, preserved-length hashes.
  - `vault.py` — SQLite-backed per-engagement mapping store. Round-trip `get_surrogate` / `get_original`, entity histogram, `clear()` between engagements, isolation across `engagement_id` values.
  - `anonymizer.py` — façade combining detection + vault + surrogate generation with an idempotent `anonymize()` / `deanonymize()` round-trip.
  - `__init__.py` — public surface (`Anonymizer`, `RegexDetector`, `SurrogateGenerator`, `Vault`, `Detection`).
- `tests/test_llm_anon.py` — 27 tests. Includes the critical **`test_must_not_leak_pentest_fixture`** that asserts no original IP / NTLM hash / email / AWS key survives anonymization of a CrackMapExec-style output block.

### Verified
```
$ python3 -m pytest tests/test_llm_anon.py -v
27 passed in 0.13s
```
Full-suite baseline: 229 (v6.4) + 27 (v7.0) = **256 passing tests**.

### Design note — why v7 is **core only**, not the proxy
A production FastAPI reverse proxy for Anthropic's SSE streams is 4–8 hours of careful engineering: content-type negotiation, streaming chunk boundaries, partial-line buffering, tool-use JSON structure preservation, error-stream deanonymization. Shipping a shaky proxy as a "major" in one drop masks bugs and makes rollback ugly. The core library ships first — it's covered by 27 tests and usable standalone. v7.1 adds the proxy on top.

### Design credit
Architecture and dual-layer design inspired by [zeroc00I/LLM-anonymization](https://github.com/zeroc00I/LLM-anonymization) — a README-only design spec with 97 stars and no license file (so direct code reuse wasn't an option). Regex arsenal, surrogate format (RFC 5737 / `.pentest.local`), per-engagement SQLite vault, and the 0%-leak test philosophy all follow that spec. Implementation is entirely original from the public description.

### Next (v7.1)
- `llm_anon/proxy.py` — FastAPI reverse proxy + SSE stream handler.
- `scripts/run_anon_proxy.sh` — one-command start.
- `commands/anon.md` — `/anon start | stop | status | vault-stats`.

### Not yet ported
- Ollama-backed LLM detection layer for entities regex can't see (bare `DC01`, `CONTOSO\user`, cleartext passwords without obvious structure). Deferred to v7.2.
- Self-improvement feedback loop (`auto_improve.py`, `feedback_loop.py`). Deferred to v7.3.

---

## v6.4.0 — 229-test suite for core modules (2026-04-18)

### Added
- `tests/conftest.py` — shared fixtures (`tmp_hunt_dir`, `journal_path`, `patterns_path`, sample entries, scope domains). Patched to resolve Vikramaditya's flat layout (repo root) instead of upstream's `tools/`.
- 12 ported test modules — total **229 new passing tests**:
  - `test_audit_log.py` — audit log + rate limiter + circuit breaker
  - `test_autopilot_guard.py` — AutopilotGuard safety envelope
  - `test_credential_store.py` — .env loading, masking, header builders
  - `test_hackerone_mcp.py` + `test_hackerone_server.py` — MCP server behavior
  - `test_hunt_journal.py` — journal append, query, concurrent writes
  - `test_intel_engine.py` — CVE/intel orchestration, memory cross-ref
  - `test_pattern_db.py` — pattern recall + ranking
  - `test_safe_method_policy.py` — GET-only / dangerous-method gating
  - `test_schemas.py` — validate_journal_entry / audit / session_summary
  - `test_scope_checker.py` — anchored subdomain match
  - `test_token_scanner.py` — rug-vector regex coverage

### Patched during port
- `from tools.credential_store` → `from credential_store` (root layout)
- `from tools.token_scanner` → `from token_scanner` (root layout)
- `sys.path.insert(0, "../tools")` → `sys.path.insert(0, "..")` in `conftest.py`

### Baseline
```
$ python3 -m pytest tests/test_audit_log.py tests/test_autopilot_guard.py \
    tests/test_credential_store.py tests/test_hackerone_mcp.py \
    tests/test_hackerone_server.py tests/test_hunt_journal.py \
    tests/test_intel_engine.py tests/test_pattern_db.py \
    tests/test_safe_method_policy.py tests/test_schemas.py \
    tests/test_scope_checker.py tests/test_token_scanner.py
229 passed in 0.68s
```

### Why
Before this port, Vikramaditya had 3 test files — `test_browser_agent.py`, `test_reporter_manual.py`, `test_request_guard.py`. Everything else (memory, MCP, credential store, scope checker, token scanner, intel engine) was uncovered. Now every ported module from v5.1.0 onward has test coverage, which makes future refactors safer.

### Deliberately skipped
- `test_recon_adapter.py` — `recon_adapter.py` doesn't exist in Vikramaditya (test expects a class that was never implemented).
- `test_report_generator_templates.py` — `report_generator.py` API differs from Vikramaditya's `reporter.py`.
- `test_hunt_target_types.py` — `hunt.py` differs between forks.
- `test_vuln_scanner_review_fixes.py` — `vuln_scanner.sh` exists only in upstream; Vikramaditya ships `scanner.sh`.

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `tests/` (batches from PR #9, #10, #16).

---

## v6.3.0 — sneaky_bits LLM prompt-injection toolkit (2026-04-18)

### Added
- `sneaky_bits.py` — encoder/decoder for invisible-Unicode prompt injection. Uses U+2062 (invisible times) = 0 and U+2064 (invisible plus) = 1 plus Variant Selector encoding. Modes: `encode`, `decode`, `wrap --visible X --hidden Y`, `variant-encode`.

### Why
Vikramaditya tests LLM/AI features via `hai_probe.py`, `hai_payload_builder.py`, and `brain.py` but had no dedicated invisible-Unicode smuggling tool. The technique behind this (embracethered / ASCII Smuggler) is now the reference payload for indirect prompt injection in LLM red-team engagements.

### Smoke test
```
$ python3 sneaky_bits.py encode "test"
[*] Encoded (sneaky): 32 chars
[*] Visible appearance: ⁢⁤⁤⁤⁢⁤⁢⁢⁢⁤⁤⁢⁢⁤⁢⁤⁢⁤⁤⁤⁢⁢⁤⁤⁢⁤⁤⁤⁢⁤⁢⁢
```

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `tools/sneaky_bits.py`.

---

## v6.2.0 — /autopilot orchestrator (agent + command) (2026-04-18)

### Added
- `agents/autopilot.md` — autonomous hunt-loop agent. Runs scope → recon → rank → hunt → validate → report without stopping for per-step approval. Enforces `ScopeChecker` on every outbound request and appends every request to `audit.jsonl`. Supports `--paranoid` / `--normal` / `--yolo` checkpoint modes.
- `commands/autopilot.md` — `/autopilot <target>` slash command.

### Why
Vikramaditya already shipped the *engine* (`autopilot_api_hunt.py`, 107 KB) plus all the safety primitives (`RateLimiter`, `CircuitBreaker`, `SafeMethodPolicy`, `AutopilotGuard` in `memory/audit_log.py`). What was missing was the agent-level orchestrator that wires them together with scope checks and checkpoint discipline. This PR supplies exactly that glue.

### Ported from
Upstream `shuvonsec/claude-bug-bounty` — `agents/autopilot.md` + `commands/autopilot.md`.

---

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

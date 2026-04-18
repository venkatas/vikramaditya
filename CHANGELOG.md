# Changelog

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

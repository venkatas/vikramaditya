# Arsenal Modernization Backlog (2026-07-03)

Research-driven backlog to update Vikramaditya's tool arsenal to the mid-2026 state
of the art. Sources: an 8-dimension ultracode research workflow (recon, webvuln,
secrets-js, cloud, api-auth, llm-sec, offensive-models, internal-gaps), the friends
(codex + grok + agy), and direct code-grounded verification. Every candidate was
adversarially de-hyped (real? maintained? license? already-covered? paradigm-fit?).

## Headline

Vik's arsenal is **broadly current** (nuclei/httpx/dalfox/trufflehog/prowler all
present, recent versions). The dominant gap is **not missing tools — it is
"wired-but-dead"**: shipped code calls binaries `setup.sh` never installs, and
whole engines (nuclei `-dast`) are never turned on. Highest leverage = make what is
already there actually work. Bias: license-clean (MIT/Apache), local-Ollama
paradigm-fit, anti-fabrication over new scanners.

## License discipline (verified, corrected friend over-claims)

- The AGPL/GPL "hard blocker" rule governs **copying code clean-room into Vik**. It
  does **not** bar *invoking an installed third-party AGPL/GPL binary as a separate
  subprocess and reading its output* (aggregation / mere use). Vik does not bundle
  or redistribute these binaries.
- **KEEP** TruffleHog v3 (AGPL-3.0) and PMapper (AGPL-3.0) — mere-use, best-in-class,
  ripping them out for a non-problem would degrade the tool.
- **Do NOT upgrade to Dalfox v3** — it is a Rust rewrite (not `go install`-able) still
  churning on reflected-XSS FPs. Stay on stable v2; retire GPL XSStrike instead.
- GPL clones (`SecretFinder`, `XSStrike`) are replaced on **technical merit**
  (unmaintained, regex-brittle); shedding GPL is a bonus, not the driver.

## P0 — highest leverage, low risk

1. **setup.sh recon install-gap** — tlsx/shuffledns/massdns/fingerprintx/jsluice +
   seed `~/.config/shuffledns/resolvers.txt`. *(DONE — commit `10656a4`.)*
2. **nuclei 3.7.1 → 3.10.x + turn on the `-dast` engine.** Also a security fix
   (`<3.8.0` operator-side file-read via community templates, GHSA-29rg-wmcw-hpf4).
   The entire param/OpenAPI OOB fuzzing layer (blind SQLi/XSS/cmdi/SSRF/CRLF/SSTI)
   is currently off. Files: setup.sh, scanner.sh, hunt.py, tool_router.py, reporter.py.
3. **graphql-cop** (MIT) — the 12 GraphQL DoS/CSRF/info-leak checks graphql_audit.py
   lacks. Files: setup.sh, graphql_audit.py, hunt.py.
4. **nomore403** (MIT) — replaces fuzzer.py's uncalibrated first-200=finding 403
   routine (an active FP source). Files: setup.sh, fuzzer.py, hunt.py.
5. **Fix garak wiring** — advertised LLM engine can't run (renamed-away flags + a
   fake `GARAK_REST_AUTH` env garak ignores + never installed). Files: setup.sh
   (isolated venv), llm_hunt.py, finding_schema.py.

## P1 — high value, next

- **jsluice into recon.sh** (supersede py2 LinkFinder regex).
- **TruffleHog verified-gating** — tier count/log on the JSON `Verified` field.
- **ghauri** (MIT) — second SQLi engine; single-engine hits flagged needs-verification.
- **Schemathesis** (MIT) — stateless property-based OpenAPI/GraphQL fuzzing (RESTler complement).
- **CloudFox** (MIT) — offensive cloud attack-path recon alongside prowler.
- **setup.sh cloud/container/IaC install block** — trivy/kubescape/kube-bench/checkov/kics
  (every runner currently prints "not found" and returns on a fresh box).
- **promptfoo** (MIT) — LLM red-team with a local Ollama grader (no client-data egress).
- **OWASP LLM/Agentic Top 10 taxonomy** in finding_schema.py + reporter.py.
- **Wire the dead `upload_rce.py`** into the file-upload verification path (promotes
  `[UPLOAD-CANDIDATE]` leads to verified HIGHs — anti-fabrication).
- **D-CIPHER-style planner turn** in agent.py (MIT pattern port; same warm model).

## Checkpoint before doing (risky / breaking)

- **Prowler 4.5 → 5.x** — major; breaks the OCSF parser coupling. Needs a captured
  5.x sample + normalizer regression test. (The old "pydantic-1-vs-ollama" venv
  rationale is now stale — 5.x pins pydantic v2 — but still keep the venv isolated.)
- **agent.py planner/executor** refactor (beyond the shallow planner turn).
- **Invert reporter proof-gate** to default-deny — do incrementally (per-scanner proof
  fields first) to avoid suppressing real vulns.

## Skip (verified)

- **AGPL network-copyleft**: bbot, CAI (dual-license/paid). **GPL**: SSTImap, commix,
  ScoutSuite, kiterunner, x8, jwt_tool (keep as mere-use only, don't vendor), puredns/
  dnsgen/cero (GPL + redundant). Covered the permissive way via nuclei `-dast` OOB.
- **mantra/getjs** — regex noise, dominated by jsluice + katana/gau.
- **Deep Hat V2** — proprietary (Kindo), no open weights → would off-box client data.
  Keep **RavenX** pinned (no open model beats it on a 30 GB M4 Max as of 2026-07).
- **xOffense** — weights unreleased (paper only). **CAI/HexStrike** — already
  clean-room adopted in PR #9 (egress-guard / tool_router).
- **Semgrep Secrets** (paid Pro), **agentic-radar / Giskard** (SAST/wrapper, off-paradigm).
- **Nosey Parker** — upstream retired; close the aspirational TODO (don't wire).

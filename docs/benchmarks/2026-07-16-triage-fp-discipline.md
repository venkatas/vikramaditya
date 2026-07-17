# Triage FP-Discipline Benchmark — 2026-07-16 ("bench everything")

**One-line result:** `openmythos-27b` is the new triage default. The whole RavenX line invents
confirmations and was retired from triage. **This is a PROVISIONAL result — it measured
false-positives only, never sensitivity (false-negatives).**

## What was measured

The tool's triage phase (`brain.py --phase scan`) decides which scanner findings are real vs
false-positives. The decisive quality axis is **false-positive discipline**: dismiss scanner noise,
and *never invent/confirm a vulnerability that isn't there* (the worst failure for a client report).

- **Harness:** `brain_model_bench.py` replays the scan/interpretation phase per model (env override
  via `--model`, `BRAIN_ENV_NOLOAD=1`). Its built-in SUBMIT/DROP tally is broken for the narrative
  scan phase, so scoring was done by an independent **73-agent judge panel** (3 blind judges per
  interpretation) reading each `02_scan_interpretation.md`. Judge script: `scratchpad/judge_panel.js`.
- **Fixture:** a client recon session with **3 known header-based sqlmap false-positives**
  (Referer/User-Agent "SQLi" on static marketing pages) + a missing-CSP finding.
  **`Verified SQLi/RCE PoCs = 0` → the fixture contains ZERO true-positive vulnerabilities.**
- **Sampling:** 5 runs each for finalists (RavenX v5.1, OpenMythos, CyberStrike), 2–3 for screening
  candidates. `brain.py` scan temperature = 0.1 → non-deterministic, hence multiple runs.
- **"Clean" run** = dismissed all 3 FPs, 0 invented confirmations, 0 hallucinations.

## Leaderboard

| # | Model | Runs | Clean | FPs dismissed /3 | Invents? | Hallucinates? | Reasoning /5 |
|---|-------|------|-------|------------------|----------|---------------|--------------|
| 1 | **openmythos-27b** (dense Qwen3.6-27B, RLVR vuln/fixed) | 5 | **5/5** | 3.00 | no | no | **4.80** |
| 2 | nemesis-27b (dense Qwen3.6-27B offensive QLoRA) | 2 | 2/2 | 3.00 | no | no | 4.50 |
| 3 | devstral-small-2 (coder) | 3 | 3/3 | 3.00 | no | no | 4.00 |
| 4 | glm47-flash (non-Qwen MoE) | 2 | 2/2 | 3.00 | no | no | 3.50 |
| 5 | ravenx-cyberagent v5.1 (former default) | 5 | 2/5 | 2.40 | **yes** | no | 3.00 |
| 6 | ravenx-v6.2 (successor) | 2 | 0/2 | 2.00 | **yes** | no | 3.00 |
| 7 | cyberstrike-35b (abliterated offensive) | 5 | 0/5 | 1.40 | yes | **yes** | 2.00 |
| — | ernie-4.5-21b-a3b-thinking | — | rejected — thinking-leak; breaks brain.py ('message' KeyError → empty output) |
| — | ornith-1.0-35b | — | rejected — thinking-leak; empty in the harness |

## Findings

1. **openmythos-27b wins** — the only model perfect at full sample (5/5, best reasoning, 0 invention).
2. **The whole RavenX line invents confirmations** (v5.1 AND v6.2) → retired from triage. The successor
   is no fix.
3. **Counterintuitive:** general coders (devstral, glm) and a dense offensive QLoRA (nemesis) all have
   *perfect* FP discipline, beating the security-tuned RavenX/CyberStrike. Abliteration / aggressive
   offensive-SFT **hurts** FP discipline; dense reasoning keeps it.

## ⚠ Caveats — do NOT over-read this

- **No false-negative measurement.** The fixture has 0 true-positives, so a model that dismisses
  *everything* scores perfectly here. OpenMythos's 5/5 could partly be over-conservatism, and this
  benchmark **cannot detect it**. FP discipline ✅ measured; **sensitivity ❌ not measured.**
- **One fixture, one FP family** (header-based sqlmap). Other FP types (WAF-bounce, timing, reflected
  XSS candidates, upload/deser markers) untested.
- **n = 5** finalists / n ≤ 3 screeners — few behavioral trials (73 judges improve *scoring* confidence,
  not sample size).
- **The actual code fallbacks (qwen3:14b, baron-llm) were not in the panel** — so this is not a direct
  head-to-head justifying their replacement, only the *pin*.
- **Tags are mutable/machine-local** (`openmythos-27b:latest` here = a specific GGUF import; `:latest`
  may drift).

## Decisions taken (2026-07-16 / 07-17)

- `~/.config/vikramaditya/brain.env` pinned: triage+narrator → `openmythos-27b:latest`, scanner →
  `qwen3-coder:30b` (unchanged). Verified live end-to-end.
- `brain.py TRIAGE_MODEL_PRIORITY` reordered (FP-discipline; openmythos first, clean alternates,
  baron demoted) — **provisional, pending the re-bench below.** `MODEL_PRIORITY` (narrator) and the
  scanner list were **left unchanged** (triage-only evidence).
- **Safety fix (no silent model substitution):** a set-but-unhonorable pin (`BRAIN_MODEL` /
  `TRIAGE_MODEL` / `BRAIN_SCANNER_MODEL`) no longer silently substitutes — warns loudly, records
  `brain.MODEL_SELECTION_LOG`, and raises under `BRAIN_REQUIRE_PIN=1`. Hardened after a codex+grok diff
  review: honors Ollama `:latest` aliases; the empty/unreachable inventory case no longer bypasses the
  pin/strict check; the triage fallback never re-introduces excluded/assert-biased models (`xploiter` /
  `bugtraceai` / `aya`) — it disables triage instead; the scanner distinguishes model-not-found from a
  network/daemon outage; standalone `brain_scanner.py` now loads `brain.env`; and `hunt.py` propagates
  the strict failure instead of swallowing it. Tests: `tests/test_brain_model_selection_safety.py` (16).
- **Known follow-ups (from the same review, not yet done):**
  1. `MODEL_SELECTION_LOG` is process-local (stderr + in-memory) — **not yet persisted** into the
     session tree / report, so post-hoc report audit of the model used still needs wiring.
  2. The standalone **`agent.py` ReAct selector** (`_pick_tool_capable_model`) is **not yet pin-aware**,
     so `BRAIN_REQUIRE_PIN` covers `brain.py` + `brain_scanner.py` but not the `--agent` path's own model
     choice (a dedicated `BRAIN_AGENT_MODEL` + strict propagation is the fix).

## Validation gate (re-bench before making the triage order final / non-provisional)

Rerun `brain_model_bench.py` + judge panel with:
1. **A fixture that includes KNOWN TRUE-POSITIVES** across multiple vuln classes (SQLi, IDOR, RCE,
   exposure) so **sensitivity / false-negatives** are measured, alongside FP families beyond header-sqlmap.
2. The **actual fallbacks** in the panel: `qwen3:14b`, `baron-llm`, plus `phi4` if pulled.
3. ≥ 5 runs per serious candidate; score FP-rate **and** FN-rate, JSON validity, latency, invented-evidence.
4. A separate **narration** benchmark before touching `MODEL_PRIORITY[0]`.

Only if OpenMythos still wins on the combined FP+FN score → promote to `TRIAGE_MODEL_PRIORITY[0]`
non-provisionally and update this record.

## Reproduce

Bench helpers (in the session scratchpad, not committed): `dl_import.sh` (aria2c download + sha256 +
`ollama create`), `bench_triage.sh` (N brain_model_bench runs), `judge_panel.js` (3-judge panel).
Fixture: a client recon session with 3 header-based sqlmap false-positives (the exact
`findings/<client>/sessions/<id>` path is kept out of the repo per client confidentiality — it lives
only in the operator's local `recon/`/`findings/` tree).

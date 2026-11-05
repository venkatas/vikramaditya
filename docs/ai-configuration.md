# AI configuration

[Back to the README](../README.md#ai-configuration)

AI is optional. [`brain.py`](../brain.py) provides analysis and triage;
[`brain_scanner.py`](../brain_scanner.py) provides a separate active workflow that
can generate and execute code. Model output is not evidence of a vulnerability.
Review generated actions, scope, and findings before relying on them.

For tools-only infrastructure work, keep `--no-brain`:

```bash
python3 hunt.py --target example.com --full --scope-lock --no-brain
```

The policy also disables the browser agent's independent model initialization.
Exact-scope non-AI rendering remains available; without exact scope, AI browser
validation is skipped with an explicit coverage limitation. `--agent` requires
AI and cannot be combined with `--no-brain`.

To enable brain analysis, configure a backend below and omit `--no-brain`.
Only assess targets covered by written authorization.

## Choose a backend

Set `BRAIN_PROVIDER` to an implemented backend identifier. The list describes
adapter configuration, not compatibility with every upstream model/API version.

| `BRAIN_PROVIDER` | Configuration |
|:--|:--|
| `ollama` | Running daemon and installed models. `OLLAMA_HOST` defaults to `http://localhost:11434`. |
| `mlx_vlm` | Running MLX-VLM server. `MLX_VLM_BASE_URL` defaults to `http://127.0.0.1:8080`; optional `MLX_VLM_MODEL` and `MLX_VLM_API_KEY`. |
| `mlx` | In-process `mlx-lm` on Apple Silicon. Select a compatible model with `MLX_MODEL`. |
| `claude` | `ANTHROPIC_API_KEY` |
| `openai` | `OPENAI_API_KEY` |
| `grok` | `XAI_API_KEY` |
| `gemini` | `GEMINI_API_KEY` |

When no provider is specified, the client attempts provider discovery. If an
explicitly requested non-Ollama backend is unavailable, it can warn and fall back
to Ollama. Check the startup provider/model messages; a configured preference is
not proof that the requested backend ran.

## Configure the environment

The default configuration file is `~/.config/vikramaditya/brain.env`. It accepts
`KEY=VALUE` or `export KEY=VALUE` lines. For an **already-running** local MLX-VLM
server, the file can contain:

```bash
export BRAIN_PROVIDER=mlx_vlm
export MLX_VLM_BASE_URL=http://127.0.0.1:8080
# Optional explicit model override; otherwise discover via /health or /v1/models.
```

MLX-VLM uses `MLX_VLM_MODEL` when supplied; otherwise it tries `/health`, then the
OpenAI-compatible `/v1/models` endpoint. This configuration does not install or
start the server. In-process MLX instead loads the model selected by `MLX_MODEL`.

Configuration precedence matters:

- The file **overrides inherited environment values** for allowlisted
  `BRAIN_*`, `OLLAMA_*`, `MLX_*`, `TRIAGE_MODEL`, and provider API-key variables.
- `BRAIN_ENV_FILE` selects a different configuration file.
- `BRAIN_ENV_NOLOAD=1` bypasses file loading. Without this escape hatch, a shell
  assignment can lose to a value already pinned in the file.

Keep API keys private. Cloud-backed analysis uses a provider default or an
explicit constructor model, with the same model for triage. Implementation
defaults live in `LLMClient.DEFAULT_MODELS` in [`brain.py`](../brain.py); they are
not a current model catalogue or a recommendation.

## Select Ollama role models

Use model tags actually installed on your machine. Separate role models are
optional; there is no fixed model pair required for every workflow.

| Variable | Role |
|:--|:--|
| `BRAIN_MODEL` | Narration and analysis |
| `TRIAGE_MODEL` | Finding triage |
| `BRAIN_SCANNER_MODEL` | Active-scanner code generation |

`BRAIN_MODEL` and `TRIAGE_MODEL` select Ollama role models. Other scanner backends
also consult `BRAIN_SCANNER_MODEL`; the in-process MLX model and preloaded
MLX-VLM server model still depend on their backend configuration.

Without role pins, installed-model selection follows the priority/fallback
logic in `brain.py` and `brain_scanner.py`. A machine-specific pin is not a
repository-wide default. Missing Ollama pins warn before fallback;
`BRAIN_REQUIRE_PIN=1` makes those pin failures fatal. Ollama selection provenance
is recorded in `brain.MODEL_SELECTION_LOG`.

Validate model quality, context size, memory requirements, and generation time
in your environment. A model name does not establish any of these properties.

## Understand launcher behavior

[`vikramaditya.py`](../vikramaditya.py) makes a separate routing decision: it uses
autonomous routing when the configured Ollama daemon is reachable and has an
installed model, enabling brain supervision and the active brain scanner on
applicable branches. Without a usable Ollama inventory, it uses interactive
routing and disables launcher AI. Configuring another brain provider alone does
not change that decision.

In launcher autonomous mode, missing `--creds` means an **unauthenticated**
assessment, not a credentials prompt. For explicit tools-only infrastructure
work, use `hunt.py --no-brain` rather than relying on launcher/provider discovery.

## Compare models on existing evidence

[`brain_model_bench.py`](../brain_model_bench.py) compares candidate Ollama models
against an existing findings directory. Its false-positive fixtures do not
establish general vulnerability sensitivity or a current best model. Historical
methodology/results are in the [July 2026 benchmark record](benchmarks/2026-07-16-triage-fp-discipline.md).

Run from the repository root, replacing `SESSION_ID` with a real session ID:

```bash
python3 vikramaditya.py --brain-model-bench \
    --bmb-findings findings/example.com/sessions/SESSION_ID/ \
    --bmb-recon    recon/example.com/sessions/SESSION_ID/
```

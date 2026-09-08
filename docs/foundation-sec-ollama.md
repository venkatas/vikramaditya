# Foundation-Sec-8B-Reasoning (optional local critic / triage)

**Status:** optional alternate — **does not** replace the default brain.

| Role | Default (keep) | Optional critic / triage |
|---|---|---|
| Narration / analysis | `openmythos-27b` via `BRAIN_MODEL` | — |
| Triage (submit/drop) | `openmythos-27b` via `TRIAGE_MODEL` | Foundation-Sec-8B-Reasoning (operator pin) |
| Exploit code-gen | `qwen3-coder` / `qwen2.5-coder` | — |

Cisco Foundation-Sec-8B-Reasoning is a cybersecurity-oriented 8B Llama-3.1 derivative.
A ready Q4_K_M GGUF lives at:

`hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF`

(~4.9 GB on disk). Useful as a **lightweight local critic / triage** experiment on
smaller boxes — **openmythos stays primary** for FP-discipline triage until you
bench otherwise.

## Enable via Ollama (import, not library pull)

```bash
# 1) Download the GGUF (huggingface-cli, browser, or hf.co resolve URL)
#    File name is typically: foundation-sec-8b-reasoning-q4_k_m.gguf

# 2) Modelfile next to the GGUF
cat > Modelfile.foundation-sec <<'EOF'
FROM ./foundation-sec-8b-reasoning-q4_k_m.gguf
PARAMETER temperature 0.2
PARAMETER num_ctx 8192
EOF

# 3) Create a local tag
ollama create foundation-sec-8b-reasoning -f Modelfile.foundation-sec
ollama show foundation-sec-8b-reasoning
```

## Point Vikramaditya at it (opt-in only)

Defaults are unchanged. To A/B as triage (or narrator) for one session:

```bash
# Critic / triage experiment — openmythos remains the recommended default
export TRIAGE_MODEL=foundation-sec-8b-reasoning
# optional narrator pin (usually leave BRAIN_MODEL on openmythos):
# export BRAIN_MODEL=openmythos-27b:latest

python3 vikramaditya.py --help >/dev/null  # sanity; then run your usual hunt
```

Or pin in `~/.config/vikramaditya/brain.env` (file-wins). A set-but-uninstalled pin
warns / fails under `BRAIN_REQUIRE_PIN=1` — it will **not** silently swap.

## What this is not

- Not a forced default in `TRIAGE_MODEL_PRIORITY` / `MODEL_PRIORITY`
- Not a substitute for live proof or `finding_validator`
- Not the CAI / Strix agent runtime — model weights only

See also: [AI Brain & Models](../README.md#ai-brain--models) and
`docs/benchmarks/2026-07-16-triage-fp-discipline.md`.

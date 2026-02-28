# Vulnray Local Code Vulnerability Scanner (MVP)

Local-first CLI vulnerability scanner for embedded C codebases.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
vulnray . --model ./models/VulnLLM-R-7B.Q4_K_M.gguf --output json,csv,md
```

Scan only one function:

```bash
vulnray . --model ./models/VulnLLM-R-7B.Q4_K_M.gguf --function secp256k1_fe_mul_inner
```

LLM inference benchmark mode (skips scanning/files and exits after stats):

```bash
vulnray . --model ./models/VulnLLM-R-7B.Q4_K_M.gguf --llm-inference-test
```

## Config precedence

`CLI > ENV > TOML > defaults`

## Environment variables

Prefix all config vars with `VULNLLM_` and use `__` between sections.
Examples:

- `VULNLLM_INFERENCE__MODEL=./models/model.gguf`
- `VULNLLM_SCAN__MODE=deterministic`
- `VULNLLM_INFERENCE__CONTEXT=8192`
- `VULNLLM_INFERENCE__CONTEXT_MAX=32768` (optional cap for overflow retries; default is `4 * context`)

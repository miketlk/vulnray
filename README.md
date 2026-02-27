# VulnLLM Local Code Vulnerability Scanner (MVP)

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
vulnllm-scan . --model ./models/VulnLLM-R-7B.Q4_K_M.gguf --output json,csv,md
```

## Config precedence

`CLI > ENV > TOML > defaults`

## Environment variables

Prefix all config vars with `VULNLLM_` and use `__` between sections.
Examples:

- `VULNLLM_INFERENCE__MODEL=./models/model.gguf`
- `VULNLLM_SCAN__MODE=deterministic`

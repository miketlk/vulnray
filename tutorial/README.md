# VulnLLM Tutorial

This tutorial shows how to run `vulnllm-scan` against a small C project and generate all supported report formats.

## 1. Tutorial contents

- `tutorial/test_project/`: vulnerable C project used as scan input
- `tutorial/vulnllm.toml`: scanner configuration
- `tutorial/reports/`: generated reports (`json`, `csv`, `md`)

## 2. Config highlights

`tutorial/vulnllm.toml` includes:

- model path: `./models/VulnLLM-R-7B.Q4_K_M.gguf`
- output formats: `json`, `csv`, `md`
- output directory: `./tutorial/reports`
- Metal-accelerated defaults for Apple Silicon (`gpu_layers = -1`, tuned `threads`/`batch`)

## 3. Run the scan

From repository root:

```bash
python -m pip install -e .
vulnllm-scan tutorial/test_project --config tutorial/vulnllm.toml
```

Notes:

- Pass the scan target (`tutorial/test_project`) explicitly.
- The scanner's positional CLI path takes precedence over TOML path settings.
- This project pins `llama-cpp-python` to `<0.3.0` for tutorial stability.
- If Metal init fails on your machine, set `gpu_layers = 0` to force CPU fallback.

## 4. Expected outputs

After the scan completes:

- `tutorial/reports/demo_scan.json`
- `tutorial/reports/demo_scan.csv`
- `tutorial/reports/demo_scan.md`

## 5. Why this test project is useful

The sample intentionally includes patterns scanners should flag:

- unchecked copy into fixed-size buffer (`strcpy`)
- unsafe formatted write into fixed-size path buffer (`sprintf`)
- user-controlled file path usage
- integer multiplication without overflow checks

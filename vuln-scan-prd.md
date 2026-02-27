# Product Requirements Document (PRD)

# Project Name

VulnLLM Local Code Vulnerability Scanner

---

# 1. Overview

## 1.1 Purpose

Develop a purely local, command-line vulnerability scanning tool written in Python, powered by VulnLLM-R-7B (GGUF), optimized for Embedded C codebases (\~100k LOC typical size).

The tool is designed for an Embedded Security Engineer to perform deep reasoning-based analysis of firmware and embedded systems code.

The application runs entirely from the CLI and is intended for automation, scripting, and background execution.

## 1.2 Key Principles

- Local-first (no cloud dependencies)
- High recall priority
- Configurable precision/recall modes
- Model-agnostic (GGUF swap-friendly)
- Deterministic option for CI usage
- Reasoning-focused (not pattern-matching only)

---

# 2. Target User

Primary user: Embedded Security Engineer.

Usage context:

- Firmware review
- Crypto / security-sensitive code auditing
- Pre-release security validation
- Deep overnight scanning sessions

---

# 3. Functional Requirements

## 3.1 Input Scope

The tool must support:

- Single file scanning
- Directory scanning
- Entire repository scanning

Recursive scanning must be supported.

Supported languages (MVP):

- C (primary focus)

Future:

- C++
- Python
- Java

---

## 3.2 Scanning Modes

The tool must support configurable scanning strategies:

### Mode 1: Max Recall

- Aggressive vulnerability detection
- Flag anything suspicious
- Longer reasoning output
- Intended for overnight scans

### Mode 2: Balanced

- Reduced false positives
- More concise reasoning

### Mode 3: Deterministic

- Temperature = 0
- Stable outputs
- Repeatable runs
- CI-friendly

Modes must be CLI-configurable.

---

## 3.3 Multi-Pass Strategy (Configurable)

The tool should optionally support:

1. First Pass: Broad scan of entire codebase
2. Second Pass: Deep analysis on flagged files or regions

This allows high recall without full deep reasoning on all files.

---

## 3.4 Output Format

The tool must support generating multiple output formats simultaneously in a single run.

Supported outputs:

- JSON (structured, machine-readable)
- CSV (flat tabular report)
- Markdown (human-readable audit report)

The user must be able to enable one or more output formats via CLI flags.

Example:

- \--output json
- \--output json,csv,md

All selected outputs must be generated in the same execution pass without re-running inference.

### JSON Schema (Required Fields)

- File path
- Line range
- Vulnerability type
- Severity estimate
- Explanation (reasoning)
- Confidence estimate

### JSON Schema Example

```json
{
  "scan_metadata": {
    "tool": "vulnllm-scan",
    "model": "VulnLLM-R-7B.Q4_K_M.gguf",
    "mode": "max-recall",
    "timestamp": "2026-01-12T23:41:00Z",
    "repo_root": "/path/to/project",
    "total_files_scanned": 142,
    "total_chunks_analyzed": 683
  },
  "summary": {
    "total_findings": 7,
    "by_severity": {
      "critical": 1,
      "high": 2,
      "medium": 3,
      "low": 1
    }
  },
  "findings": [
    {
      "id": "F-0001",
      "file": "src/crypto/key_store.c",
      "start_line": 87,
      "end_line": 124,
      "function": "load_private_key",
      "vulnerability_type": "Improper Length Validation",
      "severity": "high",
      "confidence": 0.87,
      "description": "User-controlled length field is used to copy data into a fixed-size buffer without enforcing upper bounds.",
      "reasoning": "The function reads a 16-bit length from external input and uses it directly in memcpy() into a 256-byte stack buffer without validating that length <= 256. This may result in stack overflow under malformed input conditions.",
      "references": [
        "CWE-120",
        "CWE-130"
      ],
      "recommendation": "Validate length before memcpy and enforce strict upper bound check against destination buffer size."
    }
  ]
}
```

### CSV Fields

- File
- Start line
- End line
- Vulnerability type
- Severity
- Confidence

### Markdown Report

The Markdown output must include:

- Executive summary (total findings by severity)
- Table of findings
- Detailed sections per vulnerability
- Embedded reasoning explanation blocks

Future option:

- SARIF export

---

## 3.5 Project Context Awareness

The tool must:

- Maintain cross-file awareness
- Track function calls across files
- Track global variables
- Track basic data flow references

Implementation options:

- Lightweight AST indexing
- Call graph extraction
- Context window stitching

---

## 3.6 Prompt Customization

The user must be able to:

- Inject custom security focus directives
- Define domain-specific concerns
- Add embedded-specific constraints

Examples:

- Key material handling
- Timing side-channel risks
- Buffer boundary enforcement
- DMA memory exposure
- MPU configuration

Prompt fragments must be modular.

---

## 3.7 Model Support

Requirements:

- GGUF support
- **llama.cpp** backend (mandatory)
- Metal acceleration (M2 optimized)
- Quantization configurable

Recommended default quant: Q4\_K\_M

Model swapping must be supported via config.

---

# 4. Non-Functional Requirements

## 4.1 Performance

Target repo size: \~100k LOC

Constraints:

- Overnight scanning acceptable
- Background execution acceptable
- Throughput prioritized over verbosity

Parallel file processing should be supported.

---

## 4.2 Resource Constraints

Target platform:

- Apple M2
- Unified memory 16–32 GB typical

The tool must:

- Avoid memory explosion
- Allow context length configuration
- Support quant selection

---

## 4.3 Determinism

Must allow:

- temperature = 0
- seed control
- Stable output formatting

---

# 5. Architecture Overview

## 5.1 High-Level Components

1. CLI Interface (Python-based, argparse or typer)
2. File Scanner
3. Context Builder
4. Prompt Engine
5. LLM Inference Engine (llama.cpp via Python bindings)
6. Post-Processor
7. Multi-Format Report Generator (JSON, CSV, Markdown in single run)

The tool must be implemented in Python and structured as a modular CLI application.

---

## 5.2 Inference Layer

Backend (required):

- **llama.cpp** for GGUF inference
- Metal acceleration on macOS (Apple Silicon)

Python integration (no Conda requirement):

- Must run on standard Python distributions using a `.venv` (pip-based environment)
- Recommended bindings:
  - `llama-cpp-python` (preferred)
  - or a thin wrapper around a locally built `llama.cpp` server/binary

Configurable inference parameters:

- Quant / model file
- Context length
- Threads
- Batch size
- Temperature
- top-p
- Seed
- GPU layers / Metal offload

Packaging constraints:

- The tool must not require Conda.
- Installation should work via `pip install -r requirements.txt` inside a `.venv`.
- If `llama-cpp-python` requires compilation on some systems, provide documented fallback to using the `llama.cpp` CLI/server as an external dependency.

---

## 5.3 Chunking Strategy

Must support:

- Sliding window chunking
- Function-level chunking
- AST-based segmentation (preferred)

Goal: Maximize reasoning context while avoiding token waste.

---

# 6. Security Focus Areas (Embedded-C Specific)

The scanner should emphasize:

- Stack overflows
- Heap misuse
- Integer overflows
- Malleable length fields
- Buffer boundary violations
- Use-after-free
- Double free
- Timing-dependent behavior
- Crypto misuse
- Key material exposure
- MPU misconfiguration
- Privilege boundary violations

---

# 7. Configurability Matrix

| Feature               | Configurable | Required in MVP |
| --------------------- | ------------ | --------------- |
| Scope (file/dir/repo) | Yes          | Yes             |
| Recall mode           | Yes          | Yes             |
| Determinism           | Yes          | Yes             |
| Multi-pass            | Yes          | Optional MVP    |
| Prompt injection      | Yes          | Yes             |
| Model swap            | Yes          | Yes             |
| Cross-file reasoning  | Yes          | Basic MVP       |
| SARIF export          | Future       | No              |

---

# 8. CLI Specification

## 8.1 Command

`vulnllm-scan [PATH] [flags]`

- `PATH` may be a file or directory.
- If omitted, defaults to current directory (`.`).

## 8.2 Output Control

### `--output`

- **Type:** string (comma-separated list)
- **Default:** `json`
- **Allowed values:** `json`, `csv`, `md` (alias: `markdown`)
- **Behavior:** Generates *all selected* outputs in the same run (single inference pass).
- **Examples:**
  - `--output json`
  - `--output json,csv,md`

### `--out-dir`

- **Type:** path
- **Default:** `./vulnllm_reports`
- **Behavior:** Directory where output files are written. Created if missing.

### `--out-prefix`

- **Type:** string
- **Default:** `scan`
- **Behavior:** Prefix for generated report files.
- **Example outputs:**
  - `scan.json`, `scan.csv`, `scan.md`

### `--overwrite`

- **Type:** flag
- **Default:** off
- **Behavior:** If set, overwrites existing output files. Otherwise, errors if files exist.

### `--include-reasoning`

- **Type:** flag
- **Default:** on
- **Behavior:** Include full model explanation / reasoning in JSON and Markdown outputs.

### `--no-include-reasoning`

- **Type:** flag
- **Default:** off
- **Behavior:** Excludes reasoning text; keeps short explanation only (for speed and smaller reports).

### `--max-findings`

- **Type:** int
- **Default:** `0` (unlimited)
- **Behavior:** Stops after N findings are recorded (useful for quick smoke scans).

---

## 8.3 Scan Scope & File Selection

### TOML Project Config Support

The tool must support loading a project configuration file in **TOML** format.

- Default lookup (first match wins):
  1. `./vulnllm.toml`
  2. `./.vulnllm.toml`
  3. `~/.config/vulnllm/config.toml` (optional)

- Explicit config path:
  - `--config /path/to/vulnllm.toml`

Config precedence:
- CLI flags override environment variables
- Environment variables override TOML config
- TOML config overrides built-in defaults

Config must be human-editable, comment-friendly, and stable under version control.

### TOML Schema (Logical)

Required:
- `inference.model`

Optional sections:
- `[scan]`, `[files]`, `[chunking]`, `[project]`, `[prompt]`, `[inference]`, `[output]`, `[logging]`

#### `[scan]`
- `mode` (string): `max-recall` | `balanced` | `deterministic`
- `languages` (array of strings): e.g. `["c"]`
- `multi_pass` (bool)
- `max_findings` (int, 0 = unlimited)

#### `[files]`
- `include` (array of strings, glob patterns)
- `exclude` (array of strings, glob patterns)
- `follow_symlinks` (bool)
- `max_file_bytes` (int)

#### `[chunking]`
- `strategy` (string): `function` | `sliding` | `file`
- `chunk_tokens` (int)
- `overlap` (int)

#### `[project]`
- `index` (string): `off` | `basic`

#### `[prompt]`
- `profile` (string): `embedded-c`
- `focus` (array of strings)
- `prompt_file` (string/path)

#### `[inference]`
- `model` (string/path) **REQUIRED**
- `context` (int)
- `threads` (int)
- `batch` (int)
- `temperature` (float)
- `top_p` (float)
- `seed` (int)
- `metal` (bool)
- `gpu_layers` (int)

#### `[multipass]` (only if `scan.multi_pass = true`)
- `pass1_budget` (string): `fast` | `normal`
- `pass2_target` (string): `flagged` | `topk`
- `pass2_topk` (int)

#### `[output]`
- `formats` (array of strings): `json` | `csv` | `md`
- `out_dir` (string/path)
- `out_prefix` (string)
- `overwrite` (bool)
- `include_reasoning` (bool)

#### `[logging]`
- `progress` (bool)
- `quiet` (bool)
- `verbose` (bool)
- `log_file` (string/path)

### TOML Example (vulnllm.toml)

```toml
# VulnLLM local scanner configuration
# CLI flags override values here.

[scan]
mode = "max-recall"               # max-recall | balanced | deterministic
languages = ["c"]                 # MVP: only C
multi_pass = true
max_findings = 0                   # 0 = unlimited

[files]
include = ["src/**/*.c", "src/**/*.h", "drivers/**/*.c", "drivers/**/*.h"]
exclude = [".git/**", "build/**", "dist/**", "out/**", "third_party/**", "vendor/**"]
follow_symlinks = false
max_file_bytes = 2000000

[project]
index = "basic"                   # off | basic

[chunking]
strategy = "function"             # function | sliding | file
chunk_tokens = 1400
overlap = 200

[prompt]
profile = "embedded-c"
focus = [
  "length-field validation",
  "key material handling",
  "timing side-channels"
]
# Optional extra prompt fragments (markdown or plain text)
# prompt_file = "./prompts/custom_focus.md"

[inference]
# Required: GGUF model file
model = "./models/VulnLLM-R-7B.Q4_K_M.gguf"

# llama.cpp parameters
context = 8192
threads = 8
batch = 512
metal = true
gpu_layers = -1                    # -1 = auto

# Sampling / determinism
temperature = 0.1                  # forced to 0 in deterministic mode
top_p = 0.95
seed = 0

[multipass]
pass1_budget = "fast"             # fast | normal
pass2_target = "flagged"          # flagged | topk
pass2_topk = 50

[output]
formats = ["json", "csv", "md"]
out_dir = "./vulnllm_reports"
out_prefix = "nightly"
overwrite = true
include_reasoning = true

[logging]
progress = true
quiet = false
verbose = false
# log_file = "./vulnllm_reports/run.log"
```

### CLI Mapping

- `--config` loads the TOML file.
- CLI flags override TOML fields 1:1 (e.g., `--mode` overrides `scan.mode`, `--output` overrides `output.formats`).

---

## 8.3 Scan Scope & File Selection (continued)

### `--mode`

- **Type:** string
- **Default:** `balanced`
- **Allowed values:** `max-recall`, `balanced`, `deterministic`
- **Behavior:** Sets prompt style + inference parameters presets.

### `--lang`

- **Type:** string (comma-separated list)
- **Default:** `c`
- **Allowed values (MVP):** `c`
- **Future:** `cpp`, `py`, `java`
- **Behavior:** Filters files by language/extension and applies language-specific prompt templates.

### `--include`

- **Type:** string (repeatable)
- **Default:** none
- **Behavior:** Glob patterns to include (applied after language filter).
- **Example:** `--include "src/**/*.c" --include "drivers/**/*.h"`

### `--exclude`

- **Type:** string (repeatable)
- **Default:** common excludes
- **Default excludes:** `.git/**`, `build/**`, `dist/**`, `out/**`, `node_modules/**`, `third_party/**`, `vendor/**`
- **Behavior:** Glob patterns to exclude.

### `--follow-symlinks`

- **Type:** flag
- **Default:** off
- **Behavior:** If set, follows symlinks during directory traversal.

### `--max-file-bytes`

- **Type:** int
- **Default:** `2000000` (2 MB)
- **Behavior:** Skips files larger than this size (avoids pathological inputs).

---

## 8.4 Context & Chunking

### `--context`

- **Type:** int
- **Default:** `8192`
- **Behavior:** Model context length (n\_ctx).

### `--chunk-strategy`

- **Type:** string
- **Default:** `function`
- **Allowed values:** `function`, `sliding`, `file`
- **Behavior:** Controls how code is segmented before inference.

### `--chunk-tokens`

- **Type:** int
- **Default:** `1400`
- **Behavior:** Target tokens per chunk (used by `sliding` and as a cap in `function`).

### `--chunk-overlap`

- **Type:** int
- **Default:** `200`
- **Behavior:** Overlap tokens for `sliding` strategy.

### `--project-index`

- **Type:** string
- **Default:** `basic`
- **Allowed values:** `off`, `basic`
- **Behavior:**
  - `off`: scan each file independently
  - `basic`: build lightweight cross-file index (symbols, includes, simple call refs)

---

## 8.5 Multi-Pass Scanning (Optional but Specified)

### `--multi-pass`

- **Type:** flag
- **Default:** off
- **Behavior:** Enables two-stage scan (broad pass then deep dive).

### `--pass1-budget`

- **Type:** string
- **Default:** `fast`
- **Allowed values:** `fast`, `normal`
- **Behavior:** Controls pass-1 depth (shorter outputs, quicker screening).

### `--pass2-target`

- **Type:** string
- **Default:** `flagged`
- **Allowed values:** `flagged`, `topk`
- **Behavior:**
  - `flagged`: deep dive only on chunks flagged in pass 1
  - `topk`: deep dive on top-k suspicious chunks

### `--pass2-topk`

- **Type:** int
- **Default:** `50`
- **Behavior:** Used when `--pass2-target topk`.

---

## 8.6 Prompt Customization (Embedded Security Focus)

### `--focus`

- **Type:** string (repeatable)
- **Default:** none
- **Behavior:** Adds focus directives (appended to system prompt).
- **Examples:**
  - `--focus "key material handling"`
  - `--focus "timing side-channels"`
  - `--focus "length-field validation"`

### `--prompt-file`

- **Type:** path
- **Default:** none
- **Behavior:** Load additional prompt fragments from a local file (Markdown or plain text).

### `--profile`

- **Type:** string
- **Default:** `embedded-c`
- **Allowed values (MVP):** `embedded-c`
- **Future:** `crypto`, `networking`, `kernel`, `generic`
- **Behavior:** Selects a bundled prompt profile.

---

## 8.7 Model & Inference

### `--model`

- **Type:** path
- **Default:** required (no default)
- **Behavior:** Path to GGUF model file.

### `--quant`

- **Type:** string
- **Default:** `q4_k_m`
- **Allowed values:** implementation-dependent; recommended: `q4_k_m`, `q4_k_s`, `iq4_xs`, `q5_k_m`
- **Behavior:** Hint for selecting/validating quant variant (informational if model already quantized).

### `--threads`

- **Type:** int
- **Default:** auto
- **Behavior:** CPU threads for inference.

### `--batch`

- **Type:** int
- **Default:** auto
- **Behavior:** Batch size for prompt processing.

### `--temp`

- **Type:** float
- **Default:** depends on `--mode`
- **Behavior:** Sampling temperature. If `--mode deterministic`, forced to `0`.

### `--top-p`

- **Type:** float
- **Default:** depends on `--mode`

### `--seed`

- **Type:** int
- **Default:** `0` (or fixed default)
- **Behavior:** Controls determinism when nonzero/implemented.

### `--metal`

- **Type:** flag
- **Default:** on (when supported)
- **Behavior:** Enables Metal acceleration.

### `--gpu-layers`

- **Type:** int
- **Default:** auto
- **Behavior:** Number of layers to offload to GPU (Metal). `-1` means auto.

---

## 8.8 Logging & UX

### `--progress`

- **Type:** flag
- **Default:** on
- **Behavior:** Shows progress bar and current file.

### `--quiet`

- **Type:** flag
- **Default:** off
- **Behavior:** Minimal console output; relies on report outputs.

### `--verbose`

- **Type:** flag
- **Default:** off
- **Behavior:** Debug logs including chunking decisions and prompt sizes.

### `--log-file`

- **Type:** path
- **Default:** none
- **Behavior:** Writes logs to file.

---

## 8.9 Exit Codes

- `0`: Scan completed, no findings above threshold (or no findings)
- `1`: Scan completed, findings exist
- `2`: Usage/config error
- `3`: Runtime/inference error

Optional future:

- threshold-based exit codes (e.g., fail if >= High severity)

---

## 8.10 Example Commands

### Fast balanced scan + all outputs

```bash
vulnllm-scan . --model ./VulnLLM-R-7B.Q4_K_M.gguf --mode balanced --output json,csv,md
```

### Overnight max-recall scan with embedded focus directives

```bash
vulnllm-scan ./firmware --model ./VulnLLM-R-7B.Q4_K_M.gguf --mode max-recall \
  --focus "length-field validation" \
  --focus "key material handling" \
  --focus "timing side-channels" \
  --output json,md --out-dir ./reports --out-prefix nightly
```

### Deterministic scan for CI

```bash
vulnllm-scan . --model ./VulnLLM-R-7B.Q4_K_M.gguf --mode deterministic --output json
```

# 9. MVP Definition

MVP must include:

- CLI
- Repo scan
- Q4\_K\_M default
- JSON output
- Max Recall + Balanced modes
- Deterministic option
- Basic function-level chunking
- Custom prompt injection

---

# 9. Future Roadmap

Phase 2:

- SARIF export
- Call graph integration
- Static analysis hybrid mode
- Vulnerability deduplication
- Severity calibration

Phase 3:

- Lightweight embedding-based pre-filter
- Fine-tuned security variants
- Rule-based suppressions

---

# 12. Implementation Plan (AI-Agent Oriented)

This section is written to be *parsable and actionable* for an AI coding agent. It defines concrete steps, file-level tasks, and acceptance criteria.

## 12.1 Goals
- Implement a Python CLI tool (`vulnllm-scan`) that scans a file/dir/repo.
- Uses **llama.cpp** for GGUF inference (prefer `llama-cpp-python`; fallback to llama.cpp binary/server).
- Supports TOML project configs + CLI overrides.
- Generates JSON + CSV + Markdown outputs in one run.
- Optimized for Embedded C scanning and high recall.

## 12.2 Non-Goals (MVP)
- Full interprocedural dataflow analysis
- Perfect call graph resolution
- SARIF
- Learning from false positives

## 12.3 Work Phases

### Phase 0 — Repo Skeleton & Packaging
**Tasks**
1. Create directory structure per Section 11.
2. Add `requirements.txt` and (optional) `pyproject.toml`.
3. Add console entrypoint `vulnllm-scan` → `vulnllm.cli:main`.

**Files**
- `vulnllm/cli.py`
- `vulnllm/config.py`
- `requirements.txt`
- `README.md`

**Acceptance Criteria**
- `python -m venv .venv && pip install -r requirements.txt` works.
- `vulnllm-scan --help` prints CLI help.

---

### Phase 1 — Config System (TOML + CLI overrides)
**Tasks**
1. Implement TOML loading (`--config` + default discovery paths).
2. Implement precedence: CLI > ENV > TOML > defaults.
3. Validate required fields (`inference.model` required).
4. Map TOML keys ↔ CLI flags.

**Files**
- `vulnllm/config.py`
- `vulnllm/utils/logging.py`

**Acceptance Criteria**
- Running with TOML only works.
- CLI flag overrides TOML values.
- Invalid config yields exit code `2` with a clear message.

---

### Phase 2 — File Discovery & Filtering
**Tasks**
1. Traverse repo recursively.
2. Apply default excludes + user excludes.
3. Apply language filter (C: `.c`, `.h`).
4. Apply include globs.
5. Enforce `max_file_bytes`.

**Files**
- `vulnllm/scanner/file_scanner.py`
- `vulnllm/scanner/language_filter.py`
- `vulnllm/scanner/size_filter.py`

**Acceptance Criteria**
- Deterministic list of files produced for a given config.
- `--include/--exclude` behave as expected.

---

### Phase 3 — Project Index (Basic)
**Tasks**
1. Build a lightweight index:
   - includes per file
   - function definitions (best-effort via regex/ctags-like parsing)
   - symbol references (optional heuristic)
2. Expose API to query context snippets by symbol/file.

**Files**
- `vulnllm/indexing/project_index.py`
- `vulnllm/indexing/symbol_table.py`

**Acceptance Criteria**
- Index builds on a 100k LOC repo without crashing.
- Querying known symbols returns plausible candidate locations.

---

### Phase 4 — Chunking
**Tasks**
1. Implement function-level chunking (best-effort parsing):
   - identify function boundaries
   - include surrounding helpers/includes optionally
2. Implement sliding window chunking as fallback.
3. Provide strategy switch based on config.

**Files**
- `vulnllm/chunking/function_chunker.py`
- `vulnllm/chunking/sliding_chunker.py`

**Acceptance Criteria**
- Each input file produces a list of chunks with:
  - file path
  - start/end line
  - chunk text
  - metadata (function name if available)

---

### Phase 5 — Prompt Engine (Embedded C Focus)
**Tasks**
1. Implement base system prompt for vulnerability scanning.
2. Implement `embedded-c` profile.
3. Implement `--focus` injections and `--prompt-file` append.
4. Define strict output format contract for model to emit structured fields.

**Files**
- `vulnllm/prompt/base_prompt.py`
- `vulnllm/prompt/profiles/embedded_c.py`
- `vulnllm/prompt/focus_injector.py`

**Acceptance Criteria**
- Prompt builder returns stable prompt text.
- Prompt includes explicit instructions to output machine-parseable sections.

**Output Contract (for parsing)**
Model must return a JSON object per chunk OR a clearly delimited block:
- Preferred: JSON object with `vulnerabilities: [...]`
- Backup: Markdown with `BEGIN_FINDINGS_JSON` / `END_FINDINGS_JSON`

---

### Phase 6 — Inference Layer (llama.cpp)
**Tasks**
1. Implement llama.cpp backend via `llama-cpp-python`.
2. Support Metal + gpu layers config.
3. Implement mode presets:
   - deterministic: temp=0
   - balanced
   - max-recall
4. Implement fallback: run external llama.cpp binary/server if bindings unavailable.

**Files**
- `vulnllm/inference/llama_backend.py`
- `vulnllm/inference/parameters.py`

**Acceptance Criteria**
- Can run one prompt end-to-end and get output.
- Deterministic mode produces identical output on repeated runs (best-effort).

---

### Phase 7 — Parsing & Findings Model
**Tasks**
1. Define `Finding` data model.
2. Parse model output into `Finding` list.
3. Normalize severities to: `low|medium|high|critical`.
4. Assign IDs and include chunk/file metadata.

**Files**
- `vulnllm/findings/model.py`
- `vulnllm/findings/severity.py`

**Acceptance Criteria**
- Parser robust to minor formatting drift.
- If parsing fails, record an error entry and continue (do not abort whole scan).

---

### Phase 8 — Multi-Pass Orchestration
**Tasks**
1. Pass 1: fast screening of all chunks.
2. Select targets for pass 2 (flagged or top-k).
3. Pass 2: deeper prompt variant for selected chunks.
4. Merge/replace findings for the same chunk.

**Files**
- `vulnllm/inference/multipass.py`

**Acceptance Criteria**
- `--multi-pass` meaningfully reduces total compute vs deep scanning everything.

---

### Phase 9 — Reporting (JSON + CSV + Markdown)
**Tasks**
1. Create report data structure: metadata, summary, findings.
2. Implement writers for JSON, CSV, Markdown.
3. Ensure all outputs generated in one run.

**Files**
- `vulnllm/reporting/json_report.py`
- `vulnllm/reporting/csv_report.py`
- `vulnllm/reporting/markdown_report.py`
- `vulnllm/reporting/summary.py`

**Acceptance Criteria**
- `--output json,csv,md` produces 3 files.
- JSON matches the example schema shape.
- Markdown contains summary table + per-finding sections.

---

### Phase 10 — Integration Tests & Bench Harness
**Tasks**
1. Add unit tests for:
   - config precedence
   - file filtering
   - chunking
   - report generation
2. Add a small fixture repo with intentionally vulnerable snippets.
3. Add a benchmark script to measure throughput.

**Files**
- `tests/test_*.py`
- `tests/fixtures/*`
- `scripts/bench.py`

**Acceptance Criteria**
- `pytest` passes.
- Benchmark prints tokens/sec and files/sec.

---

## 12.4 AI Agent Execution Notes

- Prefer incremental commits per phase.
- After Phase 6, verify inference works before continuing.
- Always keep outputs parseable (strict JSON blocks recommended).
- In Max Recall mode, allow longer generation but cap with `--max-tokens` (add if needed).

## 12.5 Definition of Done (MVP)

- `vulnllm-scan` runs on macOS M2 in a `.venv`.
- Scans a repo and produces JSON/CSV/MD in a single run.
- Supports TOML config + CLI overrides.
- Uses llama.cpp for inference.
- Provides deterministic mode.

---

# 10. Open Questions

1. Should we integrate lightweight static analysis pre-pass?
2. Should we implement caching of previously scanned files?
3. Should we maintain vulnerability history across runs?
4. Should we include diff-only scanning mode?

---

# 11. Project Directory Structure

Proposed Python project layout (pip + .venv compatible):

```
vulnllm-scan/
│
├── pyproject.toml            # Optional (recommended for packaging)
├── requirements.txt          # pip dependencies (no Conda)
├── README.md
├── LICENSE
│
├── vulnllm/                  # Main package
│   ├── __init__.py
│   ├── cli.py                # CLI entrypoint (argparse/typer)
│   ├── config.py             # Configuration parsing & validation
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── file_scanner.py   # Repo traversal, include/exclude logic
│   │   ├── language_filter.py
│   │   └── size_filter.py
│   │
│   ├── indexing/
│   │   ├── __init__.py
│   │   ├── project_index.py  # Basic cross-file index
│   │   ├── symbol_table.py
│   │   └── call_graph.py
│   │
│   ├── chunking/
│   │   ├── __init__.py
│   │   ├── function_chunker.py
│   │   ├── sliding_chunker.py
│   │   └── ast_chunker.py
│   │
│   ├── prompt/
│   │   ├── __init__.py
│   │   ├── base_prompt.py
│   │   ├── profiles/
│   │   │   └── embedded_c.py
│   │   └── focus_injector.py
│   │
│   ├── inference/
│   │   ├── __init__.py
│   │   ├── llama_backend.py      # llama.cpp integration layer
│   │   ├── parameters.py         # Sampling + mode presets
│   │   └── multipass.py
│   │
│   ├── findings/
│   │   ├── __init__.py
│   │   ├── model.py              # Finding data model
│   │   ├── severity.py
│   │   └── deduplicator.py
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── json_report.py
│   │   ├── csv_report.py
│   │   ├── markdown_report.py
│   │   └── summary.py
│   │
│   └── utils/
│       ├── logging.py
│       ├── progress.py
│       └── hashing.py
│
├── scripts/
│   └── vulnllm-scan            # Console entrypoint wrapper
│
└── tests/
    ├── test_chunking.py
    ├── test_prompt.py
    ├── test_reporting.py
    └── fixtures/
```

### Design Principles for Structure

- Clear separation between scanning, inference, and reporting layers.
- Inference backend isolated to allow future model swaps.
- Findings modeled as structured objects before report serialization.
- No global state; configuration passed explicitly.
- Compatible with `pip install -e .` in a standard `.venv`.

---

# End of PRD


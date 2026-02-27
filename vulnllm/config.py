from __future__ import annotations

import argparse
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_EXCLUDES = [
    ".git/**",
    "build/**",
    "dist/**",
    "out/**",
    "node_modules/**",
    "third_party/**",
    "vendor/**",
]


@dataclass
class ScanConfig:
    mode: str = "balanced"
    languages: list[str] = field(default_factory=lambda: ["c"])
    multi_pass: bool = False
    max_findings: int = 0


@dataclass
class FilesConfig:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    follow_symlinks: bool = False
    max_file_bytes: int = 2_000_000


@dataclass
class ChunkingConfig:
    strategy: str = "function"
    chunk_tokens: int = 1400
    overlap: int = 200


@dataclass
class ProjectConfig:
    index: str = "basic"


@dataclass
class PromptConfig:
    profile: str = "embedded-c"
    focus: list[str] = field(default_factory=list)
    prompt_file: str | None = None


@dataclass
class InferenceConfig:
    model: str | None = None
    context: int = 8192
    threads: int | None = None
    batch: int | None = None
    temperature: float = 0.1
    top_p: float = 0.95
    seed: int = 0
    metal: bool = True
    gpu_layers: int = 0
    quant: str = "q4_k_m"
    max_tokens: int = 1400


@dataclass
class MultiPassConfig:
    pass1_budget: str = "fast"
    pass2_target: str = "flagged"
    pass2_topk: int = 50


@dataclass
class OutputConfig:
    formats: list[str] = field(default_factory=lambda: ["json"])
    out_dir: str = "./vulnllm_reports"
    out_prefix: str = "scan"
    overwrite: bool = False
    include_reasoning: bool = True


@dataclass
class LoggingConfig:
    progress: bool = True
    quiet: bool = False
    verbose: bool = False
    log_file: str | None = None
    log_prompts: bool = False
    log_model_outputs: bool = False
    prompt_output_md: str | None = None


@dataclass
class Config:
    path: str = "."
    config_path: str | None = None
    output: str | None = None
    dry_run: bool = False
    llm_inference_test: bool = False

    scan: ScanConfig = field(default_factory=ScanConfig)
    files: FilesConfig = field(default_factory=FilesConfig)
    chunking: ChunkingConfig = field(default_factory=ChunkingConfig)
    project: ProjectConfig = field(default_factory=ProjectConfig)
    prompt: PromptConfig = field(default_factory=PromptConfig)
    inference: InferenceConfig = field(default_factory=InferenceConfig)
    multipass: MultiPassConfig = field(default_factory=MultiPassConfig)
    output_cfg: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnllm-scan", description="Local LLM vulnerability scanner")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--config", dest="config_path")
    p.add_argument("--dry-run", action="store_true", help="Print matched files and exit")
    p.add_argument(
        "--llm-inference-test",
        action="store_true",
        default=None,
        help="Run one LLM inference benchmark prompt and exit (ignores scan path)",
    )

    p.add_argument("--output", help="Comma-separated: json,csv,md")
    p.add_argument("--out-dir")
    p.add_argument("--out-prefix")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--include-reasoning", action="store_true", default=None)
    p.add_argument("--no-include-reasoning", action="store_true")
    p.add_argument("--max-findings", type=int)

    p.add_argument("--mode", choices=["max-recall", "balanced", "deterministic"])
    p.add_argument("--lang")
    p.add_argument("--include", action="append")
    p.add_argument("--exclude", action="append")
    p.add_argument("--follow-symlinks", action="store_true")
    p.add_argument("--max-file-bytes", type=int)

    p.add_argument("--context", type=int)
    p.add_argument("--chunk-strategy", choices=["function", "sliding", "file"])
    p.add_argument("--chunk-tokens", type=int)
    p.add_argument("--chunk-overlap", type=int)
    p.add_argument("--project-index", choices=["off", "basic"])

    p.add_argument("--multi-pass", action="store_true")
    p.add_argument("--pass1-budget", choices=["fast", "normal"])
    p.add_argument("--pass2-target", choices=["flagged", "topk"])
    p.add_argument("--pass2-topk", type=int)

    p.add_argument("--focus", action="append")
    p.add_argument("--prompt-file")
    p.add_argument("--profile", choices=["embedded-c"])

    p.add_argument("--model")
    p.add_argument("--quant")
    p.add_argument("--threads", type=int)
    p.add_argument("--batch", type=int)
    p.add_argument("--temp", type=float)
    p.add_argument("--top-p", type=float)
    p.add_argument("--seed", type=int)
    p.add_argument("--metal", action="store_true")
    p.add_argument("--gpu-layers", type=int)
    p.add_argument("--max-tokens", type=int)

    p.add_argument("--progress", action="store_true", default=None)
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--log-file")
    p.add_argument("--log-prompts", action="store_true")
    p.add_argument("--log-model-outputs", action="store_true")
    p.add_argument("--prompt-output-md")

    return p


def _deep_update(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_update(dst[k], v)
        else:
            dst[k] = v
    return dst


def _discover_config_path() -> Path | None:
    candidates = [
        Path("./vulnllm.toml"),
        Path("./.vulnllm.toml"),
        Path.home() / ".config" / "vulnllm" / "config.toml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _load_toml(path: Path | None) -> dict[str, Any]:
    if not path:
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def _parse_env_value(raw: str) -> Any:
    low = raw.lower()
    if low in {"true", "false"}:
        return low == "true"
    try:
        if "." in raw:
            return float(raw)
        return int(raw)
    except ValueError:
        if "," in raw:
            return [x.strip() for x in raw.split(",") if x.strip()]
        return raw


def _load_env_overrides() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in os.environ.items():
        if not k.startswith("VULNLLM_"):
            continue
        key = k[len("VULNLLM_") :].lower()
        parts = key.split("__")
        cur = out
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = _parse_env_value(v)
    return out


def _apply_cli_overrides(data: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    cli: dict[str, Any] = {
        "path": args.path,
        "config_path": args.config_path,
        "dry_run": args.dry_run,
    }

    def sec(section: str) -> dict[str, Any]:
        return cli.setdefault(section, {})

    if args.output is not None:
        sec("output")["formats"] = [x.strip() for x in args.output.split(",") if x.strip()]
    if args.out_dir is not None:
        sec("output")["out_dir"] = args.out_dir
    if args.out_prefix is not None:
        sec("output")["out_prefix"] = args.out_prefix
    if args.overwrite:
        sec("output")["overwrite"] = True
    if args.include_reasoning is True:
        sec("output")["include_reasoning"] = True
    if args.no_include_reasoning:
        sec("output")["include_reasoning"] = False

    mapping = {
        ("scan", "mode"): args.mode,
        ("scan", "max_findings"): args.max_findings,
        ("files", "include"): args.include,
        ("files", "exclude"): args.exclude,
        ("files", "max_file_bytes"): args.max_file_bytes,
        ("chunking", "strategy"): args.chunk_strategy,
        ("chunking", "chunk_tokens"): args.chunk_tokens,
        ("chunking", "overlap"): args.chunk_overlap,
        ("project", "index"): args.project_index,
        ("prompt", "focus"): args.focus,
        ("prompt", "prompt_file"): args.prompt_file,
        ("prompt", "profile"): args.profile,
        ("inference", "model"): args.model,
        ("inference", "quant"): args.quant,
        ("inference", "context"): args.context,
        ("inference", "threads"): args.threads,
        ("inference", "batch"): args.batch,
        ("inference", "temperature"): args.temp,
        ("inference", "top_p"): args.top_p,
        ("inference", "seed"): args.seed,
        ("inference", "gpu_layers"): args.gpu_layers,
        ("inference", "max_tokens"): args.max_tokens,
        ("multipass", "pass1_budget"): args.pass1_budget,
        ("multipass", "pass2_target"): args.pass2_target,
        ("multipass", "pass2_topk"): args.pass2_topk,
        ("logging", "log_file"): args.log_file,
        ("logging", "prompt_output_md"): args.prompt_output_md,
    }
    for (s, k), v in mapping.items():
        if v is not None:
            sec(s)[k] = v

    if args.lang is not None:
        sec("scan")["languages"] = [x.strip() for x in args.lang.split(",") if x.strip()]
    if args.follow_symlinks:
        sec("files")["follow_symlinks"] = True
    if args.multi_pass:
        sec("scan")["multi_pass"] = True
    if args.llm_inference_test is True:
        cli["llm_inference_test"] = True
    if args.metal:
        sec("inference")["metal"] = True
    if args.progress is True:
        sec("logging")["progress"] = True
    if args.quiet:
        sec("logging")["quiet"] = True
    if args.verbose:
        sec("logging")["verbose"] = True
    if args.log_prompts:
        sec("logging")["log_prompts"] = True
    if args.log_model_outputs:
        sec("logging")["log_model_outputs"] = True

    _deep_update(data, cli)
    return data


def _from_dict(d: dict[str, Any]) -> Config:
    return Config(
        path=d.get("path", "."),
        config_path=d.get("config_path"),
        dry_run=d.get("dry_run", False),
        llm_inference_test=d.get("llm_inference_test", False),
        scan=ScanConfig(**d.get("scan", {})),
        files=FilesConfig(**d.get("files", {})),
        chunking=ChunkingConfig(**d.get("chunking", {})),
        project=ProjectConfig(**d.get("project", {})),
        prompt=PromptConfig(**d.get("prompt", {})),
        inference=InferenceConfig(**d.get("inference", {})),
        multipass=MultiPassConfig(**d.get("multipass", {})),
        output_cfg=OutputConfig(**d.get("output", {})),
        logging=LoggingConfig(**d.get("logging", {})),
    )


def resolve_config(args: argparse.Namespace) -> Config:
    data: dict[str, Any] = {}

    config_path = Path(args.config_path) if args.config_path else _discover_config_path()
    if config_path:
        _deep_update(data, _load_toml(config_path))
        data["config_path"] = str(config_path)

    _deep_update(data, _load_env_overrides())
    _apply_cli_overrides(data, args)

    cfg = _from_dict(data)

    if cfg.scan.mode == "deterministic":
        cfg.inference.temperature = 0.0
        if cfg.inference.top_p <= 0:
            cfg.inference.top_p = 1.0

    if cfg.scan.max_findings and cfg.scan.max_findings < 0:
        raise ValueError("scan.max_findings must be >= 0")
    if not cfg.inference.model and not cfg.dry_run:
        raise ValueError("Missing required config: inference.model (set --model or TOML [inference].model)")
    if cfg.scan.mode not in {"max-recall", "balanced", "deterministic"}:
        raise ValueError("scan.mode must be max-recall|balanced|deterministic")

    for fmt in cfg.output_cfg.formats:
        if fmt == "markdown":
            continue
        if fmt not in {"json", "csv", "md"}:
            raise ValueError(f"Unsupported output format: {fmt}")
    cfg.output_cfg.formats = ["md" if f == "markdown" else f for f in cfg.output_cfg.formats]

    return cfg

from __future__ import annotations

import os
from pathlib import Path

import pytest

from vulnllm.config import build_parser, resolve_config


def test_config_cli_overrides_toml(tmp_path: Path):
    cfg_file = tmp_path / "vulnllm.toml"
    cfg_file.write_text(
        """
[scan]
mode = "balanced"

[inference]
model = "./from_toml.gguf"

[output]
formats = ["json"]
""".strip()
    )
    parser = build_parser()
    args = parser.parse_args([".", "--config", str(cfg_file), "--mode", "deterministic", "--model", "./from_cli.gguf"])
    cfg = resolve_config(args)

    assert cfg.scan.mode == "deterministic"
    assert cfg.inference.model == "./from_cli.gguf"
    assert cfg.inference.temperature == 0.0


def test_config_env_overrides_toml(tmp_path: Path, monkeypatch):
    cfg_file = tmp_path / "vulnllm.toml"
    cfg_file.write_text(
        """
[inference]
model = "./from_toml.gguf"
""".strip()
    )
    monkeypatch.setenv("VULNLLM_INFERENCE__MODEL", "./from_env.gguf")
    parser = build_parser()
    args = parser.parse_args([".", "--config", str(cfg_file)])
    cfg = resolve_config(args)

    assert cfg.inference.model == "./from_env.gguf"


def test_config_default_gpu_layers_is_cpu_safe():
    parser = build_parser()
    args = parser.parse_args([".", "--model", "./model.gguf"])
    cfg = resolve_config(args)
    assert cfg.inference.gpu_layers == 0


def test_config_context_max_from_cli():
    parser = build_parser()
    args = parser.parse_args([".", "--model", "./model.gguf", "--context", "4096", "--context-max", "16384"])
    cfg = resolve_config(args)
    assert cfg.inference.context == 4096
    assert cfg.inference.context_max == 16384


def test_config_rejects_context_max_smaller_than_context():
    parser = build_parser()
    args = parser.parse_args([".", "--model", "./model.gguf", "--context", "8192", "--context-max", "4096"])
    with pytest.raises(ValueError, match="inference.context_max must be >= inference.context"):
        resolve_config(args)


def test_config_function_filter_from_cli():
    parser = build_parser()
    args = parser.parse_args([".", "--model", "./model.gguf", "--function", "secp256k1_fe_mul_inner"])
    cfg = resolve_config(args)
    assert cfg.scan.function == "secp256k1_fe_mul_inner"


def test_config_prompt_output_logging_defaults_off_and_cli_enables():
    parser = build_parser()
    args_default = parser.parse_args([".", "--model", "./model.gguf"])
    cfg_default = resolve_config(args_default)
    assert cfg_default.logging.log_prompts is False
    assert cfg_default.logging.log_model_outputs is False

    args = parser.parse_args(
        [
            ".",
            "--model",
            "./model.gguf",
            "--log-prompts",
            "--log-model-outputs",
        ]
    )
    cfg = resolve_config(args)
    assert cfg.logging.log_prompts is True
    assert cfg.logging.log_model_outputs is True


def test_config_dry_run_does_not_require_model():
    parser = build_parser()
    args = parser.parse_args([".", "--dry-run"])
    cfg = resolve_config(args)
    assert cfg.dry_run is True


def test_config_llm_inference_test_flag():
    parser = build_parser()
    args = parser.parse_args([".", "--model", "./model.gguf", "--llm-inference-test"])
    cfg = resolve_config(args)
    assert cfg.llm_inference_test is True


def test_config_inference_retries_default_and_cli_override():
    parser = build_parser()

    args_default = parser.parse_args([".", "--model", "./model.gguf"])
    cfg_default = resolve_config(args_default)
    assert cfg_default.inference.retries == 3

    args = parser.parse_args([".", "--model", "./model.gguf", "--retries", "5"])
    cfg = resolve_config(args)
    assert cfg.inference.retries == 5


def test_config_rejects_negative_inference_retries():
    parser = build_parser()
    args = parser.parse_args([".", "--model", "./model.gguf", "--retries", "-1"])
    with pytest.raises(ValueError, match="inference.retries must be >= 0"):
        resolve_config(args)

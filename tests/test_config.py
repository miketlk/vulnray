from __future__ import annotations

import os
from pathlib import Path

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

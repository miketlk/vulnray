from __future__ import annotations

from dataclasses import dataclass

from vulnllm.config import Config


@dataclass
class GenerationParams:
    temperature: float
    top_p: float
    seed: int
    max_tokens: int


def mode_params(cfg: Config, deep: bool = False) -> GenerationParams:
    if cfg.scan.mode == "deterministic":
        return GenerationParams(temperature=0.0, top_p=1.0, seed=cfg.inference.seed, max_tokens=cfg.inference.max_tokens)
    if cfg.scan.mode == "max-recall":
        max_tokens = max(cfg.inference.max_tokens, 2000 if deep else 1400)
        return GenerationParams(temperature=max(cfg.inference.temperature, 0.2), top_p=cfg.inference.top_p, seed=cfg.inference.seed, max_tokens=max_tokens)
    return GenerationParams(temperature=cfg.inference.temperature, top_p=cfg.inference.top_p, seed=cfg.inference.seed, max_tokens=cfg.inference.max_tokens)

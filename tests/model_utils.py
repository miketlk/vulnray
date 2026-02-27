from __future__ import annotations

from pathlib import Path

import pytest

from vulnllm.utils.model_paths import discover_models


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def local_model_path() -> str:
    models = discover_models(repo_root() / "models")
    if not models:
        pytest.skip("No GGUF model found in models/")
    return str(models[0])

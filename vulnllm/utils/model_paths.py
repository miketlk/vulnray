from __future__ import annotations

from pathlib import Path


def discover_models(models_dir: str | Path = "models") -> list[Path]:
    root = Path(models_dir)
    if not root.exists() or not root.is_dir():
        return []

    models: list[Path] = []
    for p in sorted(root.iterdir()):
        if not (p.is_file() or p.is_symlink()):
            continue
        if not p.exists():
            continue
        resolved = p.resolve()
        if p.suffix.lower() == ".gguf" or resolved.suffix.lower() == ".gguf":
            models.append(p)
    return models


def resolve_model_path(model_path: str | None) -> str:
    if not model_path:
        raise ValueError("model_path is required")

    raw = Path(model_path).expanduser()
    candidates = [raw, Path.cwd() / raw, Path.cwd() / "models" / raw]

    for cand in candidates:
        if cand.exists() and (cand.is_file() or cand.is_symlink()):
            return str(cand.resolve())

    raise FileNotFoundError(f"Model path does not exist: {model_path}")

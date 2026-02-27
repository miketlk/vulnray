from __future__ import annotations

from pathlib import Path

from vulnllm.utils.model_paths import discover_models, resolve_model_path


def test_discover_models_supports_files_and_symlinks(tmp_path: Path):
    models_dir = tmp_path / "models"
    models_dir.mkdir()

    real_model = models_dir / "real.gguf"
    real_model.write_bytes(b"GGUF")

    linked_target = tmp_path / "target.gguf"
    linked_target.write_bytes(b"GGUF")
    symlink_model = models_dir / "linked.gguf"
    symlink_model.symlink_to(linked_target)

    discovered = discover_models(models_dir)
    names = [p.name for p in discovered]

    assert "real.gguf" in names
    assert "linked.gguf" in names


def test_resolve_model_path_resolves_symlink(tmp_path: Path):
    target = tmp_path / "model.gguf"
    target.write_bytes(b"GGUF")
    link = tmp_path / "alias.gguf"
    link.symlink_to(target)

    resolved = resolve_model_path(str(link))
    assert Path(resolved) == target.resolve()

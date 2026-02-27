from __future__ import annotations

from pathlib import Path, PurePosixPath

from vulnllm.config import FilesConfig, ScanConfig
from vulnllm.scanner.language_filter import allowed_extensions
from vulnllm.scanner.size_filter import within_size_limit


def _match_any(path: str, patterns: list[str]) -> bool:
    p = PurePosixPath(path)
    for pattern in patterns:
        if p.match(pattern):
            return True
        # Treat "**/" as zero-or-more directories for common glob expectations.
        if "**/" in pattern and p.match(pattern.replace("**/", "")):
            return True
    return False


def discover_files(root: str, scan_cfg: ScanConfig, files_cfg: FilesConfig) -> list[Path]:
    base = Path(root)
    if base.is_file():
        candidates = [base]
    else:
        iterator = base.rglob("*") if files_cfg.follow_symlinks else base.glob("**/*")
        candidates = [p for p in iterator if p.is_file()]

    exts = allowed_extensions(scan_cfg.languages)
    filtered: list[Path] = []

    for p in sorted(candidates):
        rel = str(p.relative_to(base if base.is_dir() else base.parent))
        rel_posix = rel.replace("\\", "/")
        if exts and p.suffix.lower() not in exts:
            continue
        if files_cfg.exclude and _match_any(rel_posix, files_cfg.exclude):
            continue
        if files_cfg.include and not _match_any(rel_posix, files_cfg.include):
            continue
        if not within_size_limit(p, files_cfg.max_file_bytes):
            continue
        filtered.append(p)

    return filtered

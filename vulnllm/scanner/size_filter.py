from __future__ import annotations

from pathlib import Path


def within_size_limit(path: Path, max_file_bytes: int) -> bool:
    return path.stat().st_size <= max_file_bytes

from __future__ import annotations

from pathlib import Path

from vulnllm.config import FilesConfig, ScanConfig
from vulnllm.scanner.file_scanner import discover_files


def test_discover_files_filters(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int main(){return 0;}\n", encoding="utf-8")
    (tmp_path / "src" / "a.h").write_text("#pragma once\n", encoding="utf-8")
    (tmp_path / "src" / "b.txt").write_text("x\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "v.c").write_text("int x;\n", encoding="utf-8")

    scan = ScanConfig(languages=["c"])
    files = FilesConfig(include=["src/**/*.c"], exclude=["vendor/**"], max_file_bytes=1024)
    found = discover_files(str(tmp_path), scan, files)
    names = [str(p.relative_to(tmp_path)).replace("\\", "/") for p in found]

    assert names == ["src/a.c"]

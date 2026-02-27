from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from vulnllm.indexing.symbol_table import SymbolTable, extract_functions

INCLUDE_RE = re.compile(r'^\s*#\s*include\s+["<]([^">]+)[">]')


@dataclass
class FileIndex:
    includes: list[str] = field(default_factory=list)
    functions: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class ProjectIndex:
    by_file: dict[str, FileIndex] = field(default_factory=dict)
    symbols: SymbolTable = field(default_factory=SymbolTable)

    def query_symbol(self, name: str) -> list[tuple[str, int]]:
        return self.symbols.lookup(name)


def build_project_index(files: list[Path], root: Path) -> ProjectIndex:
    idx = ProjectIndex()
    for path in files:
        rel = str(path.relative_to(root if root.is_dir() else root.parent))
        text = path.read_text(encoding="utf-8", errors="ignore")
        includes = [m.group(1) for m in INCLUDE_RE.finditer(text)]
        funcs = extract_functions(path)
        idx.by_file[rel] = FileIndex(includes=includes, functions=funcs)
        for name, line in funcs:
            idx.symbols.add(name, rel, line)
    return idx

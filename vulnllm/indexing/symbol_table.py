from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

FUNC_DEF_RE = re.compile(
    r"^\s*(?:[A-Za-z_][\w\s\*]*?)\s+([A-Za-z_][\w]*)\s*\(([^;]*)\)\s*\{\s*$"
)


@dataclass
class SymbolTable:
    functions: dict[str, list[tuple[str, int]]] = field(default_factory=dict)

    def add(self, name: str, file_path: str, line: int) -> None:
        self.functions.setdefault(name, []).append((file_path, line))

    def lookup(self, name: str) -> list[tuple[str, int]]:
        return self.functions.get(name, [])


def extract_functions(path: Path) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return out
    for idx, line in enumerate(lines, start=1):
        m = FUNC_DEF_RE.match(line)
        if m:
            out.append((m.group(1), idx))
    return out

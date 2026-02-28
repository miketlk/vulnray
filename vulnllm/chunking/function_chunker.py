from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

FUNC_DEF_RE = re.compile(
    r"^\s*(?:[A-Za-z_][\w\s\*]*?)\s+([A-Za-z_][\w]*)\s*\(([^;{}]*)\)\s*\{"
)


@dataclass
class CodeChunk:
    file: str
    start_line: int
    end_line: int
    text: str
    function: str | None = None



def chunk_file_by_function(path: Path, root: Path) -> list[CodeChunk]:
    rel = str(path.relative_to(root if root.is_dir() else root.parent))
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    chunks: list[CodeChunk] = []
    i = 0
    while i < len(lines):
        m = FUNC_DEF_RE.match(lines[i])
        if not m:
            i += 1
            continue

        func_name = m.group(1)
        start = i + 1
        brace_depth = lines[i].count("{") - lines[i].count("}")
        if brace_depth <= 0:
            end = i + 1
            j = i
        else:
            j = i + 1
            while j < len(lines):
                brace_depth += lines[j].count("{") - lines[j].count("}")
                if brace_depth <= 0:
                    break
                j += 1
            end = min(j + 1, len(lines))
        text = "\n".join(lines[start - 1 : end])
        chunks.append(
            CodeChunk(
                file=rel,
                start_line=start,
                end_line=end,
                text=text,
                function=func_name,
            )
        )
        i = j + 1

    return chunks

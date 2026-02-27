from __future__ import annotations

from pathlib import Path

from vulnllm.chunking.function_chunker import CodeChunk


def _approx_token_len(line: str) -> int:
    return max(1, len(line) // 4)


def chunk_file_sliding(path: Path, root: Path, chunk_tokens: int, overlap: int) -> list[CodeChunk]:
    rel = str(path.relative_to(root if root.is_dir() else root.parent))
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    chunks: list[CodeChunk] = []
    n = len(lines)
    i = 0
    while i < n:
        tok = 0
        j = i
        while j < n and tok < chunk_tokens:
            tok += _approx_token_len(lines[j])
            j += 1
        if j <= i:
            j = i + 1
        chunks.append(
            CodeChunk(
                file=rel,
                start_line=i + 1,
                end_line=j,
                text="\n".join(lines[i:j]),
                function=None,
            )
        )
        if j >= n:
            break

        back_tok = 0
        k = j
        while k > i and back_tok < overlap:
            k -= 1
            back_tok += _approx_token_len(lines[k])
        i = max(i + 1, k)
    return chunks

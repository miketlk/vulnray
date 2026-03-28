from __future__ import annotations

from pathlib import Path

from vulnllm.chunking.function_chunker import CodeChunk, chunk_file_by_function
from vulnllm.preprocessing.c_family import ast_parse_c_family, build_facts_lines

C_FAMILY_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}


def supports_ast_chunking(path: Path) -> bool:
    return path.suffix.lower() in C_FAMILY_EXTENSIONS


def chunk_file_by_ast(path: Path, root: Path) -> list[CodeChunk]:
    chunks = chunk_file_by_function(path, root)
    if not chunks:
        return chunks

    if not supports_ast_chunking(path):
        return chunks

    enriched: list[CodeChunk] = []
    for chunk in chunks:
        parsed = ast_parse_c_family(chunk.text)
        fact_lines = tuple(build_facts_lines(parsed.facts))
        enriched.append(
            CodeChunk(
                file=chunk.file,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                text=chunk.text,
                function=chunk.function,
                preprocessing_facts=fact_lines,
            )
        )
    return enriched

from __future__ import annotations

from pathlib import Path

from vulnllm.chunking.ast_chunker import chunk_file_by_ast, supports_ast_chunking


def test_supports_ast_chunking_for_c_and_cpp_extensions():
    assert supports_ast_chunking(Path("a.c")) is True
    assert supports_ast_chunking(Path("a.hpp")) is True
    assert supports_ast_chunking(Path("a.py")) is False


def test_chunk_file_by_ast_enriches_chunks_with_deterministic_facts(tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text(
        "int copy_name(char *dst, const char *src, size_t len) {\n"
        "  char local[16];\n"
        "  VERIFY_CHECK(len <= 16);\n"
        "  memcpy(local, src, len);\n"
        "  return (int)local[0];\n"
        "}\n",
        encoding="utf-8",
    )
    chunks = chunk_file_by_ast(src, tmp_path)
    assert len(chunks) == 1
    assert chunks[0].function == "copy_name"
    assert any("fixed-size write" in line for line in chunks[0].preprocessing_facts)

from __future__ import annotations

from pathlib import Path

from vulnllm.chunking.function_chunker import chunk_file_by_function


def test_function_chunking(tmp_path: Path):
    c = tmp_path / "t.c"
    c.write_text(
        """
int add(int a, int b) {
  return a + b;
}

void test() {
  int x = add(1, 2);
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    chunks = chunk_file_by_function(c, tmp_path)
    assert len(chunks) == 2
    assert chunks[0].function == "add"
    assert chunks[1].function == "test"


def test_function_chunking_skips_declaration_only_headers(tmp_path: Path):
    h = tmp_path / "decls.h"
    h.write_text(
        """
static int secp256k1_ecmult_const_xonly(
    secp256k1_fe *r,
    const secp256k1_fe *n,
    const secp256k1_fe *d,
    const secp256k1_scalar *q,
    int known_on_curve
);
""".strip()
        + "\n",
        encoding="utf-8",
    )
    chunks = chunk_file_by_function(h, tmp_path)
    assert chunks == []


def test_function_chunking_keeps_header_inline_function_bodies(tmp_path: Path):
    h = tmp_path / "inline_impl.h"
    h.write_text(
        """
static int add(int a, int b) {
  return a + b;
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    chunks = chunk_file_by_function(h, tmp_path)
    assert len(chunks) == 1
    assert chunks[0].function == "add"


def test_function_chunking_keeps_single_line_function_body(tmp_path: Path):
    c = tmp_path / "single_line.c"
    c.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    chunks = chunk_file_by_function(c, tmp_path)
    assert len(chunks) == 1
    assert chunks[0].function == "add"

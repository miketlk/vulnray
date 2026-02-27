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

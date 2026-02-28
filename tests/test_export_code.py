from __future__ import annotations

from pathlib import Path

from vulnllm.export_code import build_export_records, render_codebase_container


def test_strip_comments_preserves_literals_and_collapses_blank_runs(tmp_path: Path):
    src = tmp_path / "x.c"
    src.write_text(
        'const char *a = "http://example.com";\n'
        "const char *b = \"/*not a comment*/\";\n"
        "char c = '/';\n"
        "/* block\n"
        "comment */\n"
        "// line comment\n"
        "int x = 1;\n",
        encoding="utf-8",
    )

    rec = build_export_records(tmp_path, [src])[0]
    assert "http://example.com" in rec.content
    assert "/*not a comment*/" in rec.content
    assert "line comment" not in rec.content
    assert "comment */" not in rec.content
    assert "\n\n\n" not in rec.content
    assert "\n\nint x = 1;\n" in rec.content


def test_blank_line_runs_from_source_are_collapsed(tmp_path: Path):
    src = tmp_path / "y.c"
    src.write_text("int a = 1;\n\n\n\nint b = 2;\n", encoding="utf-8")

    rec = build_export_records(tmp_path, [src])[0]
    assert rec.content == "int a = 1;\n\nint b = 2;\n"


def test_render_container_bytes_match_unstuffed_content(tmp_path: Path):
    src = tmp_path / "src" / "a.c"
    src.parent.mkdir()
    src.write_text("int main(void) {\n  return 0;\n}\n", encoding="utf-8")
    rec = build_export_records(tmp_path, [src])[0]
    payload = render_codebase_container([rec])

    assert f"BYTES: {rec.byte_len}" in payload

    lines = payload.splitlines()
    begin = lines.index("CONTENT_BEGIN") + 1
    end = lines.index("CONTENT_END")
    unstuffed = "\n".join(line[2:] for line in lines[begin:end] if line.startswith("> "))
    assert len(unstuffed.encode("utf-8")) == rec.byte_len

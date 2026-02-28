from __future__ import annotations

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.prompt.base_prompt import build_prompt


def test_build_prompt_strips_c_comments_from_target_code():
    cfg = Config(path=".")
    chunk = CodeChunk(
        file="main.c",
        start_line=1,
        end_line=10,
        function="foo",
        text=(
            "int foo(void) {\n"
            "    // line comment should be removed\n"
            "    int x = 1; /* block comment should be removed */\n"
            "    return x;\n"
            "}\n"
        ),
    )

    prompt = build_prompt(cfg, chunk, index_context="")

    assert "line comment should be removed" not in prompt
    assert "block comment should be removed" not in prompt
    assert "int x = 1;" in prompt
    assert "return x;" in prompt


def test_build_prompt_removes_specific_line_and_block_comments():
    cfg = Config(path=".")
    chunk = CodeChunk(
        file="main.c",
        start_line=1,
        end_line=12,
        function="sanitize_me",
        text=(
            "int sanitize_me(int a) {\n"
            "    int b = a + 1; // remove this trailing comment\n"
            "    /* remove this full block comment */\n"
            "    int c = b * 2;\n"
            "    return c;\n"
            "}\n"
        ),
    )

    prompt = build_prompt(cfg, chunk, index_context="")

    assert "// target function\nint sanitize_me(int a) {" in prompt
    assert "    int b = a + 1; " in prompt
    assert "    int c = b * 2;" in prompt
    assert "    return c;" in prompt
    assert "remove this trailing comment" not in prompt
    assert "remove this full block comment" not in prompt


def test_build_prompt_keeps_comment_like_tokens_inside_literals():
    cfg = Config(path=".")
    chunk = CodeChunk(
        file="main.c",
        start_line=1,
        end_line=10,
        function="foo",
        text=(
            "int foo(void) {\n"
            '    const char *url = "https://example.com/a/*b*/c";\n'
            "    char slash = '/';\n"
            "    char quote = '\\'';\n"
            "    return (int)url[0] + (int)slash + (int)quote;\n"
            "}\n"
        ),
    )

    prompt = build_prompt(cfg, chunk, index_context="")

    assert 'https://example.com/a/*b*/c' in prompt
    assert "char slash = '/';" in prompt
    assert "char quote = '\\'';" in prompt


def test_build_prompt_collapses_sequential_blank_lines_after_comment_strip():
    cfg = Config(path=".")
    chunk = CodeChunk(
        file="main.c",
        start_line=1,
        end_line=12,
        function="foo",
        text=(
            "int foo(void) {\n"
            "    int x = 1;\n"
            "    // comment-only line\n"
            "    /* block comment line */\n"
            "    int y = x + 1;\n"
            "    return y;\n"
            "}\n"
        ),
    )

    prompt = build_prompt(cfg, chunk, index_context="")

    assert "int x = 1;\n\n\n    int y = x + 1;" not in prompt
    assert "int x = 1;\n\n    int y = x + 1;" in prompt

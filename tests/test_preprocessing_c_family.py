from __future__ import annotations

from vulnllm.preprocessing import (
    DeterministicFacts,
    PreprocessResult,
    ast_parse_c_family,
    build_facts_lines,
    parser_backends,
    sanitize_source_text,
)


def test_preprocessing_public_api_exports():
    facts = DeterministicFacts()
    result = PreprocessResult(backend="regex", facts=facts)
    assert result.backend == "regex"
    assert facts.fixed_size_writes == ()


def test_parser_backends_returns_ordered_tuple(monkeypatch):
    monkeypatch.setattr("vulnllm.preprocessing.c_family._discover_support", lambda: type("S", (), {"ordered_backends": ("tree-sitter", "regex")})())
    assert parser_backends() == ("tree-sitter", "regex")


def test_ast_parse_c_family_extracts_deterministic_facts():
    source = (
        "int copy_name(char *dst, const char *src, size_t len) {\n"
        "  char local[16];\n"
        "  VERIFY_CHECK(len <= 16);\n"
        "  memcpy(local, src, len);\n"
        "  return (int)local[0];\n"
        "}\n"
    )
    parsed = ast_parse_c_family(source, preferred_backend="regex")
    lines = build_facts_lines(parsed.facts)

    assert parsed.backend == "regex"
    assert parsed.function_name == "copy_name"
    assert any("fixed-size write" in line for line in lines)
    assert any("array extent: local[16]" in line for line in lines)
    assert any("integer type" in line for line in lines)
    assert any("assertion-proven range" in line for line in lines)


def test_ast_parse_c_family_detects_unbounded_fixed_buffer_sinks():
    source = (
        "int write_user_file(const char *relative_path) {\n"
        "  char path[64];\n"
        "  sprintf(path, \"%s\", relative_path);\n"
        "  strcpy(path, relative_path);\n"
        "  return 0;\n"
        "}\n"
    )
    parsed = ast_parse_c_family(source, preferred_backend="regex")
    lines = build_facts_lines(parsed.facts)
    assert any("sprintf to path without explicit bound" in line for line in lines)
    assert any("strcpy to path without explicit bound" in line for line in lines)


def test_ast_parse_c_family_extracts_struct_sink_and_branch_facts():
    source = (
        "typedef struct {\n"
        "  unsigned char data[65];\n"
        "} recoverable_sig;\n"
        "int fill(recoverable_sig *sig, const unsigned char *src, int offset, int len) {\n"
        "  unsigned char keydata[112];\n"
        "  if (len < 64 - offset) {\n"
        "    memcpy(keydata + offset, src, len);\n"
        "    memcpy(sig->data + offset, src, len);\n"
        "  }\n"
        "  return 0;\n"
        "}\n"
    )
    parsed = ast_parse_c_family(source, preferred_backend="regex")
    lines = build_facts_lines(parsed.facts)

    assert any("struct field extent: recoverable_sig.data[65]" in line for line in lines)
    assert any("sink extent: memcpy destination=keydata+offset, destination_extent=112, maximum_cumulative_write=offset + len" in line for line in lines)
    assert any("branch contradiction: branch condition constrains sink-related range: len < 64 - offset" in line for line in lines)


def test_ast_parse_c_family_fallbacks_when_requested_backend_unavailable(monkeypatch):
    monkeypatch.setattr(
        "vulnllm.preprocessing.c_family._discover_support",
        lambda: type("S", (), {"tree_sitter": False, "clang": False, "pycparser": False, "ordered_backends": ("regex",)})(),
    )
    parsed = ast_parse_c_family("int foo(void) { return 0; }\n", preferred_backend="clang")
    assert parsed.backend == "regex"
    assert "clang unavailable" in parsed.errors


def test_sanitize_source_text_supports_comment_stripping_and_identifier_masking():
    source = (
        "int user_copy(char *dst, const char *src) {\n"
        "  // remove me\n"
        "  return dst != 0 && src != 0;\n"
        "}\n"
    )
    stripped = sanitize_source_text(source, strip_comments=True, sanitize_identifiers=False)
    sanitized = sanitize_source_text(source, strip_comments=True, sanitize_identifiers=True)

    assert "remove me" not in stripped
    assert "user_copy" not in sanitized
    assert "int id(char *id, const char *id)" in sanitized

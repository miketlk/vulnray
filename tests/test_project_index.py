from __future__ import annotations

from pathlib import Path

from vulnllm.indexing.project_index import build_project_index


def test_project_index_builds_contract_aware_context_packet(tmp_path: Path):
    hdr = tmp_path / "api.h"
    hdr.write_text("int process_user(char *buf, int len);\n", encoding="utf-8")

    src = tmp_path / "app.c"
    src.write_text(
        "#include \"api.h\"\n"
        "#define LIMIT 64\n\n"
        "int helper(int x) { return x + 1; }\n\n"
        "int process_user(char *buf, int len) {\n"
        "    ARG_CHECK(buf != NULL);\n"
        "    char local[64];\n"
        "    if (len > LIMIT) {\n"
        "        return -1;\n"
        "    }\n"
        "    return helper(len);\n"
        "}\n\n"
        "int main(void) {\n"
        "    char in[16] = {0};\n"
        "    return process_user(in, 16);\n"
        "}\n",
        encoding="utf-8",
    )

    index = build_project_index([hdr, src], tmp_path)

    packet = index.build_context_packet("process_user", current_file="app.c")

    assert "Nearest declaration:" in packet
    assert "Caller write-budget summaries:" in packet
    assert "Relevant callees:" in packet
    assert "Nearby checks:" in packet
    assert "Deterministic facts:" in packet
    assert "- - " not in packet
    assert "Call path context" in packet
    assert "main -> process_user" in packet


def test_project_index_builds_caller_write_budget_summary(tmp_path: Path):
    src = tmp_path / "app.c"
    src.write_text(
        "int helper(char *dst, const char *src, int len) {\n"
        "    return len;\n"
        "}\n"
        "int caller(void) {\n"
        "    char keydata[112];\n"
        "    return helper(keydata, \"x\", 64);\n"
        "}\n",
        encoding="utf-8",
    )

    index = build_project_index([src], tmp_path)
    packet = index.build_context_packet("helper", current_file="app.c")

    assert "Caller write-budget summaries:" in packet
    assert "caller=caller, destination=keydata, destination_extent=112, maximum_cumulative_write=64" in packet


def test_project_index_get_function_definition_returns_code(tmp_path: Path):
    src = tmp_path / "a.c"
    src.write_text(
        "int foo(int x) {\n"
        "  return x + 1;\n"
        "}\n",
        encoding="utf-8",
    )

    index = build_project_index([src], tmp_path)
    definition = index.get_function_definition("foo")

    assert "foo (a.c:1)" in definition
    assert "return x + 1;" in definition

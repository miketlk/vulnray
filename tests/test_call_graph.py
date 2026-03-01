from __future__ import annotations

from vulnllm.indexing.call_graph import FunctionSignature, IndexedFunction, build_call_graph


def test_call_graph_builds_direct_and_indirect_edges_with_type_match():
    functions = [
        IndexedFunction(
            name="main",
            file="a.c",
            start_line=1,
            end_line=12,
            source="int main(){ caller(7); return 0; }",
            signature=FunctionSignature(name="main", param_types=()),
        ),
        IndexedFunction(
            name="caller",
            file="a.c",
            start_line=14,
            end_line=30,
            source=(
                "void caller(int n) {\n"
                "    int (*fp)(int) = 0;\n"
                "    fp = safe_add;\n"
                "    int x = fp(n);\n"
                "}\n"
            ),
            signature=FunctionSignature(name="caller", param_types=("int",)),
        ),
        IndexedFunction(
            name="safe_add",
            file="a.c",
            start_line=32,
            end_line=38,
            source="int safe_add(int n){ return n + 1; }",
            signature=FunctionSignature(name="safe_add", param_types=("int",)),
        ),
        IndexedFunction(
            name="wrong_sig",
            file="a.c",
            start_line=40,
            end_line=46,
            source="int wrong_sig(int n, int m){ return n + m; }",
            signature=FunctionSignature(name="wrong_sig", param_types=("int", "int")),
        ),
    ]

    graph = build_call_graph(functions)

    assert "caller" in graph.direct_edges["main"]
    assert "safe_add" in graph.indirect_edges["caller"]
    assert "wrong_sig" not in graph.indirect_edges["caller"]
    assert "safe_add" in graph.reachable_targets
    assert graph.sampled_paths["safe_add"][0] == ["main", "caller", "safe_add"]

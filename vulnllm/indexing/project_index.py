from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from vulnllm.chunking.function_chunker import chunk_file_by_function
from vulnllm.indexing.call_graph import CallGraph, FunctionSignature, IndexedFunction, build_call_graph, normalize_type, split_args
from vulnllm.indexing.symbol_table import SymbolTable
from vulnllm.preprocessing.c_family import ast_parse_c_family, build_facts_lines

INCLUDE_RE = re.compile(r'^\s*#\s*include\s+["<]([^">]+)[">]')
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
ASSERTION_RE = re.compile(r"\b(ARG_CHECK|VERIFY_CHECK|STATIC_ASSERT|assert)\s*\(([^)]*)\)")
ARRAY_RE = re.compile(r"\b(?:char|int|size_t|uint\d+_t|unsigned\s+char)\s+([A-Za-z_]\w*)\s*\[\s*([^\]]+)\s*\]")
RANGE_CHECK_RE = re.compile(r"\bif\s*\(([^)]*(?:len|size|count|bound|limit|max|min|index|idx)[^)]*)\)")
FUNC_DECL_RE = re.compile(r"^\s*(?:[A-Za-z_][\w\s\*]*?)\s+([A-Za-z_]\w*)\s*\((.*?)\)\s*;\s*$", re.DOTALL)


@dataclass(frozen=True)
class FunctionDefinition:
    name: str
    file: str
    start_line: int
    end_line: int
    source: str
    signature: FunctionSignature
    param_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionDeclaration:
    name: str
    file: str
    line: int
    declaration: str


@dataclass
class FileIndex:
    includes: list[str] = field(default_factory=list)
    functions: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class ProjectIndex:
    by_file: dict[str, FileIndex] = field(default_factory=dict)
    symbols: SymbolTable = field(default_factory=SymbolTable)
    declarations: dict[str, list[FunctionDeclaration]] = field(default_factory=dict)
    definitions: dict[str, list[FunctionDefinition]] = field(default_factory=dict)
    callers: dict[str, list[str]] = field(default_factory=dict)
    callees: dict[str, list[str]] = field(default_factory=dict)
    assertion_map: dict[str, list[str]] = field(default_factory=dict)
    range_facts: dict[str, list[str]] = field(default_factory=dict)
    macro_snippets: dict[str, list[str]] = field(default_factory=dict)
    deterministic_facts: dict[str, list[str]] = field(default_factory=dict)
    call_paths: dict[str, list[list[str]]] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)
    target_functions: set[str] = field(default_factory=set)

    def query_symbol(self, name: str) -> list[tuple[str, int]]:
        return self.symbols.lookup(name)

    def get_function_definition(self, name: str, *, max_lines: int = 24) -> str:
        defs = self.definitions.get(name, [])
        if not defs:
            return ""
        fn = defs[0]
        lines = fn.source.splitlines()
        snippet = "\n".join(lines[:max_lines]).strip()
        if len(lines) > max_lines:
            snippet += "\n..."
        return f"{name} ({fn.file}:{fn.start_line})\n{snippet}"

    def build_context_packet(self, function_name: str, *, current_file: str | None = None) -> str:
        packet_lines: list[str] = []

        decl = self._nearest_declaration(function_name, current_file=current_file)
        if decl is not None:
            packet_lines.append("Nearest declaration:")
            packet_lines.append(f"- {decl.file}:{decl.line} {decl.declaration}")

        callers = self.callers.get(function_name, [])[:3]
        if callers:
            packet_lines.append("Top callers:")
            for caller in callers:
                refs = self.query_symbol(caller)
                loc = f" ({refs[0][0]}:{refs[0][1]})" if refs else ""
                packet_lines.append(f"- {caller}{loc}")

        callees = self.callees.get(function_name, [])[:5]
        if callees:
            packet_lines.append("Direct callees:")
            for callee in callees:
                refs = self.query_symbol(callee)
                loc = f" ({refs[0][0]}:{refs[0][1]})" if refs else ""
                packet_lines.append(f"- {callee}{loc}")

        assertion_facts = self.assertion_map.get(function_name, [])
        if assertion_facts:
            packet_lines.append("Assertion facts:")
            for fact in assertion_facts[:6]:
                packet_lines.append(f"- {fact}")

        local_ranges = self.range_facts.get(function_name, [])
        if local_ranges:
            packet_lines.append("Local size/range facts:")
            for fact in local_ranges[:6]:
                packet_lines.append(f"- {fact}")

        deterministic = self.deterministic_facts.get(function_name, [])
        if deterministic:
            packet_lines.append("Deterministic facts:")
            for fact in deterministic[:8]:
                packet_lines.append(f"- {fact.lstrip('- ').strip()}")

        contract_summary = self._build_contract_summary(function_name)
        if contract_summary:
            packet_lines.append("Contract Summary:")
            packet_lines.extend(contract_summary)

        macro_facts = self._macro_context(function_name)
        if macro_facts:
            packet_lines.append("Macro snippets:")
            for fact in macro_facts:
                packet_lines.append(f"- {fact}")

        paths = self.call_paths.get(function_name, [])[:3]
        if paths:
            packet_lines.append("Call path context (up to 3):")
            for idx, path in enumerate(paths, start=1):
                packet_lines.append(f"- Path {idx}: {' -> '.join(path)}")
            snippets = self._path_function_snippets(function_name, paths)
            if snippets:
                packet_lines.append("Path implementation snippets:")
                packet_lines.extend(snippets)

        return "\n".join(packet_lines).strip()

    def _nearest_declaration(
        self,
        function_name: str,
        *,
        current_file: str | None,
    ) -> FunctionDeclaration | None:
        decls = self.declarations.get(function_name, [])
        if not decls:
            return None
        if current_file:
            for decl in decls:
                if decl.file == current_file:
                    return decl
        return decls[0]

    def _build_contract_summary(self, function_name: str) -> list[str]:
        out: list[str] = []
        defs = self.definitions.get(function_name, [])
        if not defs:
            return out
        fn = defs[0]
        assertions = self.assertion_map.get(function_name, [])
        ranges = self.range_facts.get(function_name, [])

        pointer_constraints: list[str] = []
        range_constraints: list[str] = []

        for param in fn.param_names:
            for assertion in assertions:
                if param in assertion and ("NULL" in assertion or "null" in assertion.lower()):
                    pointer_constraints.append(f"{param}: {assertion}")
            for fact in ranges:
                if param in fact:
                    range_constraints.append(f"{param}: {fact}")

        if pointer_constraints:
            out.append("- pointer constraints: " + "; ".join(pointer_constraints[:3]))
        elif any("*" in p for p in fn.signature.param_types):
            out.append("- pointer constraints: pointer params present; no explicit local null-check assertion found")

        size_facts = [x for x in ranges if "fixed-size" in x or "array" in x]
        if size_facts:
            out.append("- expected buffer sizes: " + "; ".join(size_facts[:3]))

        if range_constraints:
            out.append("- argument range restrictions: " + "; ".join(range_constraints[:3]))

        origin_guesses: list[str] = []
        for ptype, pname in zip(fn.signature.param_types, fn.param_names):
            origin_guesses.append(f"{pname}={_guess_origin(pname, ptype)}")
        if origin_guesses:
            out.append("- parameter origin guess: " + ", ".join(origin_guesses[:6]))
        return out

    def _path_function_snippets(self, target: str, paths: list[list[str]]) -> list[str]:
        selected: list[str] = []
        seen: set[str] = set()
        for path in paths:
            for name in path:
                if name == target or name in seen:
                    continue
                seen.add(name)
                snippet = self.get_function_definition(name, max_lines=10)
                if snippet:
                    selected.append(f"- {snippet.replace(chr(10), chr(10) + '  ')}")
                if len(selected) >= 3:
                    return selected
        return selected

    def _macro_context(self, function_name: str) -> list[str]:
        defs = self.definitions.get(function_name, [])
        if not defs:
            return []
        current_file = defs[0].file
        snippets = list(self.macro_snippets.get(current_file, []))
        file_index = self.by_file.get(current_file)
        if file_index:
            include_candidates = {inc for inc in file_index.includes if inc in self.by_file}
            for include in sorted(include_candidates):
                snippets.extend(self.macro_snippets.get(include, []))
        deduped: list[str] = []
        seen: set[str] = set()
        for snippet in snippets:
            if snippet in seen:
                continue
            seen.add(snippet)
            deduped.append(snippet)
            if len(deduped) >= 5:
                break
        return deduped


def build_project_index(files: list[Path], root: Path) -> ProjectIndex:
    idx = ProjectIndex()
    indexed_functions: list[IndexedFunction] = []

    for path in files:
        rel = str(path.relative_to(root if root.is_dir() else root.parent))
        text = path.read_text(encoding="utf-8", errors="ignore")
        includes = [m.group(1) for m in INCLUDE_RE.finditer(text)]
        chunks = chunk_file_by_function(path, root)
        idx.by_file[rel] = FileIndex(
            includes=includes,
            functions=[(c.function, c.start_line) for c in chunks if c.function],
        )

        lines = text.splitlines()
        idx.macro_snippets[rel] = _extract_macro_snippets(lines)

        for decl in _extract_function_declarations(lines, rel):
            idx.declarations.setdefault(decl.name, []).append(decl)

        for chunk in chunks:
            if not chunk.function:
                continue
            sig, param_names = _parse_signature_from_chunk(chunk.function, chunk.text)
            definition = FunctionDefinition(
                name=chunk.function,
                file=chunk.file,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                source=chunk.text,
                signature=sig,
                param_names=param_names,
            )
            idx.definitions.setdefault(chunk.function, []).append(definition)
            idx.symbols.add(chunk.function, chunk.file, chunk.start_line)

            idx.assertion_map.setdefault(chunk.function, []).extend(_extract_assertion_facts(chunk.text))
            idx.range_facts.setdefault(chunk.function, []).extend(_extract_range_facts(chunk.text))
            parsed = ast_parse_c_family(chunk.text)
            facts = [fact.lstrip("- ").strip() for fact in build_facts_lines(parsed.facts)]
            if facts:
                idx.deterministic_facts.setdefault(chunk.function, []).extend(facts)

            indexed_functions.append(
                IndexedFunction(
                    name=chunk.function,
                    file=chunk.file,
                    start_line=chunk.start_line,
                    end_line=chunk.end_line,
                    source=chunk.text,
                    signature=sig,
                )
            )

    graph = build_call_graph(indexed_functions)
    _merge_graph(idx, graph)
    return idx


def _merge_graph(idx: ProjectIndex, graph: CallGraph) -> None:
    edges = graph.all_edges
    for caller, callees in edges.items():
        idx.callees[caller] = sorted(callees)
    for callee, callers in graph.callers.items():
        idx.callers[callee] = sorted(callers)
    idx.entry_points = list(graph.entry_points)
    idx.target_functions = set(graph.reachable_targets)
    idx.call_paths = {name: [list(path) for path in paths] for name, paths in graph.sampled_paths.items()}


def _extract_macro_snippets(lines: list[str]) -> list[str]:
    snippets: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#define "):
            snippets.append(stripped[:160])
            if len(snippets) >= 20:
                break
    return snippets


def _extract_function_declarations(lines: list[str], rel: str) -> list[FunctionDeclaration]:
    out: list[FunctionDeclaration] = []
    buf: list[str] = []
    start_line = 1
    for idx, line in enumerate(lines, start=1):
        if not buf:
            start_line = idx
        buf.append(line)
        if ";" not in line:
            continue
        stmt = "\n".join(buf).strip()
        buf = []
        if "(" not in stmt or ")" not in stmt:
            continue
        if "{" in stmt or "typedef" in stmt:
            continue
        m = FUNC_DECL_RE.match(stmt)
        if not m:
            continue
        name = m.group(1)
        out.append(
            FunctionDeclaration(
                name=name,
                file=rel,
                line=start_line,
                declaration=" ".join(stmt.split()),
            )
        )
    return out


def _parse_signature_from_chunk(function_name: str, source: str) -> tuple[FunctionSignature, tuple[str, ...]]:
    header = source.split("{", 1)[0]
    params_raw = ""
    m = re.search(rf"\b{re.escape(function_name)}\s*\((.*)\)\s*$", header.strip(), re.DOTALL)
    if m:
        params_raw = m.group(1)
    param_types: list[str] = []
    param_names: list[str] = []
    for part in split_args(params_raw):
        ptype, pname = _parse_parameter(part)
        if ptype:
            param_types.append(ptype)
        if pname:
            param_names.append(pname)
    return FunctionSignature(name=function_name, param_types=tuple(param_types)), tuple(param_names)


def _parse_parameter(raw: str) -> tuple[str, str]:
    text = raw.strip()
    if not text or text == "void":
        return "", ""
    name = ""
    m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", text)
    if m:
        name = m.group(1)
        type_part = text[: m.start(1)] + text[m.end(1) :]
    else:
        type_part = text
    ptype = normalize_type(type_part.replace("[]", "*").strip())
    return ptype, name


def _extract_assertion_facts(text: str) -> list[str]:
    out: list[str] = []
    for m in ASSERTION_RE.finditer(text):
        macro = m.group(1)
        expr = " ".join(m.group(2).split())
        out.append(f"{macro}({expr})")
    return out


def _extract_range_facts(text: str) -> list[str]:
    out: list[str] = []
    for m in ARRAY_RE.finditer(text):
        out.append(f"fixed-size array {m.group(1)}[{m.group(2).strip()}]")
    for m in RANGE_CHECK_RE.finditer(text):
        cond = " ".join(m.group(1).split())
        out.append(f"range check: if ({cond})")
    return out


def _guess_origin(name: str, ptype: str) -> str:
    lowered = name.lower()
    if any(k in lowered for k in ("user", "input", "path", "argv", "data")):
        return "likely-untrusted"
    if any(k in lowered for k in ("len", "size", "count", "idx", "index")):
        return "size-or-index"
    if "*" in ptype and "const" not in ptype:
        return "mutable-pointer"
    if "const" in ptype:
        return "read-only"
    return "unknown"

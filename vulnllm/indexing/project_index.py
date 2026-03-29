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


@dataclass(frozen=True)
class TypeDefinition:
    name: str
    file: str
    start_line: int
    end_line: int
    source: str


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
    type_definitions: dict[str, list[TypeDefinition]] = field(default_factory=dict)
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

    def get_symbol_definition(self, name: str, *, max_lines: int = 24) -> str:
        function_def = self.get_function_definition(name, max_lines=max_lines)
        if function_def:
            return function_def
        defs = self.type_definitions.get(name, [])
        if not defs:
            return ""
        typedef = defs[0]
        lines = typedef.source.splitlines()
        snippet = "\n".join(lines[:max_lines]).strip()
        if len(lines) > max_lines:
            snippet += "\n..."
        return f"{name} ({typedef.file}:{typedef.start_line})\n{snippet}"

    def build_context_packet(self, function_name: str, *, current_file: str | None = None) -> str:
        packet_lines: list[str] = []
        fact_budget = 12

        decl = self._nearest_declaration(function_name, current_file=current_file)
        if decl is not None:
            packet_lines.append("Nearest declaration:")
            packet_lines.append(f"- {decl.file}:{decl.line} {decl.declaration}")
            fact_budget -= 1

        callers = self.callers.get(function_name, [])[:3]
        caller_summaries = self._caller_write_budget_summaries(function_name, callers)
        if caller_summaries and fact_budget > 0:
            packet_lines.append("Caller write-budget summaries:")
            packet_lines.extend(caller_summaries[:1])
            fact_budget -= 1

        deterministic = self._rank_deterministic_facts(self.deterministic_facts.get(function_name, []))
        if deterministic and fact_budget > 0:
            packet_lines.append("Deterministic facts:")
            for fact in deterministic[: max(0, fact_budget)]:
                packet_lines.append(f"- {fact.lstrip('- ').strip()}")
            fact_budget -= min(len(deterministic), fact_budget)

        nearby_checks = self._rank_nearby_checks(function_name)
        if nearby_checks and fact_budget > 0:
            packet_lines.append("Nearby checks:")
            for fact in nearby_checks[: max(0, fact_budget)]:
                packet_lines.append(f"- {fact}")
            fact_budget -= min(len(nearby_checks), fact_budget)

        callees = self.callees.get(function_name, [])[:2]
        if callees and fact_budget > 0:
            packet_lines.append("Relevant callees:")
            for callee in callees:
                refs = self.query_symbol(callee)
                loc = f" ({refs[0][0]}:{refs[0][1]})" if refs else ""
                packet_lines.append(f"- {callee}{loc}")
            fact_budget -= min(2, len(callees))

        paths = self.call_paths.get(function_name, [])[:3]
        if paths and fact_budget > 0:
            packet_lines.append("Call path context (up to 3):")
            packet_lines.append(f"- Path 1: {' -> '.join(paths[0])}")

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

    @staticmethod
    def _rank_deterministic_facts(facts: list[str]) -> list[str]:
        def score(line: str) -> tuple[int, str]:
            normalized = line.strip().lower()
            if normalized.startswith("struct field extent:"):
                return (0, normalized)
            if normalized.startswith("sink extent:"):
                return (1, normalized)
            if normalized.startswith("assertion-proven range:"):
                return (2, normalized)
            if normalized.startswith("branch contradiction:"):
                return (3, normalized)
            if normalized.startswith("fixed-size write:"):
                return (4, normalized)
            if normalized.startswith("array extent:"):
                return (5, normalized)
            if normalized.startswith("integer type:"):
                return (8, normalized)
            return (6, normalized)

        deduped: list[str] = []
        seen: set[str] = set()
        for fact in sorted(facts, key=score):
            if fact in seen:
                continue
            seen.add(fact)
            deduped.append(fact)
        return deduped

    def _rank_nearby_checks(self, function_name: str) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for source in (self.assertion_map.get(function_name, []), self.range_facts.get(function_name, [])):
            for fact in source:
                if fact in seen:
                    continue
                seen.add(fact)
                out.append(fact)
        return out[:3]

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

    def _caller_write_budget_summaries(self, function_name: str, callers: list[str]) -> list[str]:
        summaries: list[str] = []
        for caller in callers:
            defs = self.definitions.get(caller, [])
            if not defs:
                continue
            caller_def = defs[0]
            arrays = {name: size for name, size in ARRAY_RE.findall(caller_def.source)}
            call_re = re.compile(rf"\b{re.escape(function_name)}\s*\(([^)]*)\)")
            for match in call_re.finditer(caller_def.source):
                args = split_args(match.group(1))
                if not args:
                    continue
                destination_expr = args[0].strip()
                destination_name = destination_expr.lstrip("&").strip()
                destination_extent = self._destination_extent(destination_name, arrays, caller_def.source)
                max_write = self._max_write_from_args(args, arrays)
                if destination_extent is None or max_write is None:
                    continue
                summaries.append(
                    f"- caller={caller}, destination={destination_name}, "
                    f"destination_extent={destination_extent}, maximum_cumulative_write={max_write}"
                )
                if len(summaries) >= 6:
                    return summaries
        return summaries

    @staticmethod
    def _destination_extent(destination_name: str, arrays: dict[str, str], caller_source: str) -> int | None:
        direct = arrays.get(destination_name)
        if direct and direct.isdigit():
            return int(direct)
        sizeof_match = re.search(rf"\bsizeof\s*\(\s*{re.escape(destination_name)}\s*\)", caller_source)
        if sizeof_match and direct and direct.isdigit():
            return int(direct)
        return None

    @staticmethod
    def _max_write_from_args(args: list[str], arrays: dict[str, str]) -> int | None:
        numeric_values: list[int] = []
        for arg in args[1:]:
            token = arg.strip()
            if token.isdigit():
                numeric_values.append(int(token))
                continue
            sizeof_m = re.fullmatch(r"sizeof\s*\(\s*([A-Za-z_]\w*)\s*\)", token)
            if sizeof_m:
                ref = sizeof_m.group(1)
                size = arrays.get(ref)
                if size and size.isdigit():
                    numeric_values.append(int(size))
        if not numeric_values:
            return None
        return max(numeric_values)


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

        for typedef in _extract_type_definitions(text, rel):
            idx.type_definitions.setdefault(typedef.name, []).append(typedef)
            idx.symbols.add(typedef.name, typedef.file, typedef.start_line)

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


def _extract_type_definitions(text: str, rel: str) -> list[TypeDefinition]:
    out: list[TypeDefinition] = []
    typedef_re = re.compile(r"\btypedef\s+struct\s*(?:[A-Za-z_]\w*)?\s*\{.*?\}\s*([A-Za-z_]\w*)\s*;", re.DOTALL)
    struct_re = re.compile(r"\bstruct\s+([A-Za-z_]\w*)\s*\{.*?\}\s*;", re.DOTALL)

    for match in typedef_re.finditer(text):
        name = match.group(1)
        source = match.group(0).strip()
        start_line = text.count("\n", 0, match.start()) + 1
        end_line = start_line + source.count("\n")
        out.append(TypeDefinition(name=name, file=rel, start_line=start_line, end_line=end_line, source=source))

    for match in struct_re.finditer(text):
        name = match.group(1)
        source = match.group(0).strip()
        start_line = text.count("\n", 0, match.start()) + 1
        end_line = start_line + source.count("\n")
        out.append(TypeDefinition(name=name, file=rel, start_line=start_line, end_line=end_line, source=source))

    deduped: list[TypeDefinition] = []
    seen: set[tuple[str, int]] = set()
    for item in out:
        key = (item.name, item.start_line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped

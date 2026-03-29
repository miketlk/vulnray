from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass, field

from vulnllm.prompt.base_prompt import _strip_c_comments

FUNC_HEADER_RE = re.compile(
    r"^\s*(?:[A-Za-z_][\w\s\*\[\]]*?)\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{"
)
ARRAY_RE = re.compile(r"\b(?:char|int|size_t|uint\d+_t|unsigned\s+char)\s+([A-Za-z_]\w*)\s*\[\s*([^\]]+)\s*\]")
STRUCT_BLOCK_RE = re.compile(r"\bstruct\s+([A-Za-z_]\w*)?\s*\{([^}]*)\}\s*;", re.DOTALL)
TYPEDEF_STRUCT_BLOCK_RE = re.compile(r"\btypedef\s+struct\s*(?:[A-Za-z_]\w*)?\s*\{([^}]*)\}\s*([A-Za-z_]\w*)\s*;", re.DOTALL)
SIGNEDNESS_RE = re.compile(r"\b(?:(unsigned|signed)\s+)?(char|short|int|long|size_t|uint\d+_t|int\d+_t)\b")
ASSERTION_RE = re.compile(r"\b(ARG_CHECK|VERIFY_CHECK|STATIC_ASSERT|assert)\s*\(([^)]*)\)")
RANGE_ASSERTION_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(<=|>=|<|>|==|!=)\s*([A-Za-z_]\w*|\d+)")
FIXED_WRITE_RE = re.compile(r"\b(strncpy|memcpy|snprintf)\s*\(\s*([A-Za-z_]\w*)\s*,[^,]*,\s*([^)]+)\)")
POINTER_WRITE_RE = re.compile(
    r"\b(memcpy|memmove)\s*\(\s*([A-Za-z_]\w*)\s*\+\s*([A-Za-z_]\w*|\d+)\s*,\s*[^,]+,\s*([^)]+)\)"
)
UNBOUNDED_WRITE_RE = re.compile(r"\b(strcpy|strcat|sprintf)\s*\(\s*([A-Za-z_]\w*)\s*,")
GETS_RE = re.compile(r"\bgets\s*\(\s*([A-Za-z_]\w*)\s*\)")
RANGE_GUARD_RE = re.compile(r"\bif\s*\(([^)]*(?:<=|>=|<|>|==|!=)[^)]*)\)")


@dataclass(frozen=True)
class DeterministicFacts:
    fixed_size_writes: tuple[str, ...] = ()
    array_extents: tuple[str, ...] = ()
    integer_types: tuple[str, ...] = ()
    assertion_ranges: tuple[str, ...] = ()
    struct_field_extents: tuple[str, ...] = ()
    sink_extent_facts: tuple[str, ...] = ()
    branch_contradictions: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreprocessResult:
    backend: str
    facts: DeterministicFacts
    function_name: str | None = None
    errors: tuple[str, ...] = ()


@dataclass
class _BackendSupport:
    tree_sitter: bool = False
    clang: bool = False
    pycparser: bool = False

    @property
    def ordered_backends(self) -> tuple[str, ...]:
        out = ["regex"]
        if self.pycparser:
            out.insert(0, "pycparser")
        if self.clang:
            out.insert(0, "clang")
        if self.tree_sitter:
            out.insert(0, "tree-sitter")
        return tuple(out)


def parser_backends() -> tuple[str, ...]:
    support = _discover_support()
    return support.ordered_backends


def ast_parse_c_family(source: str, *, preferred_backend: str | None = None) -> PreprocessResult:
    sanitized = sanitize_source_text(source, strip_comments=True, sanitize_identifiers=False)
    support = _discover_support()
    requested = (preferred_backend or "").strip()

    backends = [requested] if requested else list(support.ordered_backends)
    errors: list[str] = []
    for backend in backends:
        if backend == "tree-sitter" and not support.tree_sitter:
            errors.append("tree-sitter unavailable")
            continue
        if backend == "clang" and not support.clang:
            errors.append("clang unavailable")
            continue
        if backend == "pycparser" and not support.pycparser:
            errors.append("pycparser unavailable")
            continue
        facts = _extract_facts_regex(sanitized)
        return PreprocessResult(backend=backend or "regex", facts=facts, function_name=_first_function_name(sanitized))

    return PreprocessResult(
        backend="regex",
        facts=_extract_facts_regex(sanitized),
        function_name=_first_function_name(sanitized),
        errors=tuple(errors),
    )


def build_facts_lines(facts: DeterministicFacts) -> list[str]:
    out: list[str] = []
    out.extend(f"- fixed-size write: {fact}" for fact in facts.fixed_size_writes)
    out.extend(f"- array extent: {fact}" for fact in facts.array_extents)
    out.extend(f"- integer type: {fact}" for fact in facts.integer_types)
    out.extend(f"- assertion-proven range: {fact}" for fact in facts.assertion_ranges)
    out.extend(f"- struct field extent: {fact}" for fact in facts.struct_field_extents)
    out.extend(f"- sink extent: {fact}" for fact in facts.sink_extent_facts)
    out.extend(f"- branch contradiction: {fact}" for fact in facts.branch_contradictions)
    return out


def sanitize_source_text(
    source: str,
    *,
    strip_comments: bool = True,
    sanitize_identifiers: bool = False,
) -> str:
    text = _strip_c_comments(source) if strip_comments else source
    if not sanitize_identifiers:
        return text
    # Keep keywords and primitive types readable while sanitizing project-specific names.
    return re.sub(r"\b(?!int\b|char\b|void\b|if\b|for\b|while\b|return\b|const\b)([A-Za-z_]\w*)\b", "id", text)


def _discover_support() -> _BackendSupport:
    def has_module(name: str) -> bool:
        try:
            return importlib.util.find_spec(name) is not None
        except ModuleNotFoundError:
            return False

    return _BackendSupport(
        tree_sitter=has_module("tree_sitter"),
        clang=has_module("clang.cindex"),
        pycparser=has_module("pycparser"),
    )


def _extract_facts_regex(source: str) -> DeterministicFacts:
    fixed_writes = _extract_fixed_size_writes(source)
    arrays = tuple(sorted({f"{m.group(1)}[{m.group(2).strip()}]" for m in ARRAY_RE.finditer(source)}))
    integers = _extract_integer_types(source)
    assertion_ranges = _extract_assertion_ranges(source)
    struct_field_extents = _extract_struct_field_extents(source)
    sink_extent_facts = _extract_sink_extent_facts(source)
    branch_contradictions = _extract_branch_contradictions(source)
    return DeterministicFacts(
        fixed_size_writes=fixed_writes,
        array_extents=arrays,
        integer_types=integers,
        assertion_ranges=assertion_ranges,
        struct_field_extents=struct_field_extents,
        sink_extent_facts=sink_extent_facts,
        branch_contradictions=branch_contradictions,
    )


def _extract_fixed_size_writes(source: str) -> tuple[str, ...]:
    known_arrays = {m.group(1): m.group(2).strip() for m in ARRAY_RE.finditer(source)}
    out: set[str] = set()
    for m in FIXED_WRITE_RE.finditer(source):
        sink = m.group(1)
        dst = m.group(2)
        bound_expr = " ".join(m.group(3).split())
        if dst in known_arrays:
            out.add(f"{sink} to {dst} with bound {bound_expr}, local extent={known_arrays[dst]}")
    for m in UNBOUNDED_WRITE_RE.finditer(source):
        sink = m.group(1)
        dst = m.group(2)
        if dst in known_arrays:
            out.add(f"{sink} to {dst} without explicit bound, local extent={known_arrays[dst]}")
    for m in GETS_RE.finditer(source):
        dst = m.group(1)
        if dst in known_arrays:
            out.add(f"gets to {dst} without explicit bound, local extent={known_arrays[dst]}")
    return tuple(sorted(out))


def _extract_integer_types(source: str) -> tuple[str, ...]:
    out: set[str] = set()
    for m in SIGNEDNESS_RE.finditer(source):
        signedness = m.group(1) or "signed"
        kind = m.group(2)
        out.add(f"{kind} ({signedness})")
    return tuple(sorted(out))


def _extract_assertion_ranges(source: str) -> tuple[str, ...]:
    out: set[str] = set()
    for macro, expr in ASSERTION_RE.findall(source):
        compact = " ".join(expr.split())
        for lhs, op, rhs in RANGE_ASSERTION_RE.findall(compact):
            out.add(f"{macro}: {lhs} {op} {rhs}")
    return tuple(sorted(out))


def _first_function_name(source: str) -> str | None:
    for line in source.splitlines():
        m = FUNC_HEADER_RE.match(line)
        if m:
            return m.group(1)
    return None


def _extract_struct_field_extents(source: str) -> tuple[str, ...]:
    out: set[str] = set()

    for m in STRUCT_BLOCK_RE.finditer(source):
        struct_name = m.group(1) or "anonymous_struct"
        body = m.group(2)
        for field_name, extent in ARRAY_RE.findall(body):
            out.add(f"{struct_name}.{field_name}[{extent.strip()}]")

    for m in TYPEDEF_STRUCT_BLOCK_RE.finditer(source):
        body = m.group(1)
        typedef_name = m.group(2)
        for field_name, extent in ARRAY_RE.findall(body):
            out.add(f"{typedef_name}.{field_name}[{extent.strip()}]")

    return tuple(sorted(out))


def _extract_sink_extent_facts(source: str) -> tuple[str, ...]:
    known_arrays = {m.group(1): m.group(2).strip() for m in ARRAY_RE.finditer(source)}
    out: set[str] = set()

    for sink, dst, offset, write_len in POINTER_WRITE_RE.findall(source):
        if dst not in known_arrays:
            continue
        normalized_len = " ".join(write_len.split())
        out.add(
            f"{sink} destination={dst}+{offset}, destination_extent={known_arrays[dst]}, "
            f"maximum_cumulative_write={offset} + {normalized_len}"
        )

    for sink, dst, write_len in FIXED_WRITE_RE.findall(source):
        if dst not in known_arrays:
            continue
        normalized_len = " ".join(write_len.split())
        out.add(
            f"{sink} destination={dst}, destination_extent={known_arrays[dst]}, "
            f"maximum_cumulative_write={normalized_len}"
        )

    return tuple(sorted(out))


def _extract_branch_contradictions(source: str) -> tuple[str, ...]:
    out: set[str] = set()
    for condition in RANGE_GUARD_RE.findall(source):
        compact = " ".join(condition.split())
        if any(token in compact for token in ("len", "size", "count", "bound", "limit", "offset")):
            out.add(f"branch condition constrains sink-related range: {compact}")
    return tuple(sorted(out))

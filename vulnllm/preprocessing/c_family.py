from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass, field

from vulnllm.prompt.base_prompt import _strip_c_comments

FUNC_HEADER_RE = re.compile(
    r"^\s*(?:[A-Za-z_][\w\s\*\[\]]*?)\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{"
)
ARRAY_RE = re.compile(r"\b(?:char|int|size_t|uint\d+_t|unsigned\s+char)\s+([A-Za-z_]\w*)\s*\[\s*([^\]]+)\s*\]")
SIGNEDNESS_RE = re.compile(r"\b(?:(unsigned|signed)\s+)?(char|short|int|long|size_t|uint\d+_t|int\d+_t)\b")
ASSERTION_RE = re.compile(r"\b(ARG_CHECK|VERIFY_CHECK|STATIC_ASSERT|assert)\s*\(([^)]*)\)")
RANGE_ASSERTION_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(<=|>=|<|>|==|!=)\s*([A-Za-z_]\w*|\d+)")
FIXED_WRITE_RE = re.compile(r"\b(strncpy|memcpy|snprintf)\s*\(\s*([A-Za-z_]\w*)\s*,[^,]*,\s*([^)]+)\)")
UNBOUNDED_WRITE_RE = re.compile(r"\b(strcpy|strcat|sprintf)\s*\(\s*([A-Za-z_]\w*)\s*,")
GETS_RE = re.compile(r"\bgets\s*\(\s*([A-Za-z_]\w*)\s*\)")


@dataclass(frozen=True)
class DeterministicFacts:
    fixed_size_writes: tuple[str, ...] = ()
    array_extents: tuple[str, ...] = ()
    integer_types: tuple[str, ...] = ()
    assertion_ranges: tuple[str, ...] = ()


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
    return DeterministicFacts(
        fixed_size_writes=fixed_writes,
        array_extents=arrays,
        integer_types=integers,
        assertion_ranges=assertion_ranges,
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

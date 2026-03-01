from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field

CALL_TOKEN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
INDIRECT_CALL_RE = re.compile(r"(?:\(\s*\*\s*([A-Za-z_]\w*)\s*\)|\b([A-Za-z_]\w*))\s*\(([^)]*)\)")
POINTER_DECL_RE = re.compile(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(([^)]*)\)")

KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "do",
}


@dataclass(frozen=True)
class FunctionSignature:
    name: str
    param_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class IndexedFunction:
    name: str
    file: str
    start_line: int
    end_line: int
    source: str
    signature: FunctionSignature


@dataclass
class CallGraph:
    direct_edges: dict[str, set[str]] = field(default_factory=dict)
    indirect_edges: dict[str, set[str]] = field(default_factory=dict)
    callers: dict[str, set[str]] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)
    reachable_targets: set[str] = field(default_factory=set)
    sampled_paths: dict[str, list[list[str]]] = field(default_factory=dict)

    @property
    def all_edges(self) -> dict[str, set[str]]:
        merged: dict[str, set[str]] = defaultdict(set)
        for caller, callees in self.direct_edges.items():
            merged[caller].update(callees)
        for caller, callees in self.indirect_edges.items():
            merged[caller].update(callees)
        return merged


def normalize_type(raw: str) -> str:
    text = re.sub(r"\b(const|volatile|register|static|extern|inline)\b", " ", raw)
    text = re.sub(r"\s+", " ", text).strip()
    text = text.replace(" *", "*").replace("* ", "*")
    return text


def split_args(raw: str) -> list[str]:
    s = raw.strip()
    if not s or s == "void":
        return []
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in s:
        if ch == "," and depth == 0:
            token = "".join(cur).strip()
            if token:
                parts.append(token)
            cur = []
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]" and depth > 0:
            depth -= 1
        cur.append(ch)
    token = "".join(cur).strip()
    if token:
        parts.append(token)
    return parts


def build_call_graph(functions: list[IndexedFunction]) -> CallGraph:
    known = {f.name for f in functions}
    signatures = {f.name: f.signature for f in functions}
    direct_edges: dict[str, set[str]] = defaultdict(set)
    indirect_edges: dict[str, set[str]] = defaultdict(set)

    for func in functions:
        body = func.source
        for m in CALL_TOKEN_RE.finditer(body):
            callee = m.group(1)
            if callee in KEYWORDS:
                continue
            if callee == func.name:
                continue
            if callee in known:
                direct_edges[func.name].add(callee)

        pointer_decl_types: dict[str, tuple[str, ...]] = {}
        for decl in POINTER_DECL_RE.finditer(body):
            ptr_name = decl.group(1)
            ptr_types = tuple(normalize_type(x) for x in split_args(decl.group(2)))
            pointer_decl_types[ptr_name] = ptr_types

        assigned_targets: dict[str, set[str]] = defaultdict(set)
        for ptr_name in pointer_decl_types:
            assign_re = re.compile(rf"\b{re.escape(ptr_name)}\s*=\s*&?([A-Za-z_]\w*)\s*;")
            for am in assign_re.finditer(body):
                target = am.group(1)
                if target in known:
                    assigned_targets[ptr_name].add(target)

        for cm in INDIRECT_CALL_RE.finditer(body):
            var_name = cm.group(1) or cm.group(2)
            if not var_name:
                continue
            if var_name in known:
                continue
            call_arg_count = len(split_args(cm.group(3)))
            candidates = assigned_targets.get(var_name, set())
            if not candidates:
                continue
            declared_types = pointer_decl_types.get(var_name, ())
            for target in candidates:
                sig = signatures.get(target)
                if sig is None:
                    continue
                if len(sig.param_types) != call_arg_count:
                    continue
                # Type-based candidate edge inclusion.
                if declared_types and tuple(sig.param_types) != declared_types:
                    continue
                indirect_edges[func.name].add(target)

    callers: dict[str, set[str]] = defaultdict(set)
    merged_edges: dict[str, set[str]] = defaultdict(set)
    for caller, callees in direct_edges.items():
        merged_edges[caller].update(callees)
    for caller, callees in indirect_edges.items():
        merged_edges[caller].update(callees)

    for caller, callees in merged_edges.items():
        for callee in callees:
            callers[callee].add(caller)

    entry_points = _select_entry_points(known, callers)
    reachable_targets = _reachable_from_entries(entry_points, merged_edges)
    sampled_paths = _sample_paths(entry_points, reachable_targets, merged_edges, max_paths=3, max_depth=12)

    return CallGraph(
        direct_edges={k: set(v) for k, v in direct_edges.items()},
        indirect_edges={k: set(v) for k, v in indirect_edges.items()},
        callers={k: set(v) for k, v in callers.items()},
        entry_points=entry_points,
        reachable_targets=reachable_targets,
        sampled_paths=sampled_paths,
    )


def _select_entry_points(function_names: set[str], callers: dict[str, set[str]]) -> list[str]:
    preferred = [
        name
        for name in sorted(function_names)
        if name.lower() in {"main", "llvmfuzzertestoneinput", "fuzz_entry", "harness_main"}
    ]
    if preferred:
        return preferred
    roots = [name for name in sorted(function_names) if not callers.get(name)]
    return roots or sorted(function_names)


def _reachable_from_entries(entries: list[str], edges: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    q: deque[str] = deque(entries)
    while q:
        node = q.popleft()
        if node in seen:
            continue
        seen.add(node)
        for nxt in sorted(edges.get(node, set())):
            if nxt not in seen:
                q.append(nxt)
    return seen


def _sample_paths(
    entries: list[str],
    targets: set[str],
    edges: dict[str, set[str]],
    *,
    max_paths: int,
    max_depth: int,
) -> dict[str, list[list[str]]]:
    out: dict[str, list[list[str]]] = {}
    for target in sorted(targets):
        paths: list[list[str]] = []
        for entry in entries:
            if entry == target:
                paths.append([entry])
                if len(paths) >= max_paths:
                    break
                continue
            found = _find_paths(entry, target, edges, max_depth=max_depth, limit=max_paths)
            for path in found:
                if path not in paths:
                    paths.append(path)
                if len(paths) >= max_paths:
                    break
            if len(paths) >= max_paths:
                break
        if paths:
            out[target] = paths[:max_paths]
    return out


def _find_paths(
    start: str,
    goal: str,
    edges: dict[str, set[str]],
    *,
    max_depth: int,
    limit: int,
) -> list[list[str]]:
    out: list[list[str]] = []
    stack: list[tuple[str, list[str]]] = [(start, [start])]

    while stack and len(out) < limit:
        node, path = stack.pop()
        if len(path) > max_depth:
            continue
        for nxt in sorted(edges.get(node, set()), reverse=True):
            if nxt in path:
                continue
            next_path = path + [nxt]
            if nxt == goal:
                out.append(next_path)
                if len(out) >= limit:
                    break
                continue
            stack.append((nxt, next_path))
    return sorted(out, key=lambda p: (len(p), p))[:limit]

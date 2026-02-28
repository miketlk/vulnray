from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


_LANG_BY_SUFFIX = {
    ".c": "c",
    ".h": "h",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hh": "hpp",
    ".hpp": "hpp",
    ".hxx": "hpp",
}

_CODE_SUFFIXES = set(_LANG_BY_SUFFIX)


@dataclass(frozen=True)
class ExportFile:
    rel_path: str
    lang: str
    content: str
    byte_len: int


def _detect_lang(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in _LANG_BY_SUFFIX:
        return _LANG_BY_SUFFIX[suffix]
    return suffix.lstrip(".") or "txt"


def _strip_c_family_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    state = "code"
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if state == "code":
            if ch == "/" and nxt == "/":
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                i += 2
                state = "block_comment"
                continue
            if ch == '"':
                out.append(ch)
                i += 1
                state = "string"
                continue
            if ch == "'":
                out.append(ch)
                i += 1
                state = "char"
                continue
            out.append(ch)
            i += 1
            continue

        if state == "line_comment":
            if ch == "\n":
                out.append("\n")
                i += 1
                state = "code"
            else:
                i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                i += 2
                state = "code"
                continue
            # Preserve newlines to avoid collapsing line numbers.
            if ch == "\n":
                out.append("\n")
            i += 1
            continue

        if state == "string":
            out.append(ch)
            i += 1
            if ch == "\\" and i < n:
                out.append(text[i])
                i += 1
                continue
            if ch == '"':
                state = "code"
            continue

        if state == "char":
            out.append(ch)
            i += 1
            if ch == "\\" and i < n:
                out.append(text[i])
                i += 1
                continue
            if ch == "'":
                state = "code"
            continue

    return "".join(out)


def _strip_comments_for_path(path: Path, text: str) -> str:
    if path.suffix.lower() in _CODE_SUFFIXES:
        return _strip_c_family_comments(text)
    return text


def _collapse_blank_line_runs(text: str) -> str:
    if not text:
        return text
    lines = text.split("\n")
    out: list[str] = []
    prev_blank = False
    for line in lines:
        is_blank = line.strip() == ""
        if is_blank and prev_blank:
            continue
        out.append(line)
        prev_blank = is_blank
    return "\n".join(out)


def _stuff_content_lines(content: str) -> list[str]:
    if content == "":
        return []
    # Keep trailing newline fidelity by preserving trailing empty split item.
    return [f"> {line}" for line in content.split("\n")]


def build_export_records(root: Path, files: list[Path]) -> list[ExportFile]:
    records: list[ExportFile] = []
    base = root if root.is_dir() else root.parent
    for file_path in files:
        rel = str(file_path.relative_to(base)).replace("\\", "/")
        raw = file_path.read_text(encoding="utf-8", errors="ignore")
        stripped = _strip_comments_for_path(file_path, raw)
        normalized = _collapse_blank_line_runs(stripped)
        records.append(
            ExportFile(
                rel_path=rel,
                lang=_detect_lang(file_path),
                content=normalized,
                byte_len=len(normalized.encode("utf-8")),
            )
        )
    return records


def render_codebase_container(records: list[ExportFile]) -> str:
    lines: list[str] = [
        "---",
        "",
        "CODEBASE_CONTAINER v1",
        "",
        "PURPOSE:",
        "This file contains multiple source files merged into one document for LLM ingestion.",
        "",
        "PARSING RULES:",
        "1. Read MANIFEST first.",
        "2. Each FILE block has:",
        "   - PATH: original relative path",
        "   - LANG: c / cpp / h / hpp / txt / etc",
        "   - BYTES: exact byte length of CONTENT after unescaping",
        "   - ENCODING: utf-8",
        '   - STUFFING: lines beginning with "> " are content lines; remove the leading "> " from each content line',
        "3. The visible delimiter lines are only structural markers.",
        "4. If a delimiter-like string appears inside source code, it is harmless because only lines inside CONTENT are data, and BYTES is authoritative.",
        "",
        "MANIFEST_BEGIN",
    ]
    for rec in records:
        lines.extend(
            [
                f"- path: {rec.rel_path}",
                f"  lang: {rec.lang}",
                f"  bytes: {rec.byte_len}",
            ]
        )
    lines.extend(["MANIFEST_END", ""])

    for rec in records:
        stuffed_lines = _stuff_content_lines(rec.content)
        lines.extend(
            [
                "FILE_BEGIN",
                f"PATH: {rec.rel_path}",
                f"LANG: {rec.lang}",
                f"BYTES: {rec.byte_len}",
                "ENCODING: utf-8",
                'STUFFING: prefix_lines("> ")',
                "CONTENT_BEGIN",
                *stuffed_lines,
                "CONTENT_END",
                "FILE_END",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def export_codebase_container(*, root: Path, files: list[Path], output_path: Path) -> None:
    records = build_export_records(root, files)
    payload = render_codebase_container(records)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(payload, encoding="utf-8")

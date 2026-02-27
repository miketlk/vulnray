from __future__ import annotations

import os
from pathlib import Path

from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.reporting.summary import build_summary


def _resolve_file_path(root: Path, file_path: str) -> Path:
    p = Path(file_path)
    return p if p.is_absolute() else (root / p)


def _markdown_file_link(report_path: Path, file_path: Path, line: int) -> str:
    rel = Path(os.path.relpath(file_path.resolve(), report_path.parent.resolve())).as_posix()
    return f"{rel}#L{line}"


def _markdown_link(label: str, uri: str) -> str:
    return f"[{label}]({uri})"


def _finding_anchor(finding_id: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in finding_id).strip("-")
    return f"finding-{slug or 'unknown'}"


def _nowrap_hyphenated(value: str) -> str:
    return value.replace("-", "&#8209;")


def _report_intro_lines(live: bool) -> list[str]:
    title = "# Vulnray Scan Report (Live)" if live else "# Vulnray Scan Report"
    return [
        title,
        "",
        "[Executive Summary](#executive-summary) | [Findings Table](#findings-table)",
        "",
        "## Detailed Findings",
        "",
    ]


def _detailed_finding_lines(path: Path, root: Path, f: Finding, include_reasoning: bool) -> list[str]:
    abs_path = _resolve_file_path(root, f.file)
    file_link = _markdown_link(f.file, _markdown_file_link(path, abs_path, f.start_line))
    start_link = _markdown_link(str(f.start_line), _markdown_file_link(path, abs_path, f.start_line))
    end_link = _markdown_link(str(f.end_line), _markdown_file_link(path, abs_path, f.end_line))
    lines = [
        f'<a id="{_finding_anchor(f.id)}"></a>',
        "",
        f"### {f.id} - {f.vulnerability_type}",
        "",
        f"- File: {file_link}",
        f"- Lines: {start_link}-{end_link}",
        f"- Function: `{f.function or 'N/A'}`",
        f"- Severity: `{f.severity}`",
        f"- Confidence: `{f.confidence:.2f}`",
        "",
        "Description:",
        "",
        f.description or "(none)",
        "",
    ]
    if include_reasoning:
        lines.extend(["Reasoning:", "", f.reasoning or "(none)", ""])
    if f.references:
        lines.extend(["References:", "", ", ".join(f.references), ""])
    if f.recommendation:
        lines.extend(["Recommendation:", "", f.recommendation, ""])
    return lines


def _summary_and_table_lines(path: Path, cfg: Config, findings: list[Finding]) -> list[str]:
    summary = build_summary(findings)
    root = Path(cfg.path).resolve()
    lines: list[str] = [
        "## Executive Summary",
        "",
        f"- Mode: `{cfg.scan.mode}`",
        f"- Total Findings: **{summary['total_findings']}**",
        f"- Critical: {summary['by_severity']['critical']}",
        f"- High: {summary['by_severity']['high']}",
        f"- Medium: {summary['by_severity']['medium']}",
        f"- Low: {summary['by_severity']['low']}",
        "",
        "## Findings Table",
        "",
        "| ID | File | Lines | Function | Type | Severity | Confidence |",
        "|---|---|---:|---|---|---|---:|",
    ]

    for f in findings:
        if f.vulnerability_type == "ParserError":
            continue
        abs_path = _resolve_file_path(root, f.file)
        id_link = _markdown_link(_nowrap_hyphenated(f.id), f"#{_finding_anchor(f.id)}")
        file_link = _markdown_link(f.file, _markdown_file_link(path, abs_path, f.start_line))
        lines_link = _markdown_link(
            _nowrap_hyphenated(f"{f.start_line}-{f.end_line}"),
            _markdown_file_link(path, abs_path, f.start_line),
        )
        lines.append(
            f"| {id_link} | {file_link} | {lines_link} | `{f.function or 'N/A'}` | {f.vulnerability_type} | {f.severity} | {f.confidence:.2f} |"
        )
    return lines


def init_markdown_report(path: Path, cfg: Config) -> None:
    lines = _report_intro_lines(live=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def append_markdown_finding(path: Path, cfg: Config, f: Finding, include_reasoning: bool = True) -> None:
    if f.vulnerability_type == "ParserError":
        return
    root = Path(cfg.path).resolve()
    lines = _detailed_finding_lines(path, root, f, include_reasoning)
    with path.open("a", encoding="utf-8") as out:
        out.write("\n" + "\n".join(lines).rstrip() + "\n")


def append_markdown_summary_and_table(path: Path, cfg: Config, findings: list[Finding]) -> None:
    lines = _summary_and_table_lines(path, cfg, findings)
    with path.open("a", encoding="utf-8") as out:
        out.write("\n" + "\n".join(lines).rstrip() + "\n")


def write_markdown_report(path: Path, cfg: Config, findings: list[Finding], include_reasoning: bool = True) -> None:
    root = Path(cfg.path).resolve()
    lines = _report_intro_lines(live=False)
    for f in findings:
        if f.vulnerability_type == "ParserError":
            continue
        lines.extend(_detailed_finding_lines(path, root, f, include_reasoning))
    lines.extend(_summary_and_table_lines(path, cfg, findings))

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

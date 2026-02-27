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


def init_markdown_report(path: Path, cfg: Config) -> None:
    lines = [
        "# VulnLLM Scan Report (Live)",
        "",
        "## Executive Summary",
        "",
        f"- Mode: `{cfg.scan.mode}`",
        "- Status: `running`",
        "",
        "## Detailed Findings",
        "",
    ]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def append_markdown_finding(path: Path, cfg: Config, f: Finding, include_reasoning: bool = True) -> None:
    if f.vulnerability_type == "ParserError":
        return
    root = Path(cfg.path).resolve()
    abs_path = _resolve_file_path(root, f.file)
    file_link = _markdown_link(f.file, _markdown_file_link(path, abs_path, f.start_line))
    start_link = _markdown_link(str(f.start_line), _markdown_file_link(path, abs_path, f.start_line))
    end_link = _markdown_link(str(f.end_line), _markdown_file_link(path, abs_path, f.end_line))
    lines = [
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
        lines.extend(["Reasoning:", "", "```text", f.reasoning or "(none)", "```", ""])
    if f.references:
        lines.extend(["References:", "", ", ".join(f.references), ""])
    if f.recommendation:
        lines.extend(["Recommendation:", "", f.recommendation, ""])
    with path.open("a", encoding="utf-8") as out:
        out.write("\n".join(lines).rstrip() + "\n")


def write_markdown_report(path: Path, cfg: Config, findings: list[Finding], include_reasoning: bool = True) -> None:
    summary = build_summary(findings)
    root = Path(cfg.path).resolve()
    lines: list[str] = [
        "# VulnLLM Scan Report",
        "",
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
        file_link = _markdown_link(f.file, _markdown_file_link(path, abs_path, f.start_line))
        lines_link = _markdown_link(f"{f.start_line}-{f.end_line}", _markdown_file_link(path, abs_path, f.start_line))
        lines.append(
            f"| {f.id} | {file_link} | {lines_link} | `{f.function or 'N/A'}` | {f.vulnerability_type} | {f.severity} | {f.confidence:.2f} |"
        )

    lines += ["", "## Detailed Findings", ""]
    for f in findings:
        if f.vulnerability_type == "ParserError":
            continue
        abs_path = _resolve_file_path(root, f.file)
        file_link = _markdown_link(f.file, _markdown_file_link(path, abs_path, f.start_line))
        start_link = _markdown_link(str(f.start_line), _markdown_file_link(path, abs_path, f.start_line))
        end_link = _markdown_link(str(f.end_line), _markdown_file_link(path, abs_path, f.end_line))
        lines.extend(
            [
                f"### {f.id} - {f.vulnerability_type}",
                "",
                f"- File: {file_link}",
                f"- Lines: {start_link}-{end_link}",
                f"- Findings Table ID: `{f.id}`",
                f"- Function: `{f.function or 'N/A'}`",
                f"- Severity: `{f.severity}`",
                f"- Confidence: `{f.confidence:.2f}`",
                "",
                "Description:",
                "",
                f.description or "(none)",
                "",
            ]
        )
        if include_reasoning:
            lines.extend(["Reasoning:", "", "```text", f.reasoning or "(none)", "```", ""])
        if f.references:
            lines.extend(["References:", "", ", ".join(f.references), ""])
        if f.recommendation:
            lines.extend(["Recommendation:", "", f.recommendation, ""])

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

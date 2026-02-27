from __future__ import annotations

from pathlib import Path

from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.reporting.summary import build_summary


def write_markdown_report(path: Path, cfg: Config, findings: list[Finding], include_reasoning: bool = True) -> None:
    summary = build_summary(findings)
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
        "| ID | File | Lines | Type | Severity | Confidence |",
        "|---|---|---:|---|---|---:|",
    ]

    for f in findings:
        if f.vulnerability_type == "ParserError":
            continue
        lines.append(
            f"| {f.id} | {f.file} | {f.start_line}-{f.end_line} | {f.vulnerability_type} | {f.severity} | {f.confidence:.2f} |"
        )

    lines += ["", "## Detailed Findings", ""]
    for f in findings:
        if f.vulnerability_type == "ParserError":
            continue
        lines.extend(
            [
                f"### {f.id} - {f.vulnerability_type}",
                "",
                f"- File: `{f.file}`",
                f"- Lines: `{f.start_line}-{f.end_line}`",
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

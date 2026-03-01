from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.reporting.summary import build_summary


def _finding_to_json_item(f: Finding, include_reasoning: bool = True) -> dict:
    item = {
        "id": f.id,
        "file": f.file,
        "start_line": f.start_line,
        "end_line": f.end_line,
        "function": f.function,
        "vulnerability_type": f.vulnerability_type,
        "severity": f.severity,
        "confidence": f.confidence,
        "description": f.description,
        "claim": f.claim,
        "precondition": f.precondition,
        "where_precondition_is_enforced": f.where_precondition_is_enforced,
        "trigger_path": f.trigger_path,
        "exploitability": f.exploitability,
        "contract_breach_evidence": f.contract_breach_evidence,
        "analysis_mode": f.analysis_mode,
        "evidence_spans": f.evidence_spans,
        "requires_caller_violation": f.requires_caller_violation,
        "context_sufficiency": f.context_sufficiency,
        "references": f.references,
        "recommendation": f.recommendation,
    }
    if include_reasoning:
        item["reasoning"] = f.reasoning
    if f.parse_error:
        item["parse_error"] = f.parse_error
    return item


def _last_non_whitespace_char(path: Path) -> str:
    with path.open("rb") as f:
        f.seek(0, 2)
        pos = f.tell()
        while pos > 0:
            size = min(4096, pos)
            pos -= size
            f.seek(pos)
            chunk = f.read(size)
            for b in reversed(chunk):
                ch = chr(b)
                if not ch.isspace():
                    return ch
    return ""


def _indent_lines(text: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.splitlines())


def _strip_final_summary_if_present(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    marker = '\n  ],\n  "summary":'
    idx = text.rfind(marker)
    if idx == -1:
        return
    path.write_text(text[:idx], encoding="utf-8")


def init_json_report(
    path: Path,
    cfg: Config,
    repo_root: str,
    files_scanned: int,
    chunks_analyzed: int,
) -> None:
    scan_metadata = {
        "tool": "vulnray",
        "model": cfg.inference.model,
        "mode": cfg.scan.mode,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_root": repo_root,
        "total_files_scanned": files_scanned,
        "total_chunks_analyzed": chunks_analyzed,
    }
    metadata_lines = json.dumps(scan_metadata, indent=2).splitlines()
    lines = ['{', '  "scan_metadata": {']
    for line in metadata_lines[1:-1]:
        lines.append(f"  {line}")
    lines.extend(['  },', '  "findings": ['])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_json_finding(path: Path, finding: Finding, *, include_reasoning: bool = True) -> None:
    _strip_final_summary_if_present(path)
    last = _last_non_whitespace_char(path)
    if last not in {"[", "}"}:
        raise ValueError(f"Invalid incremental JSON report layout: {path}")
    item_json = _indent_lines(
        json.dumps(_finding_to_json_item(finding, include_reasoning=include_reasoning), indent=2),
        4,
    )
    prefix = "\n" if last == "[" else ",\n"
    with path.open("a", encoding="utf-8") as out:
        out.write(prefix + item_json + "\n")


def append_json_summary(path: Path, findings: list[Finding]) -> None:
    _strip_final_summary_if_present(path)
    last = _last_non_whitespace_char(path)
    if last not in {"[", "}"}:
        raise ValueError(f"Invalid incremental JSON report layout: {path}")
    summary_json = json.dumps(build_summary(findings), indent=2)
    summary_lines = summary_json.splitlines()
    summary_block = ['  "summary": ' + summary_lines[0]]
    for line in summary_lines[1:]:
        summary_block.append(f"  {line}")
    tail = ["  ],", *summary_block, "}"]
    with path.open("a", encoding="utf-8") as out:
        out.write("\n" + "\n".join(tail) + "\n")


def write_json_report(
    path: Path,
    cfg: Config,
    repo_root: str,
    files_scanned: int,
    chunks_analyzed: int,
    findings: list[Finding],
    include_reasoning: bool = True,
) -> None:
    init_json_report(path, cfg, repo_root, files_scanned, chunks_analyzed)
    for f in findings:
        append_json_finding(path, f, include_reasoning=include_reasoning)
    append_json_summary(path, findings)

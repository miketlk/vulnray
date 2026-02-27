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
        "references": f.references,
        "recommendation": f.recommendation,
    }
    if include_reasoning:
        item["reasoning"] = f.reasoning
    if f.parse_error:
        item["parse_error"] = f.parse_error
    return item


def init_json_report(
    path: Path,
    cfg: Config,
    repo_root: str,
    files_scanned: int,
    chunks_analyzed: int,
) -> None:
    report = {
        "scan_metadata": {
            "tool": "vulnllm-scan",
            "model": cfg.inference.model,
            "mode": cfg.scan.mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo_root": repo_root,
            "total_files_scanned": files_scanned,
            "total_chunks_analyzed": chunks_analyzed,
        },
        "summary": build_summary([]),
        "findings": [],
    }
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def append_json_finding(path: Path, finding: Finding, *, include_reasoning: bool = True) -> None:
    text = path.read_text(encoding="utf-8")
    try:
        report = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid incremental JSON report layout: {path}") from e

    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError(f"Invalid incremental JSON report layout: {path}")

    report["findings"].append(_finding_to_json_item(finding, include_reasoning=include_reasoning))
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def write_json_report(
    path: Path,
    cfg: Config,
    repo_root: str,
    files_scanned: int,
    chunks_analyzed: int,
    findings: list[Finding],
    include_reasoning: bool = True,
) -> None:
    report = {
        "scan_metadata": {
            "tool": "vulnllm-scan",
            "model": cfg.inference.model,
            "mode": cfg.scan.mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo_root": repo_root,
            "total_files_scanned": files_scanned,
            "total_chunks_analyzed": chunks_analyzed,
        },
        "summary": build_summary(findings),
        "findings": [],
    }

    for f in findings:
        report["findings"].append(_finding_to_json_item(f, include_reasoning=include_reasoning))

    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

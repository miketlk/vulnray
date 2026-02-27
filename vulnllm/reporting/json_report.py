from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.reporting.summary import build_summary


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
        report["findings"].append(item)

    path.write_text(json.dumps(report, indent=2), encoding="utf-8")

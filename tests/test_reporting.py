from __future__ import annotations

import json
from pathlib import Path

from tests.model_utils import local_model_path
from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.reporting.csv_report import write_csv_report
from vulnllm.reporting.json_report import write_json_report
from vulnllm.reporting.markdown_report import write_markdown_report


def test_reports_generation(tmp_path: Path):
    cfg = Config()
    cfg.inference.model = local_model_path()
    findings = [
        Finding(
            id="F-0001",
            file="src/a.c",
            start_line=10,
            end_line=20,
            function="foo",
            vulnerability_type="Buffer Overflow",
            severity="high",
            confidence=0.9,
            description="unchecked length",
            reasoning="memcpy without bounds check",
            references=["CWE-120"],
            recommendation="check bounds",
        )
    ]

    json_path = tmp_path / "scan.json"
    csv_path = tmp_path / "scan.csv"
    md_path = tmp_path / "scan.md"

    write_json_report(json_path, cfg, str(tmp_path), 1, 1, findings, include_reasoning=True)
    write_csv_report(csv_path, findings)
    write_markdown_report(md_path, cfg, findings, include_reasoning=True)

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["total_findings"] == 1
    assert "Buffer Overflow" in csv_path.read_text(encoding="utf-8")
    assert "# VulnLLM Scan Report" in md_path.read_text(encoding="utf-8")

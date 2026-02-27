from __future__ import annotations

import json
from pathlib import Path

from tests.model_utils import local_model_path
from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.reporting.csv_report import append_csv_finding, init_csv_report, write_csv_report
from vulnllm.reporting.json_report import append_json_finding, init_json_report, write_json_report
from vulnllm.reporting.markdown_report import append_markdown_finding, init_markdown_report, write_markdown_report


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
    md_text = md_path.read_text(encoding="utf-8")

    assert data["summary"]["total_findings"] == 1
    assert "Buffer Overflow" in csv_path.read_text(encoding="utf-8")
    assert "# VulnLLM Scan Report" in md_text
    assert "| ID | File | Lines | Function | Type | Severity | Confidence |" in md_text
    assert "| F-0001 | [src/a.c](" in md_text
    assert "| `foo` | Buffer Overflow | high | 0.90 |" in md_text
    assert "- Lines: [10](" in md_text
    assert "-[20](" in md_text
    assert "- Findings Table ID: `F-0001`" in md_text


def test_incremental_report_append(tmp_path: Path):
    cfg = Config()
    cfg.path = str(tmp_path)
    cfg.inference.model = local_model_path()
    finding = Finding(
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

    json_path = tmp_path / "scan.json"
    csv_path = tmp_path / "scan.csv"
    md_path = tmp_path / "scan.md"

    init_json_report(json_path, cfg, str(tmp_path), 1, 1)
    append_json_finding(json_path, finding, include_reasoning=True)
    init_csv_report(csv_path)
    append_csv_finding(csv_path, finding)
    init_markdown_report(md_path, cfg)
    append_markdown_finding(md_path, cfg, finding, include_reasoning=True)

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "F-0001"
    assert "Buffer Overflow" in csv_path.read_text(encoding="utf-8")
    assert "### F-0001 - Buffer Overflow" in md_path.read_text(encoding="utf-8")

from __future__ import annotations

import json
from pathlib import Path

from tests.model_utils import local_model_path
from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.reporting.csv_report import append_csv_finding, init_csv_report, write_csv_report
from vulnllm.reporting.json_report import append_json_finding, append_json_summary, init_json_report, write_json_report
from vulnllm.reporting.markdown_report import (
    append_markdown_finding,
    append_markdown_summary_and_table,
    init_markdown_report,
    write_markdown_report,
)


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
    assert data["findings"][0]["analysis_mode"] == "shallow"
    assert data["findings"][0]["evidence_spans"] == 0
    assert data["findings"][0]["requires_caller_violation"] is False
    assert data["findings"][0]["context_sufficiency"] == "unknown"
    assert "Buffer Overflow" in csv_path.read_text(encoding="utf-8")
    assert "# Vulnray Scan Report" in md_text
    assert "[Executive Summary](#executive-summary) | [Findings Table](#findings-table)" in md_text
    assert md_text.index("## Detailed Findings") < md_text.index("## Executive Summary")
    assert "| ID | File | Lines | Function | Type | Severity | Confidence |" in md_text
    assert "| [F&#8209;0001](#finding-f-0001) | [src/a.c](" in md_text
    assert "| [10&#8209;20](" in md_text
    assert "| `foo` | Buffer Overflow | high | 0.90 |" in md_text
    assert '<a id="finding-f-0001"></a>' in md_text
    assert "- Lines: [10](" in md_text
    assert "-[20](" in md_text
    assert "Reasoning:\n\nmemcpy without bounds check" in md_text
    assert "```text" not in md_text


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
    append_json_summary(json_path, [finding])
    init_csv_report(csv_path)
    append_csv_finding(csv_path, finding)
    init_markdown_report(md_path, cfg)
    append_markdown_finding(md_path, cfg, finding, include_reasoning=True)
    append_markdown_summary_and_table(md_path, cfg, [finding])

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "F-0001"
    assert data["summary"]["total_findings"] == 1
    assert "Buffer Overflow" in csv_path.read_text(encoding="utf-8")
    md_text = md_path.read_text(encoding="utf-8")
    assert "# Vulnray Scan Report (Live)" in md_text
    assert "[Executive Summary](#executive-summary) | [Findings Table](#findings-table)" in md_text
    assert "### F-0001 - Buffer Overflow" in md_text
    assert "## Executive Summary" in md_text
    assert "## Findings Table" in md_text


def test_incremental_json_can_append_after_finalize(tmp_path: Path):
    cfg = Config()
    cfg.path = str(tmp_path)
    cfg.inference.model = local_model_path()
    finding1 = Finding(
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
    )
    finding2 = Finding(
        id="F-0002",
        file="src/b.c",
        start_line=30,
        end_line=40,
        function="bar",
        vulnerability_type="Integer Overflow",
        severity="medium",
        confidence=0.7,
        description="unchecked arithmetic",
        reasoning="size multiplication can overflow",
    )

    json_path = tmp_path / "scan.json"
    init_json_report(json_path, cfg, str(tmp_path), 1, 1)
    append_json_finding(json_path, finding1, include_reasoning=True)
    append_json_summary(json_path, [finding1])
    append_json_finding(json_path, finding2, include_reasoning=True)
    append_json_summary(json_path, [finding1, finding2])

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 2
    assert data["findings"][1]["id"] == "F-0002"
    assert data["summary"]["total_findings"] == 2

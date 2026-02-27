from __future__ import annotations

import csv
from pathlib import Path

from vulnllm.findings.model import Finding


CSV_COLUMNS = ["File", "Start line", "End line", "Vulnerability type", "Severity", "Confidence"]


def init_csv_report(path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(CSV_COLUMNS)


def append_csv_finding(path: Path, item: Finding) -> None:
    if item.vulnerability_type == "ParserError":
        return
    with path.open("a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(
            [
                item.file,
                item.start_line,
                item.end_line,
                item.vulnerability_type,
                item.severity,
                item.confidence,
            ]
        )


def write_csv_report(path: Path, findings: list[Finding]) -> None:
    init_csv_report(path)
    for item in findings:
        append_csv_finding(path, item)

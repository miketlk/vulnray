from __future__ import annotations

import csv
from pathlib import Path

from vulnllm.findings.model import Finding


def write_csv_report(path: Path, findings: list[Finding]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["File", "Start line", "End line", "Vulnerability type", "Severity", "Confidence"])
        for item in findings:
            if item.vulnerability_type == "ParserError":
                continue
            w.writerow(
                [
                    item.file,
                    item.start_line,
                    item.end_line,
                    item.vulnerability_type,
                    item.severity,
                    item.confidence,
                ]
            )

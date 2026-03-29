from __future__ import annotations

from collections import Counter

from vulnllm.findings.model import Finding


def build_summary(findings: list[Finding], telemetry: dict[str, int] | None = None) -> dict:
    c = Counter([f.severity for f in findings])
    summary = {
        "total_findings": sum(c.values()),
        "by_severity": {
            "critical": c.get("critical", 0),
            "high": c.get("high", 0),
            "medium": c.get("medium", 0),
            "low": c.get("low", 0),
        },
    }
    if telemetry:
        summary["telemetry"] = {k: int(v) for k, v in telemetry.items()}
    return summary

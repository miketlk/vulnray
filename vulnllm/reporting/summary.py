from __future__ import annotations

from collections import Counter

from vulnllm.findings.model import Finding


def build_summary(findings: list[Finding]) -> dict:
    c = Counter([f.severity for f in findings if f.vulnerability_type != "ParserError"])
    return {
        "total_findings": sum(c.values()),
        "by_severity": {
            "critical": c.get("critical", 0),
            "high": c.get("high", 0),
            "medium": c.get("medium", 0),
            "low": c.get("low", 0),
        },
    }

from __future__ import annotations

SEVERITIES = ["low", "medium", "high", "critical"]


def normalize_severity(value: str) -> str:
    if not value:
        return "medium"
    low = value.lower().strip()
    if low in SEVERITIES:
        return low
    if low in {"info", "informational"}:
        return "low"
    if low in {"severe", "very high"}:
        return "high"
    return "medium"


def severity_rank(value: str) -> int:
    v = normalize_severity(value)
    return SEVERITIES.index(v) + 1

from __future__ import annotations

from vulnllm.findings.model import Finding


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.file, f.start_line, f.end_line, f.vulnerability_type)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.findings.severity import normalize_severity


@dataclass
class Finding:
    id: str
    file: str
    start_line: int
    end_line: int
    function: str | None
    vulnerability_type: str
    severity: str
    confidence: float
    description: str
    reasoning: str
    references: list[str] = field(default_factory=list)
    recommendation: str = ""
    parse_error: str | None = None


def _extract_json(raw: str) -> dict:
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Backup protocol
    begin = raw.find("BEGIN_FINDINGS_JSON")
    end = raw.find("END_FINDINGS_JSON")
    if begin != -1 and end != -1 and end > begin:
        block = raw[begin + len("BEGIN_FINDINGS_JSON") : end].strip()
        return json.loads(block)

    decoder = json.JSONDecoder()
    best: dict | None = None
    best_with_vulns: dict | None = None
    idx = 0
    while True:
        idx = raw.find("{", idx)
        if idx == -1:
            break
        try:
            obj, _ = decoder.raw_decode(raw, idx)
        except json.JSONDecodeError:
            idx += 1
            continue
        if isinstance(obj, dict):
            best = obj
            if "vulnerabilities" in obj:
                best_with_vulns = obj
        idx += 1

    if best_with_vulns is not None:
        return best_with_vulns
    if best is not None:
        return best
    raise ValueError("No JSON object found")


def _extract_final_answer_format(raw: str) -> dict | None:
    judge_match = re.search(r"(?im)^\s*#judge:\s*(yes|no)\s*$", raw)
    type_match = re.search(r"(?im)^\s*#type:\s*([^\n\r]+)\s*$", raw)
    if judge_match is None or type_match is None:
        return None

    judge = judge_match.group(1).strip().lower()
    vuln_type = type_match.group(1).strip()
    if judge == "no":
        return {"vulnerabilities": []}

    if vuln_type.upper() == "N/A":
        vuln_type = "Potential Vulnerability"
    cwe = vuln_type.upper() if vuln_type.upper().startswith("CWE-") else ""
    return {
        "vulnerabilities": [
            {
                "vulnerability_type": vuln_type,
                "severity": "medium",
                "confidence": 0.6,
                "description": "Parsed from #judge/#type output.",
                "reasoning": raw[:1200],
                "recommendation": "Manually review and confirm exploitability.",
                "references": [cwe] if cwe else [],
            }
        ]
    }


def parse_findings(raw: str, chunk: CodeChunk, start_id: int = 1) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    try:
        try:
            obj = _extract_json(raw)
        except ValueError:
            obj = _extract_final_answer_format(raw)
            if obj is None:
                raise
        vulns = obj.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            raise ValueError("vulnerabilities must be list")

        next_id = start_id
        for v in vulns:
            if not isinstance(v, dict):
                continue
            f = Finding(
                id=f"F-{next_id:04d}",
                file=chunk.file,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                function=chunk.function,
                vulnerability_type=str(v.get("vulnerability_type", "Potential Vulnerability")),
                severity=normalize_severity(str(v.get("severity", "medium"))),
                confidence=float(v.get("confidence", 0.5) or 0.5),
                description=str(v.get("description", "")),
                reasoning=str(v.get("reasoning", "")),
                references=[str(x) for x in v.get("references", []) if x],
                recommendation=str(v.get("recommendation", "")),
            )
            findings.append(f)
            next_id += 1
        return findings, next_id
    except Exception as e:
        err = Finding(
            id=f"F-{start_id:04d}",
            file=chunk.file,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            function=chunk.function,
            vulnerability_type="ParserError",
            severity="low",
            confidence=0.0,
            description="Failed to parse model output",
            reasoning=raw[:1200],
            parse_error=str(e),
        )
        return [err], start_id + 1

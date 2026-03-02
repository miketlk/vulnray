from __future__ import annotations

import re
from dataclasses import dataclass, field

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.findings.compact_block import (
    compact_decision_to_payload,
    extract_complete_sane_compact_block,
    extract_last_compact_decision,
)
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
    claim: str = ""
    precondition: str = ""
    where_precondition_is_enforced: str = "none"
    trigger_path: str = ""
    exploitability: str = "theoretical"
    contract_breach_evidence: bool = False
    attacker_controlled_input: bool = False
    bounds_contradiction_evidence: bool = False
    analysis_mode: str = "shallow"
    evidence_spans: int = 0
    requires_caller_violation: bool = False
    context_sufficiency: str = "unknown"
    parse_error: str | None = None


def _normalize_analysis_mode(value: object) -> str:
    mode = str(value or "shallow").strip().lower()
    if mode in {"shallow", "contract-aware", "verified"}:
        return mode
    return "shallow"


def _parse_evidence_spans_count(value: object) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        return max(0, int(value))
    if isinstance(value, str):
        trimmed = value.strip()
        if trimmed.isdigit():
            return int(trimmed)
    return 0


def _parse_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y"}:
            return True
        if lowered in {"false", "0", "no", "n"}:
            return False
    return default


def _normalize_context_sufficiency(value: object) -> str:
    normalized = str(value or "unknown").strip().lower()
    if normalized in {"sufficient", "insufficient", "unknown"}:
        return normalized
    return "unknown"


def _normalize_exploitability(value: object) -> str:
    normalized = str(value or "theoretical").strip().lower()
    if normalized in {"practical", "theoretical", "contract-break-only"}:
        return normalized
    return "theoretical"


def extract_complete_sane_formatted_output_block(raw: str) -> str | None:
    return extract_complete_sane_compact_block(raw, allow_early_negative_without_context=True)


def extract_decision_metadata(raw: str) -> tuple[list[str], list[str]]:
    decision = extract_last_compact_decision(
        raw,
        require_complete_why_line=False,
        allow_early_negative_without_context=True,
    )
    if decision is None:
        return [], []

    vuln_types = [t.strip() for t in re.split(r"[;,]", decision.vuln_type) if t.strip()]
    cwes = [v.upper() for v in vuln_types if v.upper().startswith("CWE-")]
    symbols = [str(x).strip() for x in decision.need_context_symbols if str(x).strip()]
    return cwes, symbols


def parse_findings(raw: str, chunk: CodeChunk, start_id: int = 1) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    try:
        decision = extract_last_compact_decision(
            raw,
            require_complete_why_line=False,
            allow_early_negative_without_context=True,
        )
        if decision is None:
            raise ValueError("No valid compact output block found")
        obj = compact_decision_to_payload(decision)
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
                claim=str(v.get("claim", "")),
                precondition=str(v.get("precondition", "")),
                where_precondition_is_enforced=str(v.get("where_precondition_is_enforced", "none") or "none"),
                trigger_path=str(v.get("trigger_path", "")),
                exploitability=_normalize_exploitability(v.get("exploitability", "theoretical")),
                contract_breach_evidence=_parse_bool(v.get("contract_breach_evidence"), default=False),
                attacker_controlled_input=_parse_bool(v.get("attacker_controlled_input"), default=False),
                bounds_contradiction_evidence=_parse_bool(v.get("bounds_contradiction_evidence"), default=False),
                analysis_mode=_normalize_analysis_mode(v.get("analysis_mode", "shallow")),
                evidence_spans=_parse_evidence_spans_count(v.get("evidence_spans")),
                requires_caller_violation=_parse_bool(v.get("requires_caller_violation"), default=False),
                context_sufficiency=_normalize_context_sufficiency(v.get("context_sufficiency", "unknown")),
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

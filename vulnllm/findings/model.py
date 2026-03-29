from __future__ import annotations

import re
from dataclasses import dataclass, field

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.findings.compact_block import (
    CompactSufficiencyDecision,
    extract_complete_sane_detection_block,
    extract_last_detection_decision,
    extract_last_sufficiency_decision,
    extract_legacy_requested_symbols,
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


def _normalize_text_space(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _build_description(*, vulnerability_type: str, reasoning: str, trigger_path: str) -> str:
    vuln_upper = (vulnerability_type or "").upper()
    reason = _normalize_text_space(reasoning)
    trigger = _normalize_text_space(trigger_path).lower()
    lowered = reason.lower()

    if vuln_upper == "CWE-120":
        if "strcpy" in trigger or "strcpy" in lowered:
            return "Unbounded strcpy into a fixed-size destination may overflow."
        if "strcat" in trigger or "strcat" in lowered:
            return "Unbounded strcat into a fixed-size destination may overflow."
        return "Unbounded copy into a fixed-size destination may overflow."
    if vuln_upper == "CWE-787":
        if "sprintf" in trigger or "sprintf" in lowered:
            return "sprintf into a fixed-size buffer may write out of bounds."
        return "Out-of-bounds write into a fixed-size buffer is possible."
    if vuln_upper == "CWE-22":
        if "fopen" in trigger or "fopen" in lowered:
            return "Unvalidated relative path reaches filesystem access."
        return "Unvalidated relative path may enable path traversal."
    if vuln_upper == "CWE-190":
        if "*" in trigger or "multiplication" in lowered or " * " in lowered:
            return "Unchecked integer multiplication may overflow."
        return "Unchecked integer arithmetic may overflow."
    return reason


def extract_complete_sane_formatted_output_block(raw: str) -> str | None:
    return extract_complete_sane_detection_block(raw)


def extract_decision_metadata(raw: str) -> tuple[list[str], list[str]]:
    decision = extract_last_detection_decision(raw)
    if decision is None:
        return [], extract_legacy_requested_symbols(raw)

    vuln_types = [t.strip() for t in re.split(r"[;,]", decision.vuln_type) if t.strip()]
    cwes = [v.upper() for v in vuln_types if v.upper().startswith("CWE-")]
    return cwes, extract_legacy_requested_symbols(raw)


def parse_sufficiency_decision(raw: str) -> CompactSufficiencyDecision | None:
    return extract_last_sufficiency_decision(raw)


def parse_findings_with_error(raw: str, chunk: CodeChunk, start_id: int = 1) -> tuple[list[Finding], int, str | None]:
    decision = extract_last_detection_decision(raw)
    if decision is None:
        return [], start_id, "No valid detection output block found"

    if decision.judge == "no":
        return [], start_id, None

    raw_types = [t.strip() for t in re.split(r"[;,]", decision.vuln_type) if t.strip()]
    if not raw_types:
        return [], start_id, "No valid CWE values in detection output"
    if not all(re.fullmatch(r"CWE-\d{2,}", item, flags=re.IGNORECASE) for item in raw_types):
        return [], start_id, "Detection output contained malformed CWE values"

    confidence = {"low": 0.5, "medium": 0.7, "high": 0.9}.get(decision.confidence_label, 0.7)
    legacy_context_sufficient = "unknown"
    ctx_m = re.search(r"(?im)^\s*#context_sufficient:\s*(yes|no)\s*$", raw)
    if ctx_m:
        legacy_context_sufficient = "sufficient" if ctx_m.group(1).strip().lower() == "yes" else "insufficient"
    legacy_where = "none"
    where_m = re.search(r"(?im)^\s*#where_precondition_is_enforced:\s*([^\n\r]+)\s*$", raw)
    if where_m:
        legacy_where = where_m.group(1).strip()
    requires_caller_violation = False
    caller_m = re.search(r"(?im)^\s*#caller_violation_required:\s*(yes|no)\s*$", raw)
    if caller_m:
        requires_caller_violation = caller_m.group(1).strip().lower() == "yes"
    bounds_contradiction = False
    bounds_m = re.search(r"(?im)^\s*#bounds_contradiction:\s*(yes|no)\s*$", raw)
    if bounds_m:
        bounds_contradiction = bounds_m.group(1).strip().lower() == "yes"
    contract_breach = False
    contract_m = re.search(r"(?im)^\s*#contract_breach_evidence:\s*(yes|no)\s*$", raw)
    if contract_m:
        contract_breach = contract_m.group(1).strip().lower() == "yes"
    claim = ""
    claim_m = re.search(r"(?im)^\s*#claim:\s*([^\n\r]+)\s*$", raw)
    if claim_m:
        claim = claim_m.group(1).strip()
    precondition = ""
    precondition_m = re.search(r"(?im)^\s*#precondition:\s*([^\n\r]+)\s*$", raw)
    if precondition_m:
        precondition = precondition_m.group(1).strip()
    trigger_path = ""
    sink_m = re.search(r"(?im)^\s*#sink:\s*([^\n\r]+)\s*$", raw)
    if sink_m:
        trigger_path = sink_m.group(1).strip()
    findings: list[Finding] = []
    next_id = start_id
    for vuln_type in raw_types:
        normalized_type = vuln_type.upper() if vuln_type.upper().startswith("CWE-") else vuln_type
        description = _build_description(
            vulnerability_type=normalized_type,
            reasoning=decision.why,
            trigger_path=trigger_path,
        )
        findings.append(
            Finding(
                id=f"F-{next_id:04d}",
                file=chunk.file,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                function=chunk.function,
                vulnerability_type=normalized_type,
                severity=normalize_severity("medium"),
                confidence=confidence,
                description=description,
                reasoning=decision.why,
                references=[normalized_type] if normalized_type.upper().startswith("CWE-") else [],
                recommendation="Manually review and confirm exploitability.",
                claim=claim,
                precondition=precondition,
                where_precondition_is_enforced=legacy_where,
                trigger_path=trigger_path,
                contract_breach_evidence=contract_breach,
                bounds_contradiction_evidence=bounds_contradiction,
                requires_caller_violation=requires_caller_violation,
                context_sufficiency=legacy_context_sufficient,
            )
        )
        next_id += 1
    return findings, next_id, None


def parse_findings(raw: str, chunk: CodeChunk, start_id: int = 1) -> tuple[list[Finding], int]:
    findings, next_id, _parse_error = parse_findings_with_error(raw, chunk, start_id=start_id)
    return findings, next_id

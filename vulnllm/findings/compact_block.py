from __future__ import annotations

import re
from dataclasses import dataclass


_JUDGE_RE = re.compile(r"(?im)^\s*#judge:\s*(yes|no)\s*$")
_TYPE_RE = re.compile(r"(?im)^\s*#type:\s*([^\n\r]+)\s*$")
_WHY_RE = re.compile(r"(?im)^\s*#why:\s*([^\n\r]+)\s*$")
_FUNCTION_RE = re.compile(r"(?im)^\s*#function:\s*([^\n\r]+)\s*$")
_CONFIDENCE_RE = re.compile(r"(?im)^\s*#confidence:\s*(low|medium|high)\s*$")
_LEGACY_CONTEXT_SUFFICIENT_RE = re.compile(r"(?im)^\s*#context_sufficient:\s*(yes|no)\s*$")
_LEGACY_NEED_CONTEXT_RE = re.compile(r"(?im)^\s*#need_context:\s*([^\n\r]+)\s*$")
_LEGACY_WHERE_RE = re.compile(r"(?im)^\s*#where_precondition_is_enforced:\s*([^\n\r]+)\s*$")
_LEGACY_CALLER_RE = re.compile(r"(?im)^\s*#caller_violation_required:\s*([^\n\r]+)\s*$")
_LEGACY_BOUNDS_RE = re.compile(r"(?im)^\s*#bounds_contradiction:\s*([^\n\r]+)\s*$")
_LEGACY_CONTRACT_RE = re.compile(r"(?im)^\s*#contract_breach_evidence:\s*([^\n\r]+)\s*$")

_VALID_WHERE = {"assertion", "caller_check", "none", "unknown"}
_VALID_BOOLISH = {"yes", "no", "n/a"}


@dataclass(frozen=True)
class CompactDetectionDecision:
    judge: str
    vuln_type: str
    confidence_label: str
    why: str
    block: str


@dataclass(frozen=True)
class CompactSufficiencyDecision:
    judge: str
    requested_symbols: list[str]
    block: str

    @property
    def context_is_sufficient(self) -> bool:
        return self.judge == "yes"


def _is_example_output_segment(raw: str, segment_start: int, segment: str) -> bool:
    prefix = raw[:segment_start]
    prev_lines = [line.strip().lower() for line in prefix.splitlines() if line.strip()]
    if prev_lines and prev_lines[-1].startswith("example output"):
        return True
    lowered = segment.lower()
    return "example output" in lowered or "#judge: <yes/no>" in lowered


def _placeholder_type(vuln_type: str) -> bool:
    trimmed = vuln_type.strip().lower()
    return "|" in vuln_type or trimmed in {"cwe-xx", "<vulnerability type>"}


def _split_requested_symbols(raw_value: str) -> list[str]:
    trimmed = raw_value.strip()
    if not trimmed or trimmed.upper() == "N/A":
        return []
    return [item.strip() for item in trimmed.split(",") if item.strip()]


def _validate_legacy_fields(segment: str) -> bool:
    where_m = _LEGACY_WHERE_RE.search(segment)
    if where_m and where_m.group(1).strip().lower() not in _VALID_WHERE:
        return False
    caller_m = _LEGACY_CALLER_RE.search(segment)
    if caller_m and caller_m.group(1).strip().lower() not in _VALID_BOOLISH:
        return False
    bounds_m = _LEGACY_BOUNDS_RE.search(segment)
    if bounds_m and bounds_m.group(1).strip().lower() not in _VALID_BOOLISH:
        return False
    contract_m = _LEGACY_CONTRACT_RE.search(segment)
    if contract_m and contract_m.group(1).strip().lower() not in _VALID_BOOLISH:
        return False
    return True


def _parse_detection_segment(
    raw: str,
    segment_start: int,
    segment: str,
    *,
    require_complete_why_line: bool = False,
) -> CompactDetectionDecision | None:
    if _is_example_output_segment(raw, segment_start, segment):
        return None
    if not _validate_legacy_fields(segment):
        return None

    judge_m = _JUDGE_RE.search(segment)
    type_m = _TYPE_RE.search(segment)
    if not (judge_m and type_m):
        return None

    vuln_type = type_m.group(1).strip()
    if _placeholder_type(vuln_type):
        return None

    confidence_m = _CONFIDENCE_RE.search(segment)
    why_m = _WHY_RE.search(segment)
    end_idx = why_m.end() if why_m is not None else type_m.end()
    why = why_m.group(1).strip() if why_m is not None else ""
    if why_m is not None and not why:
        return None
    if require_complete_why_line and why_m is not None and why_m.end() >= len(segment):
        return None

    return CompactDetectionDecision(
        judge=judge_m.group(1).strip().lower(),
        vuln_type=vuln_type,
        confidence_label=(confidence_m.group(1).strip().lower() if confidence_m else "medium"),
        why=why,
        block=segment[judge_m.start() : end_idx].strip(),
    )


def _parse_sufficiency_segment(
    raw: str,
    segment_start: int,
    segment: str,
    *,
    require_complete_function_line: bool = False,
) -> CompactSufficiencyDecision | None:
    if _is_example_output_segment(raw, segment_start, segment):
        return None

    judge_m = _JUDGE_RE.search(segment)
    function_m = _FUNCTION_RE.search(segment)
    if not (judge_m and function_m):
        return None

    value = function_m.group(1).strip()
    if not value:
        return None
    lowered = value.lower()
    if "|" in value or lowered in {"list of needed functions", "<list of needed functions>"}:
        return None
    if require_complete_function_line and function_m.end() >= len(segment):
        return None

    requested_symbols = _split_requested_symbols(value)
    end_idx = function_m.end()
    return CompactSufficiencyDecision(
        judge=judge_m.group(1).strip().lower(),
        requested_symbols=requested_symbols,
        block=segment[judge_m.start() : end_idx].strip(),
    )


def _parse_legacy_sufficiency_segment(raw: str, segment_start: int, segment: str) -> CompactSufficiencyDecision | None:
    if _is_example_output_segment(raw, segment_start, segment):
        return None
    judge_m = _LEGACY_CONTEXT_SUFFICIENT_RE.search(segment)
    need_m = _LEGACY_NEED_CONTEXT_RE.search(segment)
    if not (judge_m and need_m):
        return None
    requested_symbols = _split_requested_symbols(need_m.group(1))
    return CompactSufficiencyDecision(
        judge=judge_m.group(1).strip().lower(),
        requested_symbols=requested_symbols,
        block=segment[judge_m.start() : need_m.end()].strip(),
    )


def extract_last_detection_decision(raw: str) -> CompactDetectionDecision | None:
    return _extract_last_detection_decision(raw, require_complete_why_line=False)


def _extract_last_detection_decision(raw: str, *, require_complete_why_line: bool) -> CompactDetectionDecision | None:
    judge_matches = list(_JUDGE_RE.finditer(raw))
    if not judge_matches:
        return None
    for idx in range(len(judge_matches) - 1, -1, -1):
        start = judge_matches[idx].start()
        end = judge_matches[idx + 1].start() if idx + 1 < len(judge_matches) else len(raw)
        parsed = _parse_detection_segment(
            raw,
            start,
            raw[start:end],
            require_complete_why_line=require_complete_why_line,
        )
        if parsed is not None:
            return parsed
    return None


def extract_last_sufficiency_decision(raw: str) -> CompactSufficiencyDecision | None:
    return _extract_last_sufficiency_decision(raw, require_complete_function_line=False)


def _extract_last_sufficiency_decision(
    raw: str,
    *,
    require_complete_function_line: bool,
) -> CompactSufficiencyDecision | None:
    judge_matches = list(_JUDGE_RE.finditer(raw))
    for idx in range(len(judge_matches) - 1, -1, -1):
        start = judge_matches[idx].start()
        end = judge_matches[idx + 1].start() if idx + 1 < len(judge_matches) else len(raw)
        parsed = _parse_sufficiency_segment(
            raw,
            start,
            raw[start:end],
            require_complete_function_line=require_complete_function_line,
        )
        if parsed is not None:
            return parsed

    legacy_matches = list(_LEGACY_CONTEXT_SUFFICIENT_RE.finditer(raw))
    for idx in range(len(legacy_matches) - 1, -1, -1):
        start = legacy_matches[idx].start()
        end = legacy_matches[idx + 1].start() if idx + 1 < len(legacy_matches) else len(raw)
        parsed = _parse_legacy_sufficiency_segment(raw, start, raw[start:end])
        if parsed is not None:
            return parsed
    return None


def extract_complete_sane_detection_block(raw: str) -> str | None:
    decision = _extract_last_detection_decision(raw, require_complete_why_line=True)
    if decision is None:
        return None
    vuln_types = [item.strip() for item in re.split(r"[;,]", decision.vuln_type) if item.strip()]
    if decision.judge == "yes":
        if not vuln_types or not all(re.fullmatch(r"CWE-\d+", item, flags=re.IGNORECASE) for item in vuln_types):
            return None
    elif decision.vuln_type.strip().upper() != "N/A":
        return None
    if "#why:" not in decision.block and decision.judge == "yes":
        return None
    return decision.block


def extract_complete_sane_sufficiency_block(raw: str) -> str | None:
    decision = _extract_last_sufficiency_decision(raw, require_complete_function_line=True)
    return None if decision is None else decision.block


def extract_complete_sane_compact_block(
    raw: str,
    *,
    allow_early_negative_without_context: bool = False,
    require_clean_prefix_for_early_negative: bool = False,
) -> str | None:
    del allow_early_negative_without_context
    del require_clean_prefix_for_early_negative
    return extract_complete_sane_detection_block(raw)


def extract_legacy_requested_symbols(raw: str) -> list[str]:
    decision = extract_last_sufficiency_decision(raw)
    if decision is not None:
        return decision.requested_symbols
    legacy = extract_last_detection_decision(raw)
    if legacy is None:
        return []
    need_ctx_m = _LEGACY_NEED_CONTEXT_RE.search(legacy.block)
    if need_ctx_m is None:
        need_ctx_m = _LEGACY_NEED_CONTEXT_RE.search(raw)
    if need_ctx_m is None:
        return []
    return _split_requested_symbols(need_ctx_m.group(1))

from __future__ import annotations

import re
from dataclasses import dataclass


_JUDGE_RE = re.compile(r"(?im)^\s*#judge:\s*(yes|no)\s*$")
_TYPE_RE = re.compile(r"(?im)^\s*#type:\s*([^\n\r]+)\s*$")
_CONFIDENCE_RE = re.compile(r"(?im)^\s*#confidence:\s*(low|medium|high)\s*$")
_NEED_CONTEXT_RE = re.compile(r"(?im)^\s*#need_context:\s*([^\n\r]+)\s*$")
_WHY_RE = re.compile(r"(?im)^\s*#why:\s*([^\n\r]+)\s*$")


@dataclass(frozen=True)
class CompactDecision:
    judge: str
    vuln_type: str
    confidence_label: str
    need_context_symbols: list[str]
    why: str
    block: str

    @property
    def is_negative_without_context_request(self) -> bool:
        return self.judge == "no" and not self.need_context_symbols and self.vuln_type.upper() == "N/A"


def _is_example_output_segment(raw: str, segment_start: int, segment: str) -> bool:
    prefix = raw[:segment_start]
    prev_lines = [line.strip().lower() for line in prefix.splitlines() if line.strip()]
    if prev_lines and prev_lines[-1].startswith("example output"):
        return True
    return "example output" in segment.lower()


def _is_placeholder_value(*, vuln_type: str, need_context: str, why: str) -> bool:
    if "|" in vuln_type:
        return True
    if vuln_type.strip().lower() == "cwe-xx":
        return True
    if need_context.strip().lower() in {"n/a|symbol_a,symbol_b", "symbol_name"}:
        return True
    if why.strip().lower() in {"one short sentence", "short explanation"}:
        return True
    return False


def _parse_compact_decision_segment(
    raw: str,
    segment_start: int,
    segment: str,
    *,
    require_complete_why_line: bool,
    allow_early_negative_without_context: bool,
    require_clean_prefix_for_early_negative: bool,
) -> CompactDecision | None:
    if _is_example_output_segment(raw, segment_start, segment):
        return None

    judge_m = _JUDGE_RE.search(segment)
    type_m = _TYPE_RE.search(segment)
    conf_m = _CONFIDENCE_RE.search(segment)
    need_ctx_m = _NEED_CONTEXT_RE.search(segment)
    if not (judge_m and type_m and conf_m and need_ctx_m):
        return None

    judge = judge_m.group(1).strip().lower()
    vuln_type = type_m.group(1).strip()
    confidence_label = conf_m.group(1).strip().lower()
    need_context = need_ctx_m.group(1).strip()
    need_context_symbols = (
        [x.strip() for x in need_context.split(",") if x.strip()] if need_context and need_context.upper() != "N/A" else []
    )

    early_negative = (
        allow_early_negative_without_context
        and judge == "no"
        and vuln_type.upper() == "N/A"
        and need_context.strip().upper() == "N/A"
        and not need_context_symbols
    )
    if early_negative and require_clean_prefix_for_early_negative and raw[:segment_start].strip():
        # Do not terminate early if the model already emitted preamble/thinking text.
        # In that case, wait for a complete compact block with #why.
        early_negative = False

    why_m = _WHY_RE.search(segment)
    if why_m is None:
        if not early_negative:
            return None
        why = "Model judged no vulnerability and requested no additional context."
        end_idx = need_ctx_m.end()
    else:
        why = why_m.group(1).strip()
        if not why:
            if not early_negative:
                return None
            why = "Model judged no vulnerability and requested no additional context."
        if require_complete_why_line and why_m.end() >= len(segment) and not early_negative:
            return None
        end_idx = why_m.end()

    if _is_placeholder_value(vuln_type=vuln_type, need_context=need_context, why=why):
        return None

    return CompactDecision(
        judge=judge,
        vuln_type=vuln_type,
        confidence_label=confidence_label,
        need_context_symbols=need_context_symbols,
        why=why,
        block=segment[judge_m.start() : end_idx].strip(),
    )


def extract_last_compact_decision(
    raw: str,
    *,
    require_complete_why_line: bool = True,
    allow_early_negative_without_context: bool = False,
    require_clean_prefix_for_early_negative: bool = False,
) -> CompactDecision | None:
    judge_matches = list(_JUDGE_RE.finditer(raw))
    if not judge_matches:
        return None

    for idx in range(len(judge_matches) - 1, -1, -1):
        start = judge_matches[idx].start()
        end = judge_matches[idx + 1].start() if idx + 1 < len(judge_matches) else len(raw)
        parsed = _parse_compact_decision_segment(
            raw,
            start,
            raw[start:end],
            require_complete_why_line=require_complete_why_line,
            allow_early_negative_without_context=allow_early_negative_without_context,
            require_clean_prefix_for_early_negative=require_clean_prefix_for_early_negative,
        )
        if parsed is not None:
            return parsed
    return None


def extract_complete_sane_compact_block(
    raw: str,
    *,
    allow_early_negative_without_context: bool = False,
    require_clean_prefix_for_early_negative: bool = False,
) -> str | None:
    decision = extract_last_compact_decision(
        raw,
        require_complete_why_line=True,
        allow_early_negative_without_context=allow_early_negative_without_context,
        require_clean_prefix_for_early_negative=require_clean_prefix_for_early_negative,
    )
    return None if decision is None else decision.block


def compact_decision_to_payload(decision: CompactDecision) -> dict:
    confidence = {"low": 0.5, "medium": 0.7, "high": 0.9}.get(decision.confidence_label, 0.7)
    if decision.judge == "no":
        return {
            "need_context_symbols": decision.need_context_symbols,
            "vulnerabilities": [],
        }

    vuln_type = decision.vuln_type
    if vuln_type.upper() == "N/A":
        vuln_type = "Potential Vulnerability"
    cwe = vuln_type.upper() if vuln_type.upper().startswith("CWE-") else ""
    return {
        "need_context_symbols": decision.need_context_symbols,
        "vulnerabilities": [
            {
                "vulnerability_type": vuln_type,
                "severity": "medium",
                "confidence": confidence,
                "description": decision.why,
                "reasoning": decision.why,
                "recommendation": "Manually review and confirm exploitability.",
                "references": [cwe] if cwe else [],
            }
        ],
    }

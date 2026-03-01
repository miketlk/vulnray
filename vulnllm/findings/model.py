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
    claim: str = ""
    precondition: str = ""
    where_precondition_is_enforced: str = "none"
    trigger_path: str = ""
    exploitability: str = "theoretical"
    contract_breach_evidence: bool = False
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
    best_any: dict | None = None
    best_scored: tuple[int, dict] | None = None

    def score_obj(obj: dict) -> int:
        score = 0
        final_answer = obj.get("final_answer")
        if isinstance(final_answer, dict):
            if isinstance(final_answer.get("judge"), str):
                score += 8
            if isinstance(final_answer.get("type"), str):
                score += 8
        vulns = obj.get("vulnerabilities")
        if isinstance(vulns, list):
            score += 20
            score += min(len(vulns), 5)
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                for key in (
                    "vulnerability_type",
                    "severity",
                    "confidence",
                    "description",
                    "reasoning",
                    "recommendation",
                    "references",
                ):
                    if key in v:
                        score += 1
        return score
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
            if best_any is None:
                best_any = obj
            score = score_obj(obj)
            if best_scored is None or score > best_scored[0]:
                best_scored = (score, obj)
        idx += 1

    if best_scored is not None:
        return best_scored[1]
    if best_any is not None:
        return best_any
    repaired = _repair_json_payload(raw)
    if repaired is not None:
        return repaired
    raise ValueError("No JSON object found")


def _repair_json_payload(raw: str) -> dict | None:
    text = raw.strip()
    if not text:
        return None

    if "```" in text:
        text = re.sub(r"```(?:json)?", "", text, flags=re.IGNORECASE).replace("```", "").strip()
    if not text:
        return None

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    candidate = text[start : end + 1]
    # Conservative local repair for common tailing-comma JSON issues.
    candidate = re.sub(r",(\s*[}\]])", r"\1", candidate)
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


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


def extract_decision_metadata(raw: str) -> tuple[list[str], list[str]]:
    try:
        obj = _extract_json(raw)
    except Exception:
        return [], []
    candidate_cwes = obj.get("candidate_cwes", [])
    missing_context_symbols = obj.get("missing_context_symbols", [])
    cwes = [str(x).strip().upper() for x in candidate_cwes if str(x).strip()]
    symbols = [str(x).strip() for x in missing_context_symbols if str(x).strip()]
    return cwes, symbols


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
                claim=str(v.get("claim", "")),
                precondition=str(v.get("precondition", "")),
                where_precondition_is_enforced=str(v.get("where_precondition_is_enforced", "none") or "none"),
                trigger_path=str(v.get("trigger_path", "")),
                exploitability=_normalize_exploitability(v.get("exploitability", "theoretical")),
                contract_breach_evidence=_parse_bool(v.get("contract_breach_evidence"), default=False),
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

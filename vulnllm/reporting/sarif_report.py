from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from vulnllm import __version__
from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.reporting.summary import build_summary
from vulnllm.utils.hashing import sha256_text

_SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
_CWE_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)


def _to_utc_iso(dt: datetime) -> str:
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.isoformat().replace("+00:00", "Z")


def _relative_uri(path_text: str) -> str:
    return path_text.replace("\\", "/").lstrip("/")


def _severity_to_level(severity: str) -> str:
    normalized = str(severity or "").strip().lower()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized == "medium":
        return "warning"
    return "note"


def _severity_rank(severity: str) -> int:
    normalized = str(severity or "").strip().lower()
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(normalized, 0)


def _select_rule_id(finding: Finding) -> str:
    vuln_match = _CWE_RE.search(finding.vulnerability_type or "")
    if vuln_match:
        return f"CWE-{vuln_match.group(1)}"
    for ref in finding.references:
        ref_match = _CWE_RE.search(str(ref))
        if ref_match:
            return f"CWE-{ref_match.group(1)}"
    slug = re.sub(r"[^a-z0-9]+", "-", (finding.vulnerability_type or "").strip().lower()).strip("-")
    return slug or "rule"


def _message_text(finding: Finding) -> str:
    recommendation = finding.recommendation or "Review the surrounding contract and fix the unsafe path."
    location = f"{finding.file}:{finding.start_line}-{finding.end_line}"
    return f"{finding.vulnerability_type} in {location}. {finding.description} Recommendation: {recommendation}"


def _message_markdown(finding: Finding, *, include_reasoning: bool) -> str:
    lines = [
        "### Description",
        finding.description or "N/A",
        "",
        "### Claim",
        finding.claim or "N/A",
        "",
        "### Precondition",
        finding.precondition or "N/A",
        "",
        "### Enforcement",
        finding.where_precondition_is_enforced or "none",
        "",
        "### Trigger Path",
        finding.trigger_path or "N/A",
        "",
        "### Recommendation",
        finding.recommendation or "Review the surrounding contract and fix the unsafe path.",
    ]
    if include_reasoning:
        lines.extend(["", "### Reasoning", finding.reasoning or "N/A"])
    return "\n".join(lines)


def _result_properties(finding: Finding, *, include_reasoning: bool) -> dict[str, object]:
    props: dict[str, object] = {
        "vulnrayFindingId": finding.id,
        "vulnraySeverity": finding.severity,
        "vulnrayConfidence": finding.confidence,
        "vulnrayFunction": finding.function,
        "vulnrayReferences": list(finding.references),
        "vulnrayRecommendation": finding.recommendation,
        "vulnrayClaim": finding.claim,
        "vulnrayPrecondition": finding.precondition,
        "vulnrayWherePreconditionIsEnforced": finding.where_precondition_is_enforced,
        "vulnrayTriggerPath": finding.trigger_path,
        "vulnrayExploitability": finding.exploitability,
        "vulnrayContractBreachEvidence": finding.contract_breach_evidence,
        "vulnrayAttackerControlledInput": finding.attacker_controlled_input,
        "vulnrayBoundsContradictionEvidence": finding.bounds_contradiction_evidence,
        "vulnrayAnalysisMode": finding.analysis_mode,
        "vulnrayEvidenceSpans": finding.evidence_spans,
        "vulnrayRequiresCallerViolation": finding.requires_caller_violation,
        "vulnrayContextSufficiency": finding.context_sufficiency,
    }
    if include_reasoning:
        props["vulnrayReasoning"] = finding.reasoning
    return props


def _partial_fingerprints(rule_id: str, finding: Finding) -> dict[str, str]:
    primary_text = f"{rule_id}|{finding.file}|{finding.start_line}|{finding.end_line}"
    logical_text = (
        f"{rule_id}|{finding.file}|{finding.function or ''}|{finding.claim}|"
        f"{finding.precondition}|{finding.trigger_path}"
    )
    return {
        "vulnray/primaryLocationLineHash/v1": sha256_text(primary_text),
        "vulnray/logicalIdentityHash/v1": sha256_text(logical_text),
    }


def _build_rules(findings: list[Finding]) -> list[dict[str, object]]:
    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        rule_id = _select_rule_id(finding)
        by_rule.setdefault(rule_id, []).append(finding)

    rules: list[dict[str, object]] = []
    for rule_id in sorted(by_rule):
        grouped = by_rule[rule_id]
        representative = grouped[0]
        top_severity = max(grouped, key=lambda f: _severity_rank(f.severity)).severity
        rule: dict[str, object] = {
            "id": rule_id,
            "name": representative.vulnerability_type,
            "shortDescription": {"text": representative.vulnerability_type},
            "fullDescription": {"text": representative.description or representative.vulnerability_type},
            "defaultConfiguration": {"level": _severity_to_level(top_severity)},
        }
        cwe_match = _CWE_RE.fullmatch(rule_id)
        if cwe_match:
            rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_match.group(1)}.html"
        rules.append(rule)
    return rules


def _build_artifacts(findings: list[Finding]) -> tuple[list[dict[str, object]], dict[str, int]]:
    uris = sorted({_relative_uri(f.file) for f in findings})
    artifacts: list[dict[str, object]] = []
    indexes: dict[str, int] = {}
    for idx, uri in enumerate(uris):
        indexes[uri] = idx
        artifacts.append({"location": {"uri": uri, "uriBaseId": "SRCROOT"}})
    return artifacts, indexes


def _build_results(
    findings: list[Finding],
    *,
    include_reasoning: bool,
    rule_indexes: dict[str, int],
    artifact_indexes: dict[str, int],
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for finding in findings:
        rule_id = _select_rule_id(finding)
        file_uri = _relative_uri(finding.file)
        location: dict[str, object] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": file_uri,
                    "uriBaseId": "SRCROOT",
                    "index": artifact_indexes[file_uri],
                },
                "region": {"startLine": finding.start_line, "endLine": finding.end_line},
            }
        }
        if finding.function:
            location["logicalLocations"] = [{"fullyQualifiedName": finding.function, "kind": "function"}]

        message: dict[str, str] = {"text": _message_text(finding)}
        if include_reasoning:
            message["markdown"] = _message_markdown(finding, include_reasoning=include_reasoning)

        results.append(
            {
                "ruleId": rule_id,
                "rule": {"index": rule_indexes[rule_id]},
                "level": _severity_to_level(finding.severity),
                "kind": "fail",
                "message": message,
                "locations": [location],
                "partialFingerprints": _partial_fingerprints(rule_id, finding),
                "properties": _result_properties(finding, include_reasoning=include_reasoning),
            }
        )
    return results


def _original_uri_base_ids(repo_root: str) -> dict[str, dict[str, object]]:
    root_uri = Path(repo_root).resolve().as_uri().rstrip("/") + "/"
    return {"SRCROOT": {"uri": root_uri, "description": {"text": "Scan root for this vulnray run."}}}


def write_sarif_report(
    path: Path,
    cfg: Config,
    repo_root: str,
    files_scanned: int,
    chunks_analyzed: int,
    findings: list[Finding],
    *,
    include_reasoning: bool = True,
    command_line: str,
    start_time_utc: datetime,
    end_time_utc: datetime,
    execution_successful: bool,
    failed_chunks: int,
) -> None:
    filtered = [f for f in findings if f.vulnerability_type != "ParserError"]
    rules = _build_rules(filtered)
    rule_indexes = {rule["id"]: idx for idx, rule in enumerate(rules)}
    artifacts, artifact_indexes = _build_artifacts(filtered)
    summary = build_summary(filtered)

    invocation: dict[str, object] = {
        "commandLine": command_line,
        "startTimeUtc": _to_utc_iso(start_time_utc),
        "endTimeUtc": _to_utc_iso(end_time_utc),
        "executionSuccessful": execution_successful,
    }
    if failed_chunks > 0:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "warning",
                "message": {
                    "text": (
                        f"vulnray skipped {failed_chunks} chunks due to inference or parsing failures; "
                        "results may be incomplete."
                    )
                },
            }
        ]

    run = {
        "tool": {
            "driver": {
                "name": "vulnray",
                "fullName": f"vulnray {__version__}",
                "semanticVersion": __version__,
                "rules": rules,
            }
        },
        "language": "en-US",
        "invocations": [invocation],
        "originalUriBaseIds": _original_uri_base_ids(repo_root),
        "artifacts": artifacts,
        "results": _build_results(
            filtered,
            include_reasoning=include_reasoning,
            rule_indexes=rule_indexes,
            artifact_indexes=artifact_indexes,
        ),
        "properties": {
            "vulnrayRepoRoot": repo_root,
            "vulnrayModel": cfg.inference.model,
            "vulnrayMode": cfg.scan.mode,
            "vulnrayFilesScanned": files_scanned,
            "vulnrayChunksAnalyzed": chunks_analyzed,
            "vulnrayFailedChunks": failed_chunks,
            "vulnrayTotalFindings": summary["total_findings"],
            "vulnrayBySeverity": summary["by_severity"],
        },
    }

    payload = {"version": "2.1.0", "$schema": _SCHEMA_URI, "runs": [run]}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

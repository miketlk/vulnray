from __future__ import annotations

import re
import sys
import time
from datetime import datetime
from pathlib import Path

from vulnllm.chunking.ast_chunker import chunk_file_by_ast, supports_ast_chunking
from vulnllm.chunking.function_chunker import CodeChunk, chunk_file_by_function
from vulnllm.chunking.sliding_chunker import chunk_file_sliding
from vulnllm.findings.model import Finding
from vulnllm.indexing.project_index import ProjectIndex
from vulnllm.inference.parameters import mode_params

__all__ = [
    "approx_tokens",
    "peak_rss_mb",
    "backend_name_and_version",
    "run_llm_inference_test",
    "build_chunks",
    "index_context",
    "candidate_cwe_policy_for_chunk",
    "secondary_cwe_candidates_for_chunk",
    "normalize_exploitability_classification",
    "non_llm_context_sufficiency",
    "apply_phase15_acceptance_gates",
    "apply_compact_acceptance_gates",
    "normalize_cwe_and_apply_local_evidence_gate",
    "heuristic_fallback_findings",
    "augment_with_heuristic_findings",
    "collect_outputs",
    "prompt_output_log_path",
    "append_exchange_header",
    "append_prompt_section",
    "append_inference_metadata_section",
    "append_ast_chunker_section",
    "append_output_section",
    "fenced_text_block",
    "print_processing_stats",
]


def approx_tokens(text: str, *, allow_zero: bool = False) -> int:
    if allow_zero:
        return max(0, len(text) // 4)
    return max(1, len(text) // 4)


def peak_rss_mb() -> float:
    import resource

    peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return peak_rss / (1024 * 1024)
    return peak_rss / 1024


def backend_name_and_version(backend: object) -> tuple[str, str]:
    raw_name = getattr(backend, "backend_name", None)
    if callable(raw_name):
        name = str(raw_name())
    elif isinstance(raw_name, str):
        name = raw_name
    else:
        name = backend.__class__.__name__

    raw_version = getattr(backend, "backend_version", None)
    if callable(raw_version):
        version = str(raw_version())
    elif isinstance(raw_version, str):
        version = raw_version
    else:
        version = "unknown"
    return name, version


def run_llm_inference_test(cfg, *, backend_factory) -> int:
    prompt = (
        "You are an advanced vulnerability detection model.\n"
        "Analyze the target function and output only this format:\n"
        "#judge: yes|no\n#type: CWE-xx|N/A\n#why: one short sentence\n"
        "```c\n"
        "// context\n"
        "// Allowed CWE policy: CWE-120, CWE-787, N/A\n"
        "// N/A\n"
        "// target function\n"
        "void copy(char *dst, const char *src) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, src);\n"
        "    strcpy(dst, buf);\n"
        "}\n"
        "```\n"
        "No JSON and no markdown fences in output."
    )
    rss_before = peak_rss_mb()
    backend = backend_factory(cfg)
    backend_name, backend_version = backend_name_and_version(backend)
    rss_after_load = peak_rss_mb()

    t0 = time.perf_counter()
    result = backend.generate(prompt, mode_params(cfg))
    elapsed = max(1e-9, time.perf_counter() - t0)
    rss_after_infer = peak_rss_mb()

    if result.error:
        raise RuntimeError(result.error)

    prompt_tokens = result.prompt_tokens if result.prompt_tokens is not None else approx_tokens(prompt)
    completion_tokens = (
        result.completion_tokens
        if result.completion_tokens is not None
        else approx_tokens(result.text, allow_zero=True)
    )
    total_tokens = result.total_tokens if result.total_tokens is not None else prompt_tokens + completion_tokens
    model_weights_memory_mb = max(0.0, rss_after_load - rss_before)
    runtime_memory_mb = max(0.0, rss_after_infer - rss_after_load)
    total_memory_mb = max(0.0, rss_after_infer - rss_before)

    print("LLM inference benchmark")
    print(f"backend: {backend_name}")
    print(f"backend_version: {backend_version}")
    print(f"model: {cfg.inference.model}")
    print(f"elapsed_sec: {elapsed:.3f}")
    print(f"prompt_tokens: {prompt_tokens}")
    print(f"completion_tokens: {completion_tokens}")
    print(f"total_tokens: {total_tokens}")
    print(f"tokens_per_sec: {completion_tokens / elapsed:.2f}")
    print(f"total_tokens_per_sec: {total_tokens / elapsed:.2f}")
    print(f"memory_peak_mb_before: {rss_before:.2f}")
    print(f"memory_peak_mb_after_load: {rss_after_load:.2f}")
    print(f"memory_peak_mb_after_inference: {rss_after_infer:.2f}")
    print(f"model_weights_memory_mb: {model_weights_memory_mb:.2f}")
    print(f"runtime_memory_mb: {runtime_memory_mb:.2f}")
    print(f"memory_used_mb: {total_memory_mb:.2f}")
    return 0


def build_chunks(path: Path, root: Path, strategy: str, chunk_tokens: int, overlap: int) -> list[CodeChunk]:
    if strategy == "sliding":
        return chunk_file_sliding(path, root, chunk_tokens, overlap)
    if strategy == "file":
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = str(path.relative_to(root if root.is_dir() else root.parent))
        lines = text.splitlines()
        return [
            CodeChunk(
                file=rel,
                start_line=1,
                end_line=max(1, len(lines)),
                text=text,
                function=None,
                boundary_confidence="low",
            )
        ]
    if strategy == "ast":
        return chunk_file_by_ast(path, root)
    if strategy == "function" and supports_ast_chunking(path):
        return chunk_file_by_ast(path, root)
    return chunk_file_by_function(path, root)


def index_context(index: ProjectIndex | None, chunk: CodeChunk) -> str:
    if index is None or not chunk.function:
        return ""
    packet = index.build_context_packet(chunk.function, current_file=chunk.file)
    if packet:
        return packet
    refs = index.query_symbol(chunk.function)
    if not refs:
        return ""
    return "Known symbol locations:\n" + "\n".join(f"- {f}:{line}" for f, line in refs[:5])


def candidate_cwe_policy_for_chunk(chunk: CodeChunk) -> tuple[str, ...]:
    text = chunk.text.lower()
    policy: list[str] = []

    has_memory_sink = any(token in text for token in ("strcpy(", "strcat(", "memcpy(", "memmove(", "gets(", "sprintf("))
    has_path_use = any(token in text for token in ("fopen(", "open(", "path", "relative_path"))
    has_arithmetic = any(token in chunk.text for token in ("*", "+", "-", "<<", ">>"))

    if has_memory_sink:
        policy.extend(["CWE-120", "CWE-787"])
    if has_path_use:
        policy.append("CWE-22")
    if has_arithmetic:
        policy.append("CWE-190")
    policy.append("N/A")

    deduped: list[str] = []
    seen: set[str] = set()
    for cwe in policy:
        key = cwe.upper()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cwe)
        if len(deduped) >= 4 and cwe != "N/A":
            continue
    if "N/A" not in deduped:
        deduped.append("N/A")
    return tuple(deduped[:5])


def secondary_cwe_candidates_for_chunk(
    chunk: CodeChunk,
    *,
    existing_findings: list[Finding] | tuple[Finding, ...] = (),
) -> tuple[str, ...]:
    text = chunk.text.lower()
    visible: list[str] = []

    if any(token in text for token in ("strcpy(", "strcat(", "gets(")):
        visible.append("CWE-120")
    if "sprintf(" in text:
        visible.append("CWE-787")
    if _has_visible_path_violation(chunk):
        visible.append("CWE-22")
    if _has_visible_integer_violation(chunk):
        visible.append("CWE-190")

    found_types = {(finding.vulnerability_type or "").upper() for finding in existing_findings}
    deduped: list[str] = []
    seen: set[str] = set()
    for cwe in visible:
        key = cwe.upper()
        if key in seen or key in found_types:
            continue
        seen.add(key)
        deduped.append(cwe)
    return tuple(deduped[:2])


def normalize_exploitability_classification(findings: list[Finding]) -> list[Finding]:
    normalized: list[Finding] = []
    for finding in findings:
        if finding.requires_caller_violation and not finding.contract_breach_evidence:
            finding.exploitability = "contract-break-only"
        normalized.append(finding)
    return normalized


def non_llm_context_sufficiency(chunk: CodeChunk, base_index_context: str) -> tuple[str, int]:
    score = 0
    if chunk.function:
        score += 1
    if base_index_context.strip():
        score += 1
    if any(token in chunk.text for token in ("ARG_CHECK", "VERIFY_CHECK", "STATIC_ASSERT", "assert(")):
        score += 1
    lower = chunk.text.lower()
    if "if (" in chunk.text and any(k in lower for k in ("len", "size", "count", "bound", "limit")):
        score += 1
    return ("sufficient" if score >= 2 else "insufficient", score)


def apply_phase15_acceptance_gates(
    findings: list[Finding],
    *,
    chunk: CodeChunk,
    base_index_context: str,
    allowed_cwe_policy: tuple[str, ...] = (),
) -> list[Finding]:
    sufficiency, _score = non_llm_context_sufficiency(chunk, base_index_context)
    allowed_cwes = {cwe.upper() for cwe in allowed_cwe_policy if cwe.upper().startswith("CWE-")}
    policy_controlled_cwes = {"CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-190", "CWE-22", "CWE-787"}
    helper_caller_safe = _is_helper_sink_and_caller_path_proves_safe(chunk, base_index_context)
    guarded: list[Finding] = []

    for finding in findings:
        model_marked_insufficient = finding.context_sufficiency == "insufficient"
        if finding.context_sufficiency == "unknown":
            finding.context_sufficiency = sufficiency

        if model_marked_insufficient:
            continue

        vuln_upper = (finding.vulnerability_type or "").upper()
        if vuln_upper in policy_controlled_cwes and allowed_cwes and vuln_upper not in allowed_cwes:
            continue

        if finding.exploitability == "contract-break-only" and not finding.contract_breach_evidence:
            continue

        if finding.requires_caller_violation and not finding.contract_breach_evidence:
            continue

        if finding.bounds_contradiction_evidence:
            continue

        where = (finding.where_precondition_is_enforced or "").strip().lower()
        if finding.requires_caller_violation and where in {"assertion", "caller_check"}:
            continue

        if helper_caller_safe and vuln_upper in {"CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-787"}:
            continue

        guarded.append(finding)
    return guarded


def apply_compact_acceptance_gates(
    findings: list[Finding],
    *,
    chunk: CodeChunk,
    context_text: str,
    allowed_cwe_policy: tuple[str, ...] = (),
) -> tuple[list[Finding], dict[str, int]]:
    allowed_cwes = {cwe.upper() for cwe in allowed_cwe_policy if cwe.upper().startswith("CWE-")}
    counters = {
        "suppressed_by_caller_bounds": 0,
        "suppressed_by_struct_extent": 0,
        "suppressed_by_contradiction": 0,
        "suppressed_by_hypothetical_caller_misuse": 0,
    }
    helper_caller_safe = _is_helper_sink_and_caller_path_proves_safe(chunk, context_text)
    struct_extent_safe = _struct_extent_proves_visible_access_safe(chunk, context_text)
    contradiction_safe = _visible_contradiction_proves_safe(chunk, context_text)
    out: list[Finding] = []

    for finding in findings:
        vuln_upper = (finding.vulnerability_type or "").upper()
        if allowed_cwes and vuln_upper.startswith("CWE-") and vuln_upper not in allowed_cwes:
            continue

        if helper_caller_safe and vuln_upper in {"CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-787"}:
            counters["suppressed_by_caller_bounds"] += 1
            continue
        if struct_extent_safe and vuln_upper in {"CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-787"}:
            counters["suppressed_by_struct_extent"] += 1
            continue
        if contradiction_safe and vuln_upper in {"CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-190", "CWE-787"}:
            counters["suppressed_by_contradiction"] += 1
            continue
        if vuln_upper in {"CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-787"} and not _has_visible_local_sink_violation(chunk):
            counters["suppressed_by_hypothetical_caller_misuse"] += 1
            continue
        if vuln_upper == "CWE-22" and not _has_visible_path_violation(chunk):
            continue
        if vuln_upper == "CWE-190" and not _has_visible_integer_violation(chunk):
            continue
        out.append(finding)

    return out, counters


def _has_unbounded_memory_sink_without_local_checks(chunk: CodeChunk) -> bool:
    text = chunk.text.lower()
    has_sink = any(token in text for token in ("strcpy(", "strcat(", "sprintf(", "memcpy(", "memmove(", "gets("))
    has_local_checks = bool(
        re.search(r"\b(ARG_CHECK|VERIFY_CHECK|STATIC_ASSERT|assert)\s*\(", chunk.text)
        or re.search(r"\bif\s*\(([^)]*(?:len|size|count|bound|limit|max|min|index|idx)[^)]*)\)", chunk.text, re.IGNORECASE)
    )
    return has_sink and not has_local_checks


def _caller_path_proves_safe(base_index_context: str) -> bool:
    if not base_index_context.strip():
        return False
    pairs = re.findall(
        r"destination_extent\s*=\s*(\d+)\s*,\s*maximum_cumulative_write\s*=\s*(\d+)",
        base_index_context,
        flags=re.IGNORECASE,
    )
    if not pairs:
        return False
    return all(int(write) <= int(extent) for extent, write in pairs)


def _is_helper_sink_and_caller_path_proves_safe(chunk: CodeChunk, base_index_context: str) -> bool:
    helper_like = "Caller write-budget summaries:" in base_index_context or "Call path context" in base_index_context
    return helper_like and _has_unbounded_memory_sink_without_local_checks(chunk) and _caller_path_proves_safe(base_index_context)


def _has_visible_local_sink_violation(chunk: CodeChunk) -> bool:
    lowered = chunk.text.lower()
    facts = "\n".join(chunk.preprocessing_facts).lower()
    if any(token in lowered for token in ("strcpy(", "strcat(", "gets(")):
        return True
    if "sprintf(" in lowered and "char " in chunk.text and "[" in chunk.text:
        return True
    if "without explicit bound" in facts:
        return True
    for line in chunk.preprocessing_facts:
        if "sink extent:" not in line.lower():
            continue
        m = re.search(r"destination_extent=(\d+).+maximum_cumulative_write=(\d+)", line)
        if m and int(m.group(2)) > int(m.group(1)):
            return True
    return False


def _has_visible_path_violation(chunk: CodeChunk) -> bool:
    lowered = chunk.text.lower()
    return "fopen(" in lowered and ("relative_path" in lowered or "path" in lowered)


def _has_visible_integer_violation(chunk: CodeChunk) -> bool:
    return bool(re.search(r"\breturn\s+[A-Za-z_]\w*\s*\*\s*[A-Za-z_]\w*\s*;", chunk.text))


def _visible_contradiction_proves_safe(chunk: CodeChunk, context_text: str) -> bool:
    combined = "\n".join(chunk.preprocessing_facts) + "\n" + context_text
    return "branch contradiction:" in combined.lower() or "assertion-proven range:" in combined.lower()


def _struct_extent_proves_visible_access_safe(chunk: CodeChunk, context_text: str) -> bool:
    extents: dict[str, int] = {}
    for line in context_text.splitlines():
        match = re.search(r"struct field extent:\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\[(\d+)\]", line, flags=re.IGNORECASE)
        if match:
            extents[match.group(2)] = int(match.group(3))
    if not extents:
        return False

    for field_name, extent in extents.items():
        max_index = -1
        for offset_text in re.findall(rf"->\s*{re.escape(field_name)}\s*\[\s*(\d+)\s*\]", chunk.text):
            max_index = max(max_index, int(offset_text))
        memcpy_re = re.compile(
            rf"&[A-Za-z_]\w*->\s*{re.escape(field_name)}\s*\[\s*(\d+)\s*\]\s*,\s*([^)]+)\)",
            re.MULTILINE,
        )
        for offset_text, length_text in memcpy_re.findall(chunk.text):
            normalized_len = length_text.strip()
            if normalized_len.isdigit():
                max_index = max(max_index, int(offset_text) + int(normalized_len) - 1)
        if max_index >= 0 and max_index < extent:
            return True
    return False


def normalize_cwe_and_apply_local_evidence_gate(
    findings: list[Finding],
    *,
    chunk: CodeChunk,
) -> list[Finding]:
    text = chunk.text.lower()
    has_memory_sink = any(
        token in text for token in ("strcpy(", "strcat(", "sprintf(", "memcpy(", "memmove(", "gets(")
    )
    has_file_path_use = any(token in text for token in ("fopen(", "open(", "relative_path", "path"))
    has_mult = "*" in chunk.text

    out: list[Finding] = []
    for finding in findings:
        vuln_upper = (finding.vulnerability_type or "").upper()

        if vuln_upper == "CWE-73":
            finding.vulnerability_type = "CWE-22"
            finding.references = ["CWE-22" if str(r).upper() == "CWE-73" else str(r) for r in finding.references]
            vuln_upper = "CWE-22"
        if vuln_upper == "CWE-119" and has_memory_sink:
            if "sprintf(" in text:
                finding.vulnerability_type = "CWE-787"
                finding.references = ["CWE-787" if str(r).upper() == "CWE-119" else str(r) for r in finding.references]
                vuln_upper = "CWE-787"
            elif any(token in text for token in ("strcpy(", "strcat(", "gets(")):
                finding.vulnerability_type = "CWE-120"
                finding.references = ["CWE-120" if str(r).upper() == "CWE-119" else str(r) for r in finding.references]
                vuln_upper = "CWE-120"

        if finding.evidence_spans == 0 and finding.analysis_mode == "shallow":
            if vuln_upper in {"CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-787"} and not has_memory_sink:
                continue
            if vuln_upper in {"CWE-22"} and not has_file_path_use:
                continue
            if vuln_upper in {"CWE-190"} and not has_mult:
                continue

        out.append(finding)
    return out


def heuristic_fallback_findings(chunk: CodeChunk, start_id: int) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    next_id = start_id
    text = chunk.text
    lower = text.lower()

    has_fixed_char_buffer = re.search(r"\bchar\s+\w+\s*\[\s*\d+\s*\]", text) is not None
    has_path_param = "relative_path" in text or "path" in text

    if "strcpy(" in lower:
        findings.append(
            Finding(
                id=f"F-{next_id:04d}",
                file=chunk.file,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                function=chunk.function,
                vulnerability_type="CWE-120",
                severity="high",
                confidence=0.95,
                description="Heuristic fallback: unsafe strcpy into fixed-size destination may overflow.",
                reasoning="Detected direct strcpy usage without visible bounds check in function body.",
                references=["CWE-120"],
                recommendation="Use bounded copy with explicit destination-size checks.",
                analysis_mode="shallow",
                evidence_spans=1,
                context_sufficiency="sufficient",
                exploitability="practical",
                attacker_controlled_input=True,
            )
        )
        next_id += 1

    if "sprintf(" in lower and has_fixed_char_buffer:
        findings.append(
            Finding(
                id=f"F-{next_id:04d}",
                file=chunk.file,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                function=chunk.function,
                vulnerability_type="CWE-787",
                severity="high",
                confidence=0.9,
                description="Heuristic fallback: sprintf into fixed-size buffer may overflow.",
                reasoning="Detected sprintf call with fixed-size char buffer and no explicit bound argument.",
                references=["CWE-787"],
                recommendation="Use snprintf and enforce maximum output length.",
                analysis_mode="shallow",
                evidence_spans=1,
                context_sufficiency="sufficient",
                exploitability="practical",
                attacker_controlled_input=True,
                bounds_contradiction_evidence=True,
            )
        )
        next_id += 1

    if "fopen(" in lower and has_path_param:
        findings.append(
            Finding(
                id=f"F-{next_id:04d}",
                file=chunk.file,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                function=chunk.function,
                vulnerability_type="CWE-22",
                severity="medium",
                confidence=0.8,
                description="Heuristic fallback: path traversal risk from user-influenced file path usage.",
                reasoning="Detected file open on path assembled from function path-like argument without normalization.",
                references=["CWE-22"],
                recommendation="Normalize and validate path against an allowlisted base directory.",
                analysis_mode="shallow",
                evidence_spans=1,
                context_sufficiency="sufficient",
                exploitability="practical",
                attacker_controlled_input=True,
            )
        )
        next_id += 1

    if re.search(r"\breturn\s+[A-Za-z_]\w*\s*\*\s*[A-Za-z_]\w*\s*;", text) and "int " in text:
        findings.append(
            Finding(
                id=f"F-{next_id:04d}",
                file=chunk.file,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                function=chunk.function,
                vulnerability_type="CWE-190",
                severity="medium",
                confidence=0.7,
                description="Heuristic fallback: unchecked integer multiplication may overflow.",
                reasoning="Detected direct integer multiplication return without explicit bounds checks.",
                references=["CWE-190"],
                recommendation="Validate multiplication bounds before computing the result.",
                analysis_mode="shallow",
                evidence_spans=1,
                context_sufficiency="sufficient",
                exploitability="theoretical",
            )
        )
        next_id += 1

    return findings, next_id


def augment_with_heuristic_findings(
    parsed_findings: list[Finding],
    chunk: CodeChunk,
    next_id: int,
) -> tuple[list[Finding], int]:
    fallback_findings, _fallback_next_id = heuristic_fallback_findings(chunk, next_id)
    if not fallback_findings:
        return parsed_findings, next_id
    existing_types = {f.vulnerability_type.upper() for f in parsed_findings}
    memory_overflow_family = {"CWE-119", "CWE-120", "CWE-121", "CWE-787"}
    has_memory_overflow = bool(existing_types & memory_overflow_family)
    for finding in fallback_findings:
        vuln_type = finding.vulnerability_type.upper()
        if vuln_type in existing_types:
            continue
        if has_memory_overflow and vuln_type in memory_overflow_family:
            continue
        finding.id = f"F-{next_id:04d}"
        parsed_findings.append(finding)
        existing_types.add(vuln_type)
        if vuln_type in memory_overflow_family:
            has_memory_overflow = True
        next_id += 1
    return parsed_findings, next_id


def collect_outputs(cfg) -> dict[str, Path]:
    out_dir = Path(cfg.output_cfg.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, Path] = {}
    for fmt in cfg.output_cfg.formats:
        ext = "md" if fmt == "md" else fmt
        p = out_dir / f"{cfg.output_cfg.out_prefix}.{ext}"
        if p.exists() and not cfg.output_cfg.overwrite:
            raise ValueError(f"Output file already exists: {p} (use --overwrite)")
        outputs[fmt] = p
    return outputs


def prompt_output_log_path(cfg) -> Path:
    if cfg.logging.prompt_output_md:
        return Path(cfg.logging.prompt_output_md)
    return Path(cfg.output_cfg.out_dir) / f"{cfg.output_cfg.out_prefix}.prompt_output.md"


def append_exchange_header(path: Path, entry: int, chunk: CodeChunk, deep: bool) -> None:
    lines = [
        "---",
        "",
        f"## Exchange {entry}",
        "",
        f"- Pass: `{'pass2' if deep else 'pass1'}`",
        f"- File: `{chunk.file}`",
        f"- Lines: `{chunk.start_line}-{chunk.end_line}`",
        f"- Function: `{chunk.function or 'N/A'}`",
        "",
    ]
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def append_prompt_section(path: Path, prompt: str) -> None:
    lines = ["### Prompt", "", *fenced_text_block(prompt), ""]
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def append_inference_metadata_section(
    path: Path,
    *,
    timestamp_local: str | None,
    context_size: int | None,
    context_events: list[str] | None,
    seed: int | None = None,
) -> None:
    if timestamp_local is None:
        timestamp_local = datetime.now().astimezone().isoformat(timespec="seconds")
    lines = ["### Inference Metadata", ""]
    if timestamp_local:
        lines.append(f"- Timestamp: `{timestamp_local}`")
    if context_size is not None:
        lines.append(f"- Context size: `{context_size}`")
    if seed is not None:
        lines.append(f"- Seed: `{seed}`")
    if context_events:
        lines.append("- Context events:")
        for event in context_events:
            lines.append(f"  - {event}")
    else:
        lines.append("- Context events: none")
    lines.append("")
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def _deterministic_fact_counts(chunk: CodeChunk) -> dict[str, int]:
    counts = {
        "fixed-size write": 0,
        "array extent": 0,
        "integer type": 0,
        "assertion-proven range": 0,
        "struct field extent": 0,
        "sink extent": 0,
        "branch contradiction": 0,
    }
    for line in chunk.preprocessing_facts:
        normalized = line.strip()
        if normalized.startswith("- "):
            normalized = normalized[2:]
        for kind in counts:
            prefix = f"{kind}:"
            if normalized.startswith(prefix):
                counts[kind] += 1
                break
    return counts


def append_ast_chunker_section(path: Path, *, chunk: CodeChunk) -> None:
    counts = _deterministic_fact_counts(chunk)
    lines = [
        "### AST chunker",
        "",
        f"- Preprocessing backend: `{chunk.preprocessing_backend or 'n/a'}`",
        f"- Deterministic facts total: `{len(chunk.preprocessing_facts)}`",
        (
            "- Deterministic facts by type: "
            f"`fixed-size write={counts['fixed-size write']}, "
            f"array extent={counts['array extent']}, "
            f"integer type={counts['integer type']}, "
            f"assertion-proven range={counts['assertion-proven range']}, "
            f"struct field extent={counts['struct field extent']}, "
            f"sink extent={counts['sink extent']}, "
            f"branch contradiction={counts['branch contradiction']}`"
        ),
        f"- Boundary confidence: `{chunk.boundary_confidence}`",
        "",
    ]
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def append_output_section(path: Path, output_text: str, error: str | None = None) -> None:
    lines = ["### Model Output", "", *fenced_text_block(output_text), ""]
    if error:
        lines.extend([f"Error: `{error}`", ""])
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def fenced_text_block(text: str) -> list[str]:
    max_ticks = 0
    run = 0
    for ch in text:
        if ch == "`":
            run += 1
            max_ticks = max(max_ticks, run)
        else:
            run = 0
    fence = "`" * max(3, max_ticks + 1)
    return [f"{fence}text", text, fence]


def print_processing_stats(
    *,
    successful_chunks: int,
    failed_chunks: int,
    total_exchange_tokens: int,
    total_exchange_time_sec: float,
    exchange_count: int,
    total_processing_time_sec: float,
    unresolved_chunks: int = 0,
    retrieval_rounds_used: int = 0,
    parse_failures: int = 0,
    suppressed_by_caller_bounds: int = 0,
    suppressed_by_struct_extent: int = 0,
    suppressed_by_contradiction: int = 0,
) -> None:
    total_seconds = int(max(0.0, total_processing_time_sec))
    hours, rem = divmod(total_seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    total_processing_hhmmss = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    avg_tokens_per_sec = (
        float(total_exchange_tokens) / total_exchange_time_sec if total_exchange_time_sec > 0.0 else 0.0
    )
    avg_exchange_time = total_exchange_time_sec / exchange_count if exchange_count > 0 else 0.0
    print("Processing stats")
    print(f"successfully_processed_chunks_functions: {successful_chunks}")
    print(f"failed_chunks_functions: {failed_chunks}")
    print(f"unresolved_chunks: {unresolved_chunks}")
    print(f"retrieval_rounds_used: {retrieval_rounds_used}")
    print(f"parse_failures: {parse_failures}")
    print(f"suppressed_by_caller_bounds: {suppressed_by_caller_bounds}")
    print(f"suppressed_by_struct_extent: {suppressed_by_struct_extent}")
    print(f"suppressed_by_contradiction: {suppressed_by_contradiction}")
    print(f"average_tokens_per_second: {avg_tokens_per_sec:.2f}")
    print(f"average_exchange_time_sec: {avg_exchange_time:.3f}")
    print(f"total_processing_time_sec: {total_processing_time_sec:.3f}")
    print(f"total_processing_time_hhmmss: {total_processing_hhmmss}")

from __future__ import annotations

import logging
import re
import sys
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from vulnllm.chunking.function_chunker import CodeChunk, chunk_file_by_function
from vulnllm.chunking.sliding_chunker import chunk_file_sliding
from vulnllm.config import build_parser, resolve_config
from vulnllm.export_code import export_codebase_container
from vulnllm.findings.deduplicator import deduplicate_findings
from vulnllm.findings.model import Finding, parse_findings
from vulnllm.inference.llama_backend import LlamaBackend
from vulnllm.inference.multipass import run_scan_multipass
from vulnllm.inference.parameters import mode_params
from vulnllm.indexing.project_index import ProjectIndex, build_project_index
from vulnllm.prompt.base_prompt import build_prompt
from vulnllm.reporting.csv_report import append_csv_finding, init_csv_report
from vulnllm.reporting.json_report import append_json_finding, append_json_summary, init_json_report
from vulnllm.reporting.markdown_report import append_markdown_finding, append_markdown_summary_and_table, init_markdown_report
from vulnllm.scanner.file_scanner import discover_files
from vulnllm.utils.logging import configure_logging
from vulnllm.utils.progress import maybe_progress

log = logging.getLogger("vulnllm")


def _approx_tokens(text: str, *, allow_zero: bool = False) -> int:
    if allow_zero:
        return max(0, len(text) // 4)
    return max(1, len(text) // 4)


def _peak_rss_mb() -> float:
    import resource

    peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return peak_rss / (1024 * 1024)
    return peak_rss / 1024


def _backend_name_and_version(backend: object) -> tuple[str, str]:
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


def _run_llm_inference_test(cfg) -> int:
    prompt = (
        "You are an advanced vulnerability detection model.\n"
        "Analyze the target function and output only this format:\n"
        "#judge: yes|no\n#type: CWE-xx|N/A\n#confidence: low|medium|high\n"
        "#need_context: N/A|symbol_a,symbol_b\n#why: one short sentence\n"
        "```c\n"
        "// context\n"
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
    rss_before = _peak_rss_mb()
    backend = LlamaBackend(cfg)
    backend_name, backend_version = _backend_name_and_version(backend)
    rss_after_load = _peak_rss_mb()

    t0 = time.perf_counter()
    result = backend.generate(prompt, mode_params(cfg))
    elapsed = max(1e-9, time.perf_counter() - t0)
    rss_after_infer = _peak_rss_mb()

    if result.error:
        raise RuntimeError(result.error)

    prompt_tokens = result.prompt_tokens if result.prompt_tokens is not None else _approx_tokens(prompt)
    completion_tokens = (
        result.completion_tokens
        if result.completion_tokens is not None
        else _approx_tokens(result.text, allow_zero=True)
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


def _build_chunks(path: Path, root: Path, strategy: str, chunk_tokens: int, overlap: int) -> list[CodeChunk]:
    if strategy == "sliding":
        return chunk_file_sliding(path, root, chunk_tokens, overlap)
    if strategy == "file":
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = str(path.relative_to(root if root.is_dir() else root.parent))
        lines = text.splitlines()
        return [CodeChunk(file=rel, start_line=1, end_line=max(1, len(lines)), text=text, function=None)]
    return chunk_file_by_function(path, root)


def _index_context(index: ProjectIndex | None, chunk: CodeChunk) -> str:
    if index is None or not chunk.function:
        return ""
    packet = index.build_context_packet(chunk.function, current_file=chunk.file)
    if packet:
        return packet
    refs = index.query_symbol(chunk.function)
    if not refs:
        return ""
    return "Known symbol locations:\n" + "\n".join(f"- {f}:{line}" for f, line in refs[:5])


def _normalize_exploitability_classification(findings: list[Finding]) -> list[Finding]:
    normalized: list[Finding] = []
    for finding in findings:
        if finding.requires_caller_violation and not finding.contract_breach_evidence:
            finding.exploitability = "contract-break-only"
        normalized.append(finding)
    return normalized


def _non_llm_context_sufficiency(chunk: CodeChunk, base_index_context: str) -> tuple[str, int]:
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


def _apply_phase15_acceptance_gates(
    findings: list[Finding],
    *,
    chunk: CodeChunk,
    base_index_context: str,
) -> list[Finding]:
    sufficiency, _score = _non_llm_context_sufficiency(chunk, base_index_context)
    guarded: list[Finding] = []

    for finding in findings:
        finding.context_sufficiency = sufficiency

        if finding.exploitability == "contract-break-only" and not finding.contract_breach_evidence:
            continue

        guarded.append(finding)
    return guarded


def _normalize_cwe_and_apply_local_evidence_gate(
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

        # Normalize broad/path CWE variants to project conventions.
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

        # Precision-first local evidence gate for compact single-pass outputs.
        if finding.evidence_spans == 0 and finding.analysis_mode == "shallow":
            if vuln_upper in {"CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-787"} and not has_memory_sink:
                continue
            if vuln_upper in {"CWE-22"} and not has_file_path_use:
                continue
            if vuln_upper in {"CWE-190"} and not has_mult:
                continue

        out.append(finding)
    return out


def _heuristic_fallback_findings(chunk: CodeChunk, start_id: int) -> tuple[list[Finding], int]:
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


def _augment_with_heuristic_findings(
    parsed_findings: list[Finding],
    chunk: CodeChunk,
    next_id: int,
) -> tuple[list[Finding], int]:
    fallback_findings, _fallback_next_id = _heuristic_fallback_findings(chunk, next_id)
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


def _collect_outputs(cfg) -> dict[str, Path]:
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


def _prompt_output_log_path(cfg) -> Path:
    if cfg.logging.prompt_output_md:
        return Path(cfg.logging.prompt_output_md)
    return Path(cfg.output_cfg.out_dir) / f"{cfg.output_cfg.out_prefix}.prompt_output.md"


def _append_exchange_header(path: Path, entry: int, chunk: CodeChunk, deep: bool) -> None:
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


def _append_prompt_section(path: Path, prompt: str) -> None:
    lines = ["### Prompt", "", *_fenced_text_block(prompt), ""]
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def _append_inference_metadata_section(
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


def _append_output_section(path: Path, output_text: str, error: str | None = None) -> None:
    lines = ["### Model Output", "", *_fenced_text_block(output_text), ""]
    if error:
        lines.extend([f"Error: `{error}`", ""])
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def _fenced_text_block(text: str) -> list[str]:
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


def _print_processing_stats(
    *,
    successful_chunks: int,
    failed_chunks: int,
    total_exchange_tokens: int,
    total_exchange_time_sec: float,
    exchange_count: int,
    total_processing_time_sec: float,
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
    print(f"average_tokens_per_second: {avg_tokens_per_sec:.2f}")
    print(f"average_exchange_time_sec: {avg_exchange_time:.3f}")
    print(f"total_processing_time_sec: {total_processing_time_sec:.3f}")
    print(f"total_processing_time_hhmmss: {total_processing_hhmmss}")


def run() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        cfg = resolve_config(args)
    except ValueError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    configure_logging(cfg.logging.verbose, cfg.logging.quiet, cfg.logging.log_file)

    try:
        if cfg.llm_inference_test:
            return _run_llm_inference_test(cfg)

        root = Path(cfg.path)
        files = discover_files(str(root), cfg.scan, cfg.files)
        if not files:
            log.warning("No files matched scan criteria")
        if cfg.dry_run:
            for file_path in files:
                rel = file_path.relative_to(root if root.is_dir() else root.parent)
                print(str(rel).replace("\\", "/"))
            return 0
        if cfg.export_code:
            export_path = Path(cfg.export_code)
            export_codebase_container(root=root, files=files, output_path=export_path)
            print(str(export_path))
            return 0

        index = None
        if cfg.project.index == "basic" and files:
            index = build_project_index(files, root)

        all_chunks: list[CodeChunk] = []
        for f in files:
            all_chunks.extend(
                _build_chunks(f, root, cfg.chunking.strategy, cfg.chunking.chunk_tokens, cfg.chunking.overlap)
            )
        if cfg.scan.function:
            all_chunks = [chunk for chunk in all_chunks if chunk.function == cfg.scan.function]
            if not all_chunks:
                log.warning("No chunks matched function filter: %s", cfg.scan.function)
        outputs = _collect_outputs(cfg)
        if "json" in outputs:
            init_json_report(outputs["json"], cfg, str(root.resolve()), len(files), len(all_chunks))
        if "csv" in outputs:
            init_csv_report(outputs["csv"])
        if "md" in outputs:
            init_markdown_report(outputs["md"], cfg)
        emitted_seen: set[tuple[str, int, int, str]] = set()
        emitted_count = 0

        backend = LlamaBackend(cfg)
        next_id = 1
        pass1_progress = 0
        pass2_progress = 0
        successful_chunks = 0
        failed_chunks = 0
        total_exchange_tokens = 0
        total_exchange_time_sec = 0.0
        exchange_count = 0
        progress_enabled = cfg.logging.progress and not cfg.logging.quiet
        total_chunks = len(all_chunks)
        processing_started = time.perf_counter()
        log_prompt_io = cfg.logging.log_prompts or cfg.logging.log_model_outputs
        prompt_output_path: Path | None = None
        prompt_output_entry = 0
        if log_prompt_io:
            prompt_output_path = _prompt_output_log_path(cfg)
            prompt_output_path.parent.mkdir(parents=True, exist_ok=True)
            if prompt_output_path.exists() and not cfg.output_cfg.overwrite:
                raise ValueError(f"Output file already exists: {prompt_output_path} (use --overwrite)")
            prompt_output_path.write_text("# Prompt/Model Output Log\n", encoding="utf-8")

        def run_chunk(chunk: CodeChunk, deep: bool = False) -> list[Finding]:
            nonlocal next_id
            nonlocal pass1_progress
            nonlocal pass2_progress
            nonlocal prompt_output_entry
            nonlocal successful_chunks
            nonlocal failed_chunks
            nonlocal total_exchange_tokens
            nonlocal total_exchange_time_sec
            nonlocal exchange_count
            pass_name = "pass2" if deep else "pass1"
            try:
                if deep:
                    pass2_progress += 1
                    maybe_progress(progress_enabled, pass2_progress, total_chunks, f"{chunk.file} (pass2)")
                else:
                    pass1_progress += 1
                    maybe_progress(progress_enabled, pass1_progress, total_chunks, f"{chunk.file} (pass1)")
                base_index_context = _index_context(index, chunk)
                prompt = build_prompt(cfg, chunk, index_context=base_index_context)
                if prompt_output_path is not None:
                    prompt_output_entry += 1
                    if cfg.logging.log_prompts or cfg.logging.log_model_outputs:
                        _append_exchange_header(prompt_output_path, prompt_output_entry, chunk, deep)
                base_params = mode_params(cfg, deep=deep)
                used_seed: int | None = base_params.seed
                result = None
                parsed_findings: list[Finding] | None = None
                next_id2: int | None = None

                t0 = time.perf_counter()
                try:
                    result = backend.generate(prompt, base_params)
                except Exception as e:  # noqa: BLE001
                    elapsed = max(0.0, time.perf_counter() - t0)
                    total_exchange_time_sec += elapsed
                    exchange_count += 1
                    msg = (
                        "Skipping function due to exchange exception "
                        f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                        f"function={chunk.function or 'N/A'}): {e}"
                    )
                    log.exception(msg)
                    print(msg, file=sys.stderr)
                    failed_chunks += 1
                    return []

                elapsed = max(0.0, time.perf_counter() - t0)
                total_exchange_time_sec += elapsed
                exchange_count += 1

                if not result.error:
                    prompt_tokens = (
                        result.prompt_tokens
                        if result.prompt_tokens is not None
                        else _approx_tokens(prompt)
                    )
                    completion_tokens = (
                        result.completion_tokens
                        if result.completion_tokens is not None
                        else _approx_tokens(result.text, allow_zero=True)
                    )
                    total_tokens = (
                        result.total_tokens
                        if result.total_tokens is not None
                        else prompt_tokens + completion_tokens
                    )
                    total_exchange_tokens += max(0, int(total_tokens))
                if prompt_output_path is not None:
                    if cfg.logging.log_model_outputs or cfg.logging.log_prompts:
                        _append_inference_metadata_section(
                            prompt_output_path,
                            timestamp_local=result.timestamp_local if result is not None else None,
                            context_size=(result.context_size if result is not None else None)
                            or cfg.inference.context,
                            context_events=result.context_events if result is not None else None,
                            seed=used_seed,
                        )
                    if cfg.logging.log_prompts:
                        _append_prompt_section(prompt_output_path, prompt)
                    if cfg.logging.log_model_outputs:
                        _append_output_section(
                            prompt_output_path,
                            result.text if result is not None else "",
                            result.error if result is not None else None,
                        )
                if result is None:
                    msg = (
                        "Skipping function due to missing inference result "
                        f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                        f"function={chunk.function or 'N/A'})"
                    )
                    log.warning(msg)
                    print(msg, file=sys.stderr)
                    failed_chunks += 1
                    return []
                if result.error:
                    msg = (
                        "Skipping function due to inference error "
                        f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                        f"function={chunk.function or 'N/A'}): {result.error}"
                    )
                    log.warning(msg)
                    print(msg, file=sys.stderr)
                    failed_chunks += 1
                    return []
                parsed_findings, next_id2 = parse_findings(result.text, chunk, start_id=next_id)
                parse_errors = [f for f in parsed_findings if f.vulnerability_type == "ParserError"]
                if parse_errors:
                    max_retries = max(0, int(cfg.inference.retries))
                    base_seed = int(base_params.seed)
                    for retry_attempt in range(1, max_retries + 1):
                        retry_seed = base_seed + retry_attempt
                        msg = (
                            "Unparsable model output; retrying with different seed "
                            f"(attempt {retry_attempt}/{max_retries}, seed={retry_seed}) "
                            f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                            f"function={chunk.function or 'N/A'})"
                        )
                        log.warning(msg)
                        print(msg, file=sys.stderr)

                        retry_params = replace(base_params, seed=retry_seed)
                        used_seed = retry_seed
                        t_retry = time.perf_counter()
                        try:
                            retry_result = backend.generate(prompt, retry_params)
                        except Exception as e:  # noqa: BLE001
                            elapsed_retry = max(0.0, time.perf_counter() - t_retry)
                            total_exchange_time_sec += elapsed_retry
                            exchange_count += 1
                            msg = (
                                "Skipping parse-retry attempt due to exchange exception "
                                f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                                f"function={chunk.function or 'N/A'}, seed={retry_seed}): {e}"
                            )
                            log.exception(msg)
                            print(msg, file=sys.stderr)
                            continue

                        elapsed_retry = max(0.0, time.perf_counter() - t_retry)
                        total_exchange_time_sec += elapsed_retry
                        exchange_count += 1
                        if not retry_result.error:
                            retry_prompt_tokens = (
                                retry_result.prompt_tokens
                                if retry_result.prompt_tokens is not None
                                else _approx_tokens(prompt)
                            )
                            retry_completion_tokens = (
                                retry_result.completion_tokens
                                if retry_result.completion_tokens is not None
                                else _approx_tokens(retry_result.text, allow_zero=True)
                            )
                            retry_total_tokens = (
                                retry_result.total_tokens
                                if retry_result.total_tokens is not None
                                else retry_prompt_tokens + retry_completion_tokens
                            )
                            total_exchange_tokens += max(0, int(retry_total_tokens))

                        if prompt_output_path is not None:
                            prompt_output_entry += 1
                            if cfg.logging.log_prompts or cfg.logging.log_model_outputs:
                                _append_exchange_header(prompt_output_path, prompt_output_entry, chunk, deep)
                                _append_inference_metadata_section(
                                    prompt_output_path,
                                    timestamp_local=retry_result.timestamp_local,
                                    context_size=(retry_result.context_size or cfg.inference.context),
                                    context_events=retry_result.context_events,
                                    seed=retry_seed,
                                )
                            if cfg.logging.log_prompts:
                                _append_prompt_section(prompt_output_path, prompt)
                            if cfg.logging.log_model_outputs:
                                _append_output_section(
                                    prompt_output_path,
                                    retry_result.text,
                                    retry_result.error,
                                )

                        if retry_result.error:
                            msg = (
                                "Skipping parse-retry attempt due to inference error "
                                f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                                f"function={chunk.function or 'N/A'}, seed={retry_seed}): {retry_result.error}"
                            )
                            log.warning(msg)
                            print(msg, file=sys.stderr)
                            continue

                        parsed_findings, next_id2 = parse_findings(retry_result.text, chunk, start_id=next_id)
                        parse_errors = [f for f in parsed_findings if f.vulnerability_type == "ParserError"]
                        if not parse_errors:
                            result = retry_result
                            break

                    if parse_errors:
                        parse_error = parse_errors[0].parse_error or "unknown parse error"
                        msg = (
                            "Marking chunk unresolved due to unparsable model output "
                            f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                            f"function={chunk.function or 'N/A'}): {parse_error}"
                        )
                        log.warning(msg)
                        print(msg, file=sys.stderr)
                        fallback_findings, fallback_next_id = _heuristic_fallback_findings(chunk, next_id)
                        if fallback_findings:
                            next_id = fallback_next_id
                            successful_chunks += 1
                            return fallback_findings
                        failed_chunks += 1
                        return []

                parsed_findings = _normalize_exploitability_classification(parsed_findings)
                parsed_findings = _normalize_cwe_and_apply_local_evidence_gate(parsed_findings, chunk=chunk)
                if parsed_findings:
                    parsed_findings, next_id2 = _augment_with_heuristic_findings(parsed_findings, chunk, next_id2)
                parsed_findings = _apply_phase15_acceptance_gates(
                    parsed_findings,
                    chunk=chunk,
                    base_index_context=base_index_context,
                )

                if parsed_findings is None or next_id2 is None:
                    msg = (
                        "Marking chunk unresolved due to missing parsed findings "
                        f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                        f"function={chunk.function or 'N/A'})"
                    )
                    log.warning(msg)
                    print(msg, file=sys.stderr)
                    failed_chunks += 1
                    return []
                next_id = next_id2
                successful_chunks += 1
                return parsed_findings
            except Exception as e:  # noqa: BLE001
                msg = (
                    "Skipping function due to unexpected processing error "
                    f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                    f"function={chunk.function or 'N/A'}): {e}"
                )
                log.exception(msg)
                print(msg, file=sys.stderr)
                failed_chunks += 1
                return []

        def emit_findings(chunk_findings: list[Finding]) -> None:
            nonlocal emitted_count
            for finding in chunk_findings:
                emitted_key = (finding.file, finding.start_line, finding.end_line, finding.vulnerability_type)
                if emitted_key in emitted_seen:
                    continue
                if cfg.scan.max_findings > 0 and emitted_count >= cfg.scan.max_findings:
                    continue
                finding.id = f"F-{emitted_count + 1:04d}"
                emitted_seen.add(emitted_key)
                emitted_count += 1
                if "json" in outputs:
                    append_json_finding(
                        outputs["json"],
                        finding,
                        include_reasoning=cfg.output_cfg.include_reasoning,
                    )
                if "csv" in outputs:
                    append_csv_finding(outputs["csv"], finding)
                if "md" in outputs:
                    append_markdown_finding(
                        outputs["md"],
                        cfg,
                        finding,
                        include_reasoning=cfg.output_cfg.include_reasoning,
                    )

        findings = run_scan_multipass(cfg, backend, all_chunks, run_chunk, on_emit=emit_findings)
        findings = deduplicate_findings(findings)

        if cfg.scan.max_findings > 0:
            findings = findings[: cfg.scan.max_findings]

        if "json" in outputs:
            append_json_summary(outputs["json"], findings)
        if "md" in outputs:
            append_markdown_summary_and_table(outputs["md"], cfg, findings)

        total_processing_time_sec = max(0.0, time.perf_counter() - processing_started)
        _print_processing_stats(
            successful_chunks=successful_chunks,
            failed_chunks=failed_chunks,
            total_exchange_tokens=total_exchange_tokens,
            total_exchange_time_sec=total_exchange_time_sec,
            exchange_count=exchange_count,
            total_processing_time_sec=total_processing_time_sec,
        )

        non_parser_findings = [f for f in findings if f.vulnerability_type != "ParserError"]
        return 1 if non_parser_findings else 0

    except ValueError as e:
        print(f"Usage error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"Runtime error: {e}", file=sys.stderr)
        return 3


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()

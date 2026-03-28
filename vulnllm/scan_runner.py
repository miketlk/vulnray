from __future__ import annotations

import logging
import shlex
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.cli_logic import (
    append_exchange_header,
    append_ast_chunker_section,
    append_inference_metadata_section,
    append_output_section,
    append_prompt_section,
    apply_phase15_acceptance_gates,
    approx_tokens,
    augment_with_heuristic_findings,
    build_chunks,
    collect_outputs,
    heuristic_fallback_findings,
    index_context,
    normalize_cwe_and_apply_local_evidence_gate,
    normalize_exploitability_classification,
    print_processing_stats,
    prompt_output_log_path,
)
from vulnllm.findings.deduplicator import deduplicate_findings
from vulnllm.findings.model import Finding, parse_findings
from vulnllm.inference.multipass import run_scan_multipass
from vulnllm.inference.parameters import mode_params
from vulnllm.indexing.project_index import build_project_index
from vulnllm.prompt.base_prompt import build_prompt
from vulnllm.reporting.csv_report import append_csv_finding, init_csv_report
from vulnllm.reporting.json_report import append_json_finding, append_json_summary, init_json_report
from vulnllm.reporting.markdown_report import append_markdown_finding, append_markdown_summary_and_table, init_markdown_report
from vulnllm.reporting.sarif_report import write_sarif_report
from vulnllm.utils.progress import maybe_progress

log = logging.getLogger("vulnllm")
__all__ = ["run_scan"]


def run_scan(cfg, *, root: Path, files: list[Path], backend_factory) -> int:
    start_time_utc = datetime.now(timezone.utc)
    index = None
    if cfg.project.index == "basic" and files:
        index = build_project_index(files, root)

    all_chunks: list[CodeChunk] = []
    for file_path in files:
        all_chunks.extend(
            build_chunks(
                file_path,
                root,
                cfg.chunking.strategy,
                cfg.chunking.chunk_tokens,
                cfg.chunking.overlap,
            )
        )
    if cfg.scan.function:
        all_chunks = [chunk for chunk in all_chunks if chunk.function == cfg.scan.function]
        if not all_chunks:
            log.warning("No chunks matched function filter: %s", cfg.scan.function)

    outputs = collect_outputs(cfg)
    if "json" in outputs:
        init_json_report(outputs["json"], cfg, str(root.resolve()), len(files), len(all_chunks))
    if "csv" in outputs:
        init_csv_report(outputs["csv"])
    if "md" in outputs:
        init_markdown_report(outputs["md"], cfg)

    emitted_seen: set[tuple[str, int, int, str]] = set()
    emitted_count = 0

    backend = backend_factory(cfg)
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
        prompt_output_path = prompt_output_log_path(cfg)
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
            base_index_context = index_context(index, chunk)
            prompt = build_prompt(cfg, chunk, index_context=base_index_context)
            if prompt_output_path is not None:
                prompt_output_entry += 1
                if cfg.logging.log_prompts or cfg.logging.log_model_outputs:
                    append_exchange_header(prompt_output_path, prompt_output_entry, chunk, deep)
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
                prompt_tokens = result.prompt_tokens if result.prompt_tokens is not None else approx_tokens(prompt)
                completion_tokens = (
                    result.completion_tokens
                    if result.completion_tokens is not None
                    else approx_tokens(result.text, allow_zero=True)
                )
                total_tokens = (
                    result.total_tokens if result.total_tokens is not None else prompt_tokens + completion_tokens
                )
                total_exchange_tokens += max(0, int(total_tokens))
            if prompt_output_path is not None:
                if cfg.logging.log_model_outputs or cfg.logging.log_prompts:
                    append_inference_metadata_section(
                        prompt_output_path,
                        timestamp_local=result.timestamp_local if result is not None else None,
                        context_size=(result.context_size if result is not None else None) or cfg.inference.context,
                        context_events=result.context_events if result is not None else None,
                        seed=used_seed,
                    )
                    append_ast_chunker_section(prompt_output_path, chunk=chunk)
                if cfg.logging.log_prompts:
                    append_prompt_section(prompt_output_path, prompt)
                if cfg.logging.log_model_outputs:
                    append_output_section(
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
                            else approx_tokens(prompt)
                        )
                        retry_completion_tokens = (
                            retry_result.completion_tokens
                            if retry_result.completion_tokens is not None
                            else approx_tokens(retry_result.text, allow_zero=True)
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
                            append_exchange_header(prompt_output_path, prompt_output_entry, chunk, deep)
                            append_inference_metadata_section(
                                prompt_output_path,
                                timestamp_local=retry_result.timestamp_local,
                                context_size=(retry_result.context_size or cfg.inference.context),
                                context_events=retry_result.context_events,
                                seed=retry_seed,
                            )
                            append_ast_chunker_section(prompt_output_path, chunk=chunk)
                        if cfg.logging.log_prompts:
                            append_prompt_section(prompt_output_path, prompt)
                        if cfg.logging.log_model_outputs:
                            append_output_section(
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
                    fallback_findings, fallback_next_id = heuristic_fallback_findings(chunk, next_id)
                    if fallback_findings:
                        next_id = fallback_next_id
                        successful_chunks += 1
                        return fallback_findings
                    failed_chunks += 1
                    return []

            parsed_findings = normalize_exploitability_classification(parsed_findings)
            parsed_findings = normalize_cwe_and_apply_local_evidence_gate(parsed_findings, chunk=chunk)
            if parsed_findings:
                parsed_findings, next_id2 = augment_with_heuristic_findings(parsed_findings, chunk, next_id2)
            parsed_findings = apply_phase15_acceptance_gates(
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
    if "sarif" in outputs:
        end_time_utc = datetime.now(timezone.utc)
        write_sarif_report(
            outputs["sarif"],
            cfg,
            str(root.resolve()),
            len(files),
            len(all_chunks),
            findings,
            include_reasoning=cfg.output_cfg.include_reasoning,
            command_line=shlex.join(sys.argv),
            start_time_utc=start_time_utc,
            end_time_utc=end_time_utc,
            execution_successful=True,
            failed_chunks=failed_chunks,
        )

    total_processing_time_sec = max(0.0, time.perf_counter() - processing_started)
    print_processing_stats(
        successful_chunks=successful_chunks,
        failed_chunks=failed_chunks,
        total_exchange_tokens=total_exchange_tokens,
        total_exchange_time_sec=total_exchange_time_sec,
        exchange_count=exchange_count,
        total_processing_time_sec=total_processing_time_sec,
    )

    non_parser_findings = [f for f in findings if f.vulnerability_type != "ParserError"]
    return 1 if non_parser_findings else 0

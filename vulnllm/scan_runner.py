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
    apply_compact_acceptance_gates,
    approx_tokens,
    augment_with_heuristic_findings,
    build_chunks,
    candidate_cwe_policy_for_chunk,
    collect_outputs,
    index_context,
    normalize_exploitability_classification,
    print_processing_stats,
    prompt_output_log_path,
    secondary_cwe_candidates_for_chunk,
)
from vulnllm.findings.deduplicator import deduplicate_findings
from vulnllm.findings.model import Finding, parse_findings_with_error, parse_sufficiency_decision
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
    unresolved_chunks = 0
    retrieval_rounds_used = 0
    parse_failures = 0
    suppressed_by_caller_bounds = 0
    suppressed_by_struct_extent = 0
    suppressed_by_contradiction = 0
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
        nonlocal unresolved_chunks
        nonlocal retrieval_rounds_used
        nonlocal parse_failures
        nonlocal suppressed_by_caller_bounds
        nonlocal suppressed_by_struct_extent
        nonlocal suppressed_by_contradiction
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
            allowed_cwe_policy = candidate_cwe_policy_for_chunk(chunk)
            base_params = mode_params(cfg, deep=deep)
            context_text = base_index_context
            retrieved_symbols: list[str] = []
            sufficiency_result = "unknown"
            parsed_findings: list[Finding] | None = None
            next_id2: int | None = None

            def _run_exchange(prompt: str, *, stage: str, params=None, extra_events: list[str] | None = None):
                nonlocal prompt_output_entry
                nonlocal total_exchange_tokens
                nonlocal total_exchange_time_sec
                nonlocal exchange_count
                if params is None:
                    params = base_params
                if prompt_output_path is not None and (cfg.logging.log_prompts or cfg.logging.log_model_outputs):
                    prompt_output_entry += 1
                    append_exchange_header(prompt_output_path, prompt_output_entry, chunk, deep)
                t0 = time.perf_counter()
                try:
                    result = backend.generate(prompt, params)
                except Exception as e:  # noqa: BLE001
                    elapsed = max(0.0, time.perf_counter() - t0)
                    total_exchange_time_sec += elapsed
                    exchange_count += 1
                    msg = (
                        "Skipping function due to exchange exception "
                        f"({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                        f"function={chunk.function or 'N/A'}, stage={stage}): {e}"
                    )
                    log.exception(msg)
                    print(msg, file=sys.stderr)
                    return None

                elapsed = max(0.0, time.perf_counter() - t0)
                total_exchange_time_sec += elapsed
                exchange_count += 1
                if extra_events:
                    result.context_events.extend(extra_events)
                result.context_events.append(f"stage={stage}")
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
                            timestamp_local=result.timestamp_local,
                            context_size=result.context_size or cfg.inference.context,
                            context_events=result.context_events,
                            seed=params.seed,
                        )
                        append_ast_chunker_section(prompt_output_path, chunk=chunk)
                    if cfg.logging.log_prompts:
                        append_prompt_section(prompt_output_path, prompt)
                    if cfg.logging.log_model_outputs:
                        append_output_section(prompt_output_path, result.text, result.error)
                return result

            def _retry_once(prompt: str, *, stage: str, parse_error: str):
                nonlocal parse_failures
                parse_failures += 1
                retry_seed = int(base_params.seed) + 1
                msg = (
                    "Malformed model output; retrying once with different seed "
                    f"(seed={retry_seed}) ({pass_name}, {chunk.file}:{chunk.start_line}-{chunk.end_line}, "
                    f"function={chunk.function or 'N/A'}, stage={stage}): {parse_error}"
                )
                log.warning(msg)
                print(msg, file=sys.stderr)
                retry_params = replace(base_params, seed=retry_seed)
                return _run_exchange(prompt, stage=f"{stage}-retry", params=retry_params)

            sufficiency_prompt = build_prompt(
                cfg,
                chunk,
                index_context=context_text,
                allowed_cwe_policy=allowed_cwe_policy,
                prompt_kind="sufficiency",
            )
            sufficiency_exchange = _run_exchange(
                sufficiency_prompt,
                stage="sufficiency",
                extra_events=[f"initial_context_lines={len([line for line in context_text.splitlines() if line.strip()])}"],
            )
            if sufficiency_exchange is None or sufficiency_exchange.error:
                failed_chunks += 1
                return []

            sufficiency_decision = parse_sufficiency_decision(sufficiency_exchange.text)
            if sufficiency_decision is None:
                legacy_findings, _legacy_next_id, legacy_parse_error = parse_findings_with_error(
                    sufficiency_exchange.text,
                    chunk,
                    start_id=next_id,
                )
                if legacy_parse_error is None:
                    sufficiency_result = "yes"
                    parsed_findings = legacy_findings
                    next_id2 = _legacy_next_id
                else:
                    retry_result = _retry_once(
                        sufficiency_prompt,
                        stage="sufficiency",
                        parse_error="No valid sufficiency output block found",
                    )
                    if retry_result is None or retry_result.error:
                        unresolved_chunks += 1
                        return []
                    sufficiency_decision = parse_sufficiency_decision(retry_result.text)
                    if sufficiency_decision is None:
                        unresolved_chunks += 1
                        return []
            else:
                parsed_findings = None
                next_id2 = None

            if sufficiency_decision is not None:
                sufficiency_result = "yes" if sufficiency_decision.context_is_sufficient else "no"
            if sufficiency_decision is not None and not sufficiency_decision.context_is_sufficient:
                if index is None:
                    unresolved_chunks += 1
                    return []
                retrieval_context, retrieved_symbols = _build_retrieval_context(index, sufficiency_decision.requested_symbols, base_index_context)
                if not retrieval_context or not retrieved_symbols:
                    unresolved_chunks += 1
                    return []
                retrieval_rounds_used += 1
                context_text = retrieval_context
                sufficiency_prompt = build_prompt(
                    cfg,
                    chunk,
                    index_context=context_text,
                    allowed_cwe_policy=allowed_cwe_policy,
                    prompt_kind="sufficiency",
                )
                sufficiency_exchange = _run_exchange(
                    sufficiency_prompt,
                    stage="sufficiency-retrieval",
                    extra_events=[f"retrieved_symbols={','.join(retrieved_symbols)}"],
                )
                if sufficiency_exchange is None or sufficiency_exchange.error:
                    failed_chunks += 1
                    return []
                sufficiency_decision = parse_sufficiency_decision(sufficiency_exchange.text)
                if sufficiency_decision is None or not sufficiency_decision.context_is_sufficient:
                    unresolved_chunks += 1
                    return []
                sufficiency_result = "yes"

            if parsed_findings is None or next_id2 is None:
                detection_prompt = build_prompt(
                    cfg,
                    chunk,
                    index_context=context_text,
                    allowed_cwe_policy=allowed_cwe_policy,
                    prompt_kind="detection",
                )
                detection_exchange = _run_exchange(
                    detection_prompt,
                    stage="detection",
                    extra_events=[
                        f"sufficiency_result={sufficiency_result}",
                        f"retrieved_symbols={','.join(retrieved_symbols) if retrieved_symbols else 'N/A'}",
                    ],
                )
                if detection_exchange is None or detection_exchange.error:
                    failed_chunks += 1
                    return []

                parsed_findings, next_id2, parse_error = parse_findings_with_error(
                    detection_exchange.text,
                    chunk,
                    start_id=next_id,
                )
                if parse_error:
                    retry_result = _retry_once(detection_prompt, stage="detection", parse_error=parse_error)
                    if retry_result is None or retry_result.error:
                        unresolved_chunks += 1
                        return []
                    parsed_findings, next_id2, parse_error = parse_findings_with_error(
                        retry_result.text,
                        chunk,
                        start_id=next_id,
                    )
                    if parse_error:
                        unresolved_chunks += 1
                        return []

            parsed_findings = normalize_exploitability_classification(parsed_findings)
            parsed_findings, suppression_counts = apply_compact_acceptance_gates(
                parsed_findings,
                chunk=chunk,
                context_text=context_text,
                allowed_cwe_policy=allowed_cwe_policy,
            )
            suppressed_by_caller_bounds += suppression_counts["suppressed_by_caller_bounds"]
            suppressed_by_struct_extent += suppression_counts["suppressed_by_struct_extent"]
            suppressed_by_contradiction += suppression_counts["suppressed_by_contradiction"]

            followup_candidates = secondary_cwe_candidates_for_chunk(chunk, existing_findings=parsed_findings)
            if parsed_findings and followup_candidates and next_id2 is not None:
                for extra_cwe in followup_candidates:
                    followup_prompt = build_prompt(
                        cfg,
                        chunk,
                        index_context=context_text,
                        allowed_cwe_policy=(extra_cwe, "N/A"),
                        prompt_kind="detection",
                    )
                    followup_exchange = _run_exchange(
                        followup_prompt,
                        stage=f"detection-followup-{extra_cwe.lower()}",
                        extra_events=[
                            f"sufficiency_result={sufficiency_result}",
                            f"retrieved_symbols={','.join(retrieved_symbols) if retrieved_symbols else 'N/A'}",
                            f"followup_policy={extra_cwe}",
                        ],
                    )
                    if followup_exchange is None or followup_exchange.error:
                        continue

                    extra_findings, next_id2_candidate, parse_error = parse_findings_with_error(
                        followup_exchange.text,
                        chunk,
                        start_id=next_id2,
                    )
                    if parse_error:
                        retry_result = _retry_once(
                            followup_prompt,
                            stage=f"detection-followup-{extra_cwe.lower()}",
                            parse_error=parse_error,
                        )
                        if retry_result is None or retry_result.error:
                            continue
                        extra_findings, next_id2_candidate, parse_error = parse_findings_with_error(
                            retry_result.text,
                            chunk,
                            start_id=next_id2,
                        )
                        if parse_error:
                            continue

                    extra_findings = normalize_exploitability_classification(extra_findings)
                    extra_findings, extra_counts = apply_compact_acceptance_gates(
                        extra_findings,
                        chunk=chunk,
                        context_text=context_text,
                        allowed_cwe_policy=(extra_cwe, "N/A"),
                    )
                    suppressed_by_caller_bounds += extra_counts["suppressed_by_caller_bounds"]
                    suppressed_by_struct_extent += extra_counts["suppressed_by_struct_extent"]
                    suppressed_by_contradiction += extra_counts["suppressed_by_contradiction"]
                    if extra_findings:
                        parsed_findings.extend(extra_findings)
                    next_id2 = next_id2_candidate

            if prompt_output_path is not None and (cfg.logging.log_prompts or cfg.logging.log_model_outputs):
                with prompt_output_path.open("a", encoding="utf-8") as out:
                    out.write(
                        "\n### Controller Summary\n\n"
                        f"- Sufficiency result: `{sufficiency_result}`\n"
                        f"- Retrieved symbols: `{', '.join(retrieved_symbols) if retrieved_symbols else 'N/A'}`\n"
                        f"- Suppression reason: `"
                        f"{_format_suppression_reason(suppression_counts)}`\n"
                        f"- Final detection result: `"
                        f"{', '.join(f.vulnerability_type for f in parsed_findings) if parsed_findings else 'N/A'}`\n"
                    )

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
        append_json_summary(
            outputs["json"],
            findings,
            telemetry={
                "unresolved_chunks": unresolved_chunks,
                "retrieval_rounds_used": retrieval_rounds_used,
                "parse_failures": parse_failures,
                "suppressed_by_caller_bounds": suppressed_by_caller_bounds,
                "suppressed_by_struct_extent": suppressed_by_struct_extent,
                "suppressed_by_contradiction": suppressed_by_contradiction,
            },
        )
    if "md" in outputs:
        append_markdown_summary_and_table(
            outputs["md"],
            cfg,
            findings,
            telemetry={
                "unresolved_chunks": unresolved_chunks,
                "retrieval_rounds_used": retrieval_rounds_used,
                "parse_failures": parse_failures,
                "suppressed_by_caller_bounds": suppressed_by_caller_bounds,
                "suppressed_by_struct_extent": suppressed_by_struct_extent,
                "suppressed_by_contradiction": suppressed_by_contradiction,
            },
        )
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
        unresolved_chunks=unresolved_chunks,
        retrieval_rounds_used=retrieval_rounds_used,
        parse_failures=parse_failures,
        suppressed_by_caller_bounds=suppressed_by_caller_bounds,
        suppressed_by_struct_extent=suppressed_by_struct_extent,
        suppressed_by_contradiction=suppressed_by_contradiction,
    )

    return 1 if findings else 0


def _format_suppression_reason(counts: dict[str, int]) -> str:
    reasons = [name for name, value in counts.items() if value > 0]
    return ",".join(reasons) if reasons else "none"


def _build_retrieval_context(index, symbols: list[str], base_index_context: str) -> tuple[str, list[str]]:
    lines: list[str] = [base_index_context.strip()] if base_index_context.strip() else []
    retrieval_lines: list[str] = []
    resolved_symbols: list[str] = []
    for symbol in symbols[:2]:
        name = symbol.strip()
        if not name:
            continue
        snippet = index.get_symbol_definition(name, max_lines=16)
        if snippet:
            retrieval_lines.append(f"- {snippet.replace(chr(10), chr(10) + '  ')}")
            resolved_symbols.append(name)
            continue
        refs = index.query_symbol(name)
        if refs:
            locations = ", ".join(f"{file}:{line}" for file, line in refs[:3])
            retrieval_lines.append(f"- {name}: {locations}")
            resolved_symbols.append(name)
    if retrieval_lines:
        lines.append("Retrieved symbols:")
        lines.extend(retrieval_lines)
    return "\n".join(lines).strip(), resolved_symbols

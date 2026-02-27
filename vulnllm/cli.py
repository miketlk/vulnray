from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

from vulnllm.chunking.function_chunker import CodeChunk, chunk_file_by_function
from vulnllm.chunking.sliding_chunker import chunk_file_sliding
from vulnllm.config import build_parser, resolve_config
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
        "Analyze the target function and return ONLY JSON with keys final_answer and vulnerabilities.\n"
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
        'If vulnerable, use one CWE in final_answer.type; otherwise set final_answer.type to "N/A".'
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
    refs = index.query_symbol(chunk.function)
    if not refs:
        return ""
    return "Known symbol locations:\n" + "\n".join(f"- {f}:{line}" for f, line in refs[:5])


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
    lines = ["Prompt:", "", "```text", prompt, "```", ""]
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def _append_output_section(path: Path, output_text: str, error: str | None = None) -> None:
    lines = ["Model Output:", "", "```text", output_text, "```", ""]
    if error:
        lines.extend([f"Error: `{error}`", ""])
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


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

        index = None
        if cfg.project.index == "basic" and files:
            index = build_project_index(files, root)

        all_chunks: list[CodeChunk] = []
        for f in files:
            all_chunks.extend(
                _build_chunks(f, root, cfg.chunking.strategy, cfg.chunking.chunk_tokens, cfg.chunking.overlap)
            )
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
        progress_enabled = cfg.logging.progress and not cfg.logging.quiet
        total_chunks = len(all_chunks)
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
            nonlocal next_id, pass1_progress, pass2_progress, prompt_output_entry
            if deep:
                pass2_progress += 1
                maybe_progress(progress_enabled, pass2_progress, total_chunks, f"{chunk.file} (pass2)")
            else:
                pass1_progress += 1
                maybe_progress(progress_enabled, pass1_progress, total_chunks, f"{chunk.file} (pass1)")
            prompt = build_prompt(cfg, chunk, index_context=_index_context(index, chunk))
            if prompt_output_path is not None:
                prompt_output_entry += 1
                if cfg.logging.log_prompts:
                    _append_exchange_header(prompt_output_path, prompt_output_entry, chunk, deep)
                    _append_prompt_section(prompt_output_path, prompt)
            result = backend.generate(prompt, mode_params(cfg, deep=deep))
            if prompt_output_path is not None:
                if cfg.logging.log_model_outputs:
                    if not cfg.logging.log_prompts:
                        _append_exchange_header(prompt_output_path, prompt_output_entry, chunk, deep)
                    _append_output_section(prompt_output_path, result.text, result.error)
            if result.error:
                raise RuntimeError(result.error)
            findings, next_id2 = parse_findings(result.text, chunk, start_id=next_id)
            next_id = next_id2
            return findings

        def emit_findings(chunk_findings: list[Finding]) -> None:
            nonlocal emitted_count
            for finding in chunk_findings:
                emitted_key = (finding.file, finding.start_line, finding.end_line, finding.vulnerability_type)
                if emitted_key in emitted_seen:
                    continue
                if cfg.scan.max_findings > 0 and emitted_count >= cfg.scan.max_findings:
                    continue
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

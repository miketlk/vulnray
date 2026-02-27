from __future__ import annotations

import logging
import sys
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
from vulnllm.reporting.csv_report import write_csv_report
from vulnllm.reporting.json_report import write_json_report
from vulnllm.reporting.markdown_report import write_markdown_report
from vulnllm.scanner.file_scanner import discover_files
from vulnllm.utils.logging import configure_logging
from vulnllm.utils.progress import maybe_progress

log = logging.getLogger("vulnllm")


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


def run() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        cfg = resolve_config(args)
    except ValueError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    configure_logging(cfg.logging.verbose, cfg.logging.quiet, cfg.logging.log_file)

    root = Path(cfg.path)
    try:
        files = discover_files(str(root), cfg.scan, cfg.files)
        if not files:
            log.warning("No files matched scan criteria")

        index = None
        if cfg.project.index == "basic" and files:
            index = build_project_index(files, root)

        all_chunks: list[CodeChunk] = []
        for f in files:
            all_chunks.extend(
                _build_chunks(f, root, cfg.chunking.strategy, cfg.chunking.chunk_tokens, cfg.chunking.overlap)
            )

        backend = LlamaBackend(cfg)
        next_id = 1
        pass1_progress = 0
        pass2_progress = 0
        progress_enabled = cfg.logging.progress and not cfg.logging.quiet
        total_chunks = len(all_chunks)

        def run_chunk(chunk: CodeChunk, deep: bool = False) -> list[Finding]:
            nonlocal next_id, pass1_progress, pass2_progress
            if deep:
                pass2_progress += 1
                maybe_progress(progress_enabled, pass2_progress, total_chunks, f"{chunk.file} (pass2)")
            else:
                pass1_progress += 1
                maybe_progress(progress_enabled, pass1_progress, total_chunks, f"{chunk.file} (pass1)")
            prompt = build_prompt(cfg, chunk, index_context=_index_context(index, chunk))
            result = backend.generate(prompt, mode_params(cfg, deep=deep))
            if result.error:
                raise RuntimeError(result.error)
            findings, next_id2 = parse_findings(result.text, chunk, start_id=next_id)
            next_id = next_id2
            return findings

        findings = run_scan_multipass(cfg, backend, all_chunks, run_chunk)
        findings = deduplicate_findings(findings)

        if cfg.scan.max_findings > 0:
            findings = findings[: cfg.scan.max_findings]

        outputs = _collect_outputs(cfg)

        if "json" in outputs:
            write_json_report(
                outputs["json"],
                cfg,
                str(root.resolve()),
                len(files),
                len(all_chunks),
                findings,
                include_reasoning=cfg.output_cfg.include_reasoning,
            )
        if "csv" in outputs:
            write_csv_report(outputs["csv"], findings)
        if "md" in outputs:
            write_markdown_report(outputs["md"], cfg, findings, include_reasoning=cfg.output_cfg.include_reasoning)

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

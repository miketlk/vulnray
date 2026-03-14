from __future__ import annotations

import logging
import sys
from pathlib import Path

from vulnllm.cli_logic import augment_with_heuristic_findings, run_llm_inference_test
from vulnllm.config import build_parser, resolve_config
from vulnllm.export_code import export_codebase_container
from vulnllm.inference.llama_backend import LlamaBackend
from vulnllm.scan_runner import run_scan
from vulnllm.scanner.file_scanner import discover_files
from vulnllm.utils.logging import configure_logging

log = logging.getLogger("vulnllm")

# Backwards-compatible symbol used by tests.
_augment_with_heuristic_findings = augment_with_heuristic_findings


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
            return run_llm_inference_test(cfg, backend_factory=LlamaBackend)

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
        return run_scan(cfg, root=root, files=files, backend_factory=LlamaBackend)

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

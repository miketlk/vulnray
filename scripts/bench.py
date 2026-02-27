from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Allow running as `python scripts/bench.py` without installing the package.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulnllm.chunking.function_chunker import chunk_file_by_function
from vulnllm.chunking.sliding_chunker import chunk_file_sliding
from vulnllm.config import FilesConfig, ScanConfig
from vulnllm.scanner.file_scanner import discover_files


def _approx_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Benchmark VulnLLM scanner throughput")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--lang", default="c")
    p.add_argument("--include", action="append")
    p.add_argument("--exclude", action="append")
    p.add_argument("--max-file-bytes", type=int, default=2_000_000)
    p.add_argument("--chunk-strategy", choices=["function", "sliding", "file"], default="function")
    p.add_argument("--chunk-tokens", type=int, default=1400)
    p.add_argument("--chunk-overlap", type=int, default=200)
    return p


def main() -> None:
    args = build_parser().parse_args()
    root = Path(args.path)

    scan_cfg = ScanConfig(languages=[x.strip() for x in args.lang.split(",") if x.strip()])
    files_cfg = FilesConfig(
        include=args.include or [],
        exclude=args.exclude or FilesConfig().exclude,
        max_file_bytes=args.max_file_bytes,
    )

    t0 = time.perf_counter()
    files = discover_files(str(root), scan_cfg, files_cfg)

    chunks = []
    for f in files:
        if args.chunk_strategy == "sliding":
            chunks.extend(chunk_file_sliding(f, root, args.chunk_tokens, args.chunk_overlap))
        elif args.chunk_strategy == "file":
            text = f.read_text(encoding="utf-8", errors="ignore")
            rel = str(f.relative_to(root if root.is_dir() else root.parent))
            lines = text.splitlines()
            from vulnllm.chunking.function_chunker import CodeChunk

            chunks.append(CodeChunk(file=rel, start_line=1, end_line=max(1, len(lines)), text=text, function=None))
        else:
            chunks.extend(chunk_file_by_function(f, root))

    token_count = sum(_approx_tokens(c.text) for c in chunks)
    elapsed = max(1e-9, time.perf_counter() - t0)

    print(f"files: {len(files)}")
    print(f"chunks: {len(chunks)}")
    print(f"tokens: {token_count}")
    print(f"files/sec: {len(files)/elapsed:.2f}")
    print(f"tokens/sec: {token_count/elapsed:.2f}")


if __name__ == "__main__":
    main()

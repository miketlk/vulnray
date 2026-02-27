from __future__ import annotations

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.inference.multipass import run_scan_multipass


def _mk_finding(fid: str, chunk: CodeChunk, severity: str = "medium") -> Finding:
    return Finding(
        id=fid,
        file=chunk.file,
        start_line=chunk.start_line,
        end_line=chunk.end_line,
        function=chunk.function,
        vulnerability_type="Test",
        severity=severity,
        confidence=0.8,
        description="d",
        reasoning="r",
    )


def test_multipass_fast_budget_uses_shallow_pass1_and_deep_pass2():
    cfg = Config()
    cfg.scan.multi_pass = True
    cfg.multipass.pass1_budget = "fast"
    cfg.multipass.pass2_target = "flagged"

    chunks = [
        CodeChunk(file="a.c", start_line=1, end_line=10, text="int a(){return 1;}", function="a"),
        CodeChunk(file="b.c", start_line=1, end_line=10, text="int b(){return 2;}", function="b"),
    ]

    calls: list[tuple[str, bool]] = []

    def run_chunk(chunk: CodeChunk, deep: bool = False):
        calls.append((chunk.file, deep))
        if chunk.file == "a.c" and not deep:
            return [_mk_finding("F-0001", chunk, severity="high")]
        if chunk.file == "a.c" and deep:
            return [_mk_finding("F-0002", chunk, severity="critical")]
        return []

    findings = run_scan_multipass(cfg, backend=None, chunks=chunks, run_chunk=run_chunk)

    assert calls == [("a.c", False), ("b.c", False), ("a.c", True)]
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_multipass_normal_budget_deepens_pass1():
    cfg = Config()
    cfg.scan.multi_pass = True
    cfg.multipass.pass1_budget = "normal"
    cfg.multipass.pass2_target = "flagged"

    chunks = [
        CodeChunk(file="a.c", start_line=1, end_line=10, text="int a(){return 1;}", function="a"),
        CodeChunk(file="b.c", start_line=1, end_line=10, text="int b(){return 2;}", function="b"),
    ]

    calls: list[tuple[str, bool]] = []

    def run_chunk(chunk: CodeChunk, deep: bool = False):
        calls.append((chunk.file, deep))
        if chunk.file == "a.c":
            return [_mk_finding("F-0001", chunk, severity="high")]
        return []

    run_scan_multipass(cfg, backend=None, chunks=chunks, run_chunk=run_chunk)

    assert calls == [("a.c", True), ("b.c", True), ("a.c", True)]

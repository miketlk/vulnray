from __future__ import annotations

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.findings.severity import severity_rank


def _score(findings: list[Finding]) -> int:
    return max((severity_rank(f.severity) for f in findings), default=0)


def run_scan_multipass(
    cfg: Config,
    backend,
    chunks: list[CodeChunk],
    run_chunk,
    on_emit=None,
) -> list[Finding]:
    if not cfg.scan.multi_pass:
        merged: list[Finding] = []
        for chunk in chunks:
            chunk_findings = run_chunk(chunk, deep=False)
            if on_emit is not None:
                on_emit(chunk_findings)
            merged.extend(chunk_findings)
        return merged

    # "fast" keeps pass-1 shallow for screening. "normal" allows deeper pass-1 analysis.
    pass1_deep = cfg.multipass.pass1_budget == "normal"
    pass1 = [(chunk, run_chunk(chunk, deep=pass1_deep)) for chunk in chunks]
    if cfg.multipass.pass2_target == "topk":
        ranked = sorted(pass1, key=lambda x: _score(x[1]), reverse=True)
        selected = [c for c, _ in ranked[: cfg.multipass.pass2_topk]]
    else:
        selected = [c for c, fs in pass1 if fs]

    deep_map = {id(c): run_chunk(c, deep=True) for c in selected}

    merged: list[Finding] = []
    for chunk, findings in pass1:
        replacement = deep_map.get(id(chunk))
        chosen = replacement if replacement is not None else findings
        if on_emit is not None:
            on_emit(chosen)
        merged.extend(chosen)

    return merged

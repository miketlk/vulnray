from __future__ import annotations

from pathlib import Path

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.cli_logic import (
    __all__ as cli_logic_all,
    append_exchange_header,
    append_inference_metadata_section,
    append_output_section,
    append_prompt_section,
    apply_phase15_acceptance_gates,
    approx_tokens,
    backend_name_and_version,
    build_chunks,
    collect_outputs,
    fenced_text_block,
    heuristic_fallback_findings,
    index_context,
    normalize_cwe_and_apply_local_evidence_gate,
    normalize_exploitability_classification,
    non_llm_context_sufficiency,
    print_processing_stats,
    prompt_output_log_path,
    run_llm_inference_test,
)
from vulnllm.config import Config
from vulnllm.findings.model import Finding
from vulnllm.inference.llama_backend import InferenceResult


def _finding(chunk: CodeChunk, vuln_type: str = "CWE-120") -> Finding:
    return Finding(
        id="F-0001",
        file=chunk.file,
        start_line=chunk.start_line,
        end_line=chunk.end_line,
        function=chunk.function,
        vulnerability_type=vuln_type,
        severity="high",
        confidence=0.9,
        description="d",
        reasoning="r",
        references=[vuln_type],
    )


def test_cli_logic_has_explicit_public_api():
    assert "run_llm_inference_test" in cli_logic_all
    assert "normalize_cwe_and_apply_local_evidence_gate" in cli_logic_all
    assert "print_processing_stats" in cli_logic_all


def test_approx_tokens_and_backend_name_and_version():
    assert approx_tokens("") == 1
    assert approx_tokens("", allow_zero=True) == 0
    assert approx_tokens("abcd") == 1

    class B1:
        backend_name = "name-attr"
        backend_version = "ver-attr"

    assert backend_name_and_version(B1()) == ("name-attr", "ver-attr")

    class B2:
        def backend_name(self):
            return "name-fn"

        def backend_version(self):
            return "ver-fn"

    assert backend_name_and_version(B2()) == ("name-fn", "ver-fn")


def test_run_llm_inference_test_uses_injected_backend(monkeypatch, capsys):
    cfg = Config()
    cfg.inference.model = "fake.gguf"

    perf = iter([10.0, 10.5])
    rss = iter([100.0, 120.0, 130.0])
    monkeypatch.setattr("vulnllm.cli_logic.time.perf_counter", lambda: next(perf))
    monkeypatch.setattr("vulnllm.cli_logic.peak_rss_mb", lambda: next(rss))

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def backend_name(self):
            return "fake-backend"

        def backend_version(self):
            return "1.2.3"

        def generate(self, _prompt, _params):
            return InferenceResult(text="#judge: no", error=None, prompt_tokens=10, completion_tokens=20, total_tokens=30)

    rc = run_llm_inference_test(cfg, backend_factory=FakeBackend)
    out = capsys.readouterr().out

    assert rc == 0
    assert "backend: fake-backend" in out
    assert "backend_version: 1.2.3" in out
    assert "model_weights_memory_mb: 20.00" in out
    assert "memory_used_mb: 30.00" in out


def test_build_chunks_file_strategy_and_index_context(tmp_path: Path):
    root = tmp_path
    src = tmp_path / "main.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    chunks = build_chunks(src, root, "file", 128, 16)
    assert len(chunks) == 1
    assert chunks[0].file == "main.c"

    class FakeIndex:
        def build_context_packet(self, _symbol, current_file=None):
            return ""

        def query_symbol(self, _symbol):
            return [("main.c", 2), ("other.c", 9)]

    fn_chunk = CodeChunk(file="main.c", start_line=1, end_line=1, text="x", function="add")
    assert "Known symbol locations" in index_context(FakeIndex(), fn_chunk)


def test_finding_normalization_and_gates():
    chunk = CodeChunk(
        file="main.c",
        start_line=1,
        end_line=3,
        function="copy_name",
        text="void copy_name(char *dst, const char *src) { strcpy(dst, src); }",
    )
    f = _finding(chunk, "CWE-119")
    f.requires_caller_violation = True

    normalized = normalize_exploitability_classification([f])
    assert normalized[0].exploitability == "contract-break-only"

    gated = apply_phase15_acceptance_gates(normalized, chunk=chunk, base_index_context="ctx")
    assert gated == []

    f2 = _finding(chunk, "CWE-119")
    f2.evidence_spans = 0
    f2.analysis_mode = "shallow"
    out = normalize_cwe_and_apply_local_evidence_gate([f2], chunk=chunk)
    assert out and out[0].vulnerability_type == "CWE-120"

    sufficiency, score = non_llm_context_sufficiency(chunk, "ctx")
    assert sufficiency == "sufficient"
    assert score >= 2


def test_heuristic_fallback_findings_detects_multiple_types():
    chunk = CodeChunk(
        file="main.c",
        start_line=1,
        end_line=8,
        function="write_user_file",
        text=(
            "void write_user_file(const char *relative_path) {\n"
            "    char path[64];\n"
            "    strcpy(path, relative_path);\n"
            '    sprintf(path, "%s/%s", "./data", relative_path);\n'
            '    FILE *fp = fopen(path, "w");\n'
            "    int a = 2;\n"
            "    int b = 4;\n"
            "    return a * b;\n"
            "}\n"
        ),
    )
    findings, next_id = heuristic_fallback_findings(chunk, 1)
    vuln_types = {f.vulnerability_type for f in findings}
    assert {"CWE-120", "CWE-787", "CWE-22", "CWE-190"} <= vuln_types
    assert next_id == 5


def test_output_helpers_and_processing_stats(tmp_path: Path, capsys):
    cfg = Config()
    cfg.output_cfg.out_dir = str(tmp_path / "reports")
    cfg.output_cfg.out_prefix = "scan"
    cfg.output_cfg.formats = ["json", "md"]
    cfg.output_cfg.overwrite = True
    cfg.logging.prompt_output_md = str(tmp_path / "custom.md")

    outputs = collect_outputs(cfg)
    assert outputs["json"].name == "scan.json"
    assert prompt_output_log_path(cfg) == Path(cfg.logging.prompt_output_md)

    log_path = tmp_path / "prompt-log.md"
    log_path.write_text("# log\n", encoding="utf-8")
    chunk = CodeChunk(file="main.c", start_line=1, end_line=2, function="add", text="int add(void){return 1;}")
    append_exchange_header(log_path, 1, chunk, False)
    append_inference_metadata_section(log_path, timestamp_local="2026-03-14T10:00:00-03:00", context_size=8192, context_events=["x"], seed=3)
    append_prompt_section(log_path, "hello")
    append_output_section(log_path, "out", "err")
    payload = log_path.read_text(encoding="utf-8")
    assert "## Exchange 1" in payload
    assert "### Prompt" in payload
    assert "### Model Output" in payload
    assert "Error: `err`" in payload

    fenced = fenced_text_block("abc ``` xyz")
    assert fenced[0].startswith("````")

    print_processing_stats(
        successful_chunks=2,
        failed_chunks=1,
        total_exchange_tokens=30,
        total_exchange_time_sec=1.5,
        exchange_count=3,
        total_processing_time_sec=65.2,
    )
    out = capsys.readouterr().out
    assert "Processing stats" in out
    assert "total_processing_time_hhmmss: 00:01:05" in out

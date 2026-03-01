from __future__ import annotations

from pathlib import Path

from tests.model_utils import local_model_path, repo_root
from vulnllm.chunking.function_chunker import chunk_file_by_function
from vulnllm.config import Config
from vulnllm.findings.model import parse_findings
from vulnllm.inference.llama_backend import InferenceResult, LlamaBackend
from vulnllm.inference.parameters import mode_params
from vulnllm.prompt.base_prompt import build_prompt
from vulnllm.scanner.file_scanner import discover_files


FIXTURES_DIR = repo_root() / "tests" / "fixtures" / "embedded_vulns"


def test_embedded_fixture_chunking_contains_expected_functions():
    files = sorted(FIXTURES_DIR.glob("*.c"))
    chunk_functions: set[str] = set()

    for f in files:
        chunks = chunk_file_by_function(f, FIXTURES_DIR)
        for c in chunks:
            if c.function:
                chunk_functions.add(c.function)

    expected = {
        "unsafe_packet_copy",
        "append_crc_byte",
        "insecure_session_cleanup",
        "use_after_free_path",
        "configure_dma_transfer",
        "secret_key_copy",
    }
    assert expected.issubset(chunk_functions)


def test_embedded_fixture_mocked_detection_pipeline():
    cfg = Config(path=str(FIXTURES_DIR))
    cfg.inference.model = local_model_path()
    cfg.scan.languages = ["c"]

    files = discover_files(cfg.path, cfg.scan, cfg.files)
    chunks = []
    for p in files:
        chunks.extend(chunk_file_by_function(p, FIXTURES_DIR))

    backend = LlamaBackend(cfg)

    def fake_generate(prompt: str, _params):
        if "unsafe_packet_copy" in prompt:
            return InferenceResult(
                text=(
                    "#judge: yes\n"
                    "#type: Improper Length Validation\n"
                    "#confidence: high\n"
                    "#need_context: N/A\n"
                    "#why: Length field copied into fixed-size stack buffer."
                )
            )
        if "insecure_session_cleanup" in prompt:
            return InferenceResult(
                text=(
                    "#judge: yes\n"
                    "#type: Double Free\n"
                    "#confidence: high\n"
                    "#need_context: N/A\n"
                    "#why: session token may be freed twice."
                )
            )
        if "use_after_free_path" in prompt:
            return InferenceResult(
                text=(
                    "#judge: yes\n"
                    "#type: Use After Free\n"
                    "#confidence: high\n"
                    "#need_context: N/A\n"
                    "#why: Freed buffer is accessed."
                )
            )
        if "configure_dma_transfer" in prompt:
            return InferenceResult(
                text=(
                    "#judge: yes\n"
                    "#type: Integer Overflow\n"
                    "#confidence: high\n"
                    "#need_context: N/A\n"
                    "#why: Multiplication may overflow 16-bit accumulator."
                )
            )
        if "secret_key_copy" in prompt:
            return InferenceResult(
                text=(
                    "#judge: yes\n"
                    "#type: Key Material Exposure\n"
                    "#confidence: medium\n"
                    "#need_context: N/A\n"
                    "#why: Secret key is copied into debug log buffer."
                )
            )
        return InferenceResult(
            text="#judge: no\n#type: N/A\n#confidence: high\n#need_context: N/A\n#why: no vulnerability found"
        )

    backend.generate = fake_generate  # type: ignore[assignment]

    all_findings = []
    next_id = 1
    for c in chunks:
        prompt = build_prompt(cfg, c)
        result = backend.generate(prompt, mode_params(cfg))
        findings, next_id = parse_findings(result.text, c, start_id=next_id)
        all_findings.extend(findings)

    vuln_types = {f.vulnerability_type for f in all_findings}
    assert "Improper Length Validation" in vuln_types
    assert "Double Free" in vuln_types
    assert "Use After Free" in vuln_types
    assert "Integer Overflow" in vuln_types
    assert "Key Material Exposure" in vuln_types

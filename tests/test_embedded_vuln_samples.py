from __future__ import annotations

import json
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
        vulnerabilities = []
        if "unsafe_packet_copy" in prompt:
            vulnerabilities.append(
                {
                    "vulnerability_type": "Improper Length Validation",
                    "severity": "high",
                    "confidence": 0.92,
                    "description": "Length field copied into fixed-size stack buffer.",
                    "reasoning": "copy_len from packet controls memcpy length into local[64].",
                    "recommendation": "Validate copy_len <= sizeof(local)",
                    "references": ["CWE-120", "CWE-130"],
                }
            )
        if "insecure_session_cleanup" in prompt:
            vulnerabilities.append(
                {
                    "vulnerability_type": "Double Free",
                    "severity": "high",
                    "confidence": 0.89,
                    "description": "session token may be freed twice.",
                    "reasoning": "free is invoked twice on token through distinct branches.",
                    "recommendation": "Guard with single free and null assignment.",
                    "references": ["CWE-415"],
                }
            )
        if "use_after_free_path" in prompt:
            vulnerabilities.append(
                {
                    "vulnerability_type": "Use After Free",
                    "severity": "critical",
                    "confidence": 0.91,
                    "description": "Freed buffer is accessed.",
                    "reasoning": "tmp is freed and then dereferenced via tmp[0].",
                    "recommendation": "Do not dereference freed pointers.",
                    "references": ["CWE-416"],
                }
            )
        if "configure_dma_transfer" in prompt:
            vulnerabilities.append(
                {
                    "vulnerability_type": "Integer Overflow",
                    "severity": "high",
                    "confidence": 0.86,
                    "description": "Multiplication may overflow 16-bit accumulator.",
                    "reasoning": "desc->length * chunks stored in uint16_t total.",
                    "recommendation": "Use wider type and bounds check before multiply.",
                    "references": ["CWE-190"],
                }
            )
        if "secret_key_copy" in prompt:
            vulnerabilities.append(
                {
                    "vulnerability_type": "Key Material Exposure",
                    "severity": "medium",
                    "confidence": 0.78,
                    "description": "Secret key is copied into debug log buffer.",
                    "reasoning": "key bytes are copied to debug_log without redaction.",
                    "recommendation": "Avoid logging raw key material.",
                    "references": ["CWE-200"],
                }
            )

        return InferenceResult(text=json.dumps({"vulnerabilities": vulnerabilities}))

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

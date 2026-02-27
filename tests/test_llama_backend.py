from __future__ import annotations

import sys
import types
from pathlib import Path

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.findings.model import parse_findings
from vulnllm.inference.llama_backend import LlamaBackend
from vulnllm.inference.parameters import GenerationParams


def test_llama_backend_omits_none_threads_and_batch(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    captured: dict[str, object] = {}

    class FakeLlama:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FakeLlama))

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    cfg.inference.threads = None
    cfg.inference.batch = None

    LlamaBackend(cfg)

    assert "n_threads" not in captured
    assert "n_batch" not in captured


def test_llama_backend_returns_error_when_python_binding_unavailable(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    class FailingLlama:
        def __init__(self, **_kwargs):
            raise RuntimeError("import failed")

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FailingLlama))

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    backend = LlamaBackend(cfg)

    result = backend.generate(
        "scan this",
        GenerationParams(temperature=0.1, top_p=0.95, seed=0, max_tokens=64),
    )

    assert result.text == ""
    assert result.error == "llama-cpp-python backend unavailable: import failed"


def test_parse_findings_handles_prompt_echo_and_extra_json_text():
    raw = """
You are a code security reviewer. Return ONLY JSON:
{
  "vulnerabilities": [{"vulnerability_type":"example"}]
}

```json
{
  "vulnerabilities": [
    {
      "vulnerability_type": "Integer Overflow",
      "severity": "high",
      "confidence": 0.8,
      "description": "overflow",
      "reasoning": "reason",
      "recommendation": "fix",
      "references": ["CWE-190"]
    }
  ]
}
```
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "Integer Overflow"


def test_llama_backend_populates_usage_metrics(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    class FakeLlama:
        def __init__(self, **_kwargs):
            pass

        def create_completion(self, **_kwargs):
            return {
                "choices": [{"text": "ok"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 34, "total_tokens": 46},
            }

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FakeLlama))

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    backend = LlamaBackend(cfg)

    result = backend.generate(
        "scan this",
        GenerationParams(temperature=0.1, top_p=0.95, seed=0, max_tokens=64),
    )

    assert result.error is None
    assert result.prompt_tokens == 12
    assert result.completion_tokens == 34
    assert result.total_tokens == 46


def test_llama_backend_exposes_backend_library_version(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    class FakeLlama:
        def __init__(self, **_kwargs):
            pass

        def create_completion(self, **_kwargs):
            return {"choices": [{"text": "ok"}], "usage": {}}

    monkeypatch.setitem(
        sys.modules,
        "llama_cpp",
        types.SimpleNamespace(Llama=FakeLlama, __version__="0.3.2"),
    )

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    backend = LlamaBackend(cfg)

    assert backend.backend_name() == "llama-cpp-python"
    assert backend.backend_version() == "0.3.2"

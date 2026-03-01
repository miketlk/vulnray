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


def test_parse_findings_prefers_best_structured_json_over_later_noise():
    raw = """
{"vulnerabilities":[{"vulnerability_type":"Integer Overflow","severity":"high","confidence":0.9,"description":"d","reasoning":"r","recommendation":"fix","references":["CWE-190"]}]}

Human: let's keep going
{"vulnerabilities":[{"vulnerability_type":"NoisyTail"}]}
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "Integer Overflow"


def test_parse_findings_accepts_final_answer_format_yes():
    raw = """
<reasoning>
Potential out-of-bounds write through unchecked copy length.
</reasoning>
## Final Answer
#judge: yes
#type: CWE-787
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "CWE-787"
    assert "CWE-787" in findings[0].references


def test_parse_findings_accepts_final_answer_format_no():
    raw = """
## Final Answer
#judge: no
#type: N/A
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert findings == []


def test_parse_findings_parses_phase0_telemetry_fields():
    raw = """
{
  "vulnerabilities": [
    {
      "vulnerability_type": "CWE-125",
      "severity": "high",
      "confidence": 0.91,
      "description": "desc",
      "reasoning": "reason",
      "recommendation": "fix",
      "references": ["CWE-125"],
      "analysis_mode": "contract-aware",
      "evidence_spans": [{"line": 10}, {"line": 12}],
      "requires_caller_violation": "true",
      "context_sufficiency": "sufficient"
    }
  ]
}
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].analysis_mode == "contract-aware"
    assert findings[0].evidence_spans == 2
    assert findings[0].requires_caller_violation is True
    assert findings[0].context_sufficiency == "sufficient"


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


def test_llama_backend_retries_with_larger_context_on_overflow(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    created_contexts: list[int] = []

    class FakeLlama:
        def __init__(self, **kwargs):
            self.n_ctx = int(kwargs["n_ctx"])
            created_contexts.append(self.n_ctx)

        def create_completion(self, **_kwargs):
            if self.n_ctx < 9083:
                raise RuntimeError(f"Requested tokens (9083) exceed context window of {self.n_ctx}")
            return {"choices": [{"text": "ok"}], "usage": {}}

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FakeLlama))

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    cfg.inference.context = 4096
    backend = LlamaBackend(cfg)

    result = backend.generate(
        "scan this",
        GenerationParams(temperature=0.1, top_p=0.95, seed=0, max_tokens=64),
    )

    assert result.error is None
    assert result.context_size == 9083
    assert any("context increase: 4096 -> 9083" in e for e in result.context_events)
    assert any("context decrease: 9083 -> 4096" in e for e in result.context_events)
    assert result.timestamp_local is not None
    assert created_contexts == [4096, 9083]


def test_llama_backend_reports_error_when_context_max_exhausted(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    created_contexts: list[int] = []

    class FakeLlama:
        def __init__(self, **kwargs):
            self.n_ctx = int(kwargs["n_ctx"])
            created_contexts.append(self.n_ctx)

        def create_completion(self, **_kwargs):
            raise RuntimeError(f"Requested tokens (12000) exceed context window of {self.n_ctx}")

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FakeLlama))

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    cfg.inference.context = 4096
    cfg.inference.context_max = 8192
    backend = LlamaBackend(cfg)

    result = backend.generate(
        "scan this",
        GenerationParams(temperature=0.1, top_p=0.95, seed=0, max_tokens=64),
    )

    assert result.text == ""
    assert result.error is not None
    assert "Requested tokens (12000) exceed context window of 4096" in result.error
    assert "context=8192 inference failed" in result.error
    assert result.context_size == 4096
    assert any("context increase: 4096 -> 8192" in e for e in result.context_events)
    assert any("context decrease: 8192 -> 4096" in e for e in result.context_events)
    assert result.timestamp_local is not None
    assert created_contexts == [4096, 8192]


def test_llama_backend_reuses_cached_expanded_context_between_exchanges(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    created_contexts: list[int] = []

    class FakeLlama:
        def __init__(self, **kwargs):
            self.n_ctx = int(kwargs["n_ctx"])
            created_contexts.append(self.n_ctx)

        def create_completion(self, **_kwargs):
            if self.n_ctx < 9083:
                raise RuntimeError(f"Requested tokens (9083) exceed context window of {self.n_ctx}")
            return {"choices": [{"text": "ok"}], "usage": {}}

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FakeLlama))

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    cfg.inference.context = 4096
    backend = LlamaBackend(cfg)

    first = backend.generate(
        "scan this",
        GenerationParams(temperature=0.1, top_p=0.95, seed=0, max_tokens=64),
    )
    second = backend.generate(
        "scan this again",
        GenerationParams(temperature=0.1, top_p=0.95, seed=1, max_tokens=64),
    )

    assert first.error is None
    assert second.error is None
    assert first.context_size == 9083
    assert second.context_size == 9083
    assert created_contexts == [4096, 9083]

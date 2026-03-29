from __future__ import annotations

import sys
import types
from pathlib import Path

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.findings.model import (
    extract_complete_sane_formatted_output_block,
    extract_decision_metadata,
    parse_findings,
)
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


def test_parse_findings_handles_prompt_echo_and_example_block():
    raw = """
Output format (plain text, exactly these keys):
#judge: yes|no
#type: CWE-xx|N/A
#why: one short sentence

#judge: yes
#type: CWE-190
#why: overflow in multiplication path
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "CWE-190"


def test_parse_findings_prefers_last_valid_compact_block():
    raw = """
#judge: yes
#type: CWE-120
#why: intermediate answer

#judge: no
#type: N/A
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert findings == []


def test_parse_findings_accepts_compact_yes():
    raw = """
#judge: yes
#type: CWE-787
#confidence: high
#why: unchecked copy may overflow destination
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "CWE-787"
    assert "CWE-787" in findings[0].references
    assert findings[0].description == "Out-of-bounds write into a fixed-size buffer is possible."
    assert findings[0].reasoning == "unchecked copy may overflow destination"
    assert findings[0].confidence == 0.9


def test_parse_findings_accepts_evidence_structured_fields():
    raw = """
#context_sufficient: yes
#need_context: N/A
#missing_fact_kind: N/A
#judge: yes
#type: CWE-120
#confidence: medium
#claim: destination can overflow on oversized source
#sink: strcpy(dst, src)
#precondition: src length exceeds destination size
#where_precondition_is_enforced: none
#caller_violation_required: yes
#bounds_contradiction: no
#contract_breach_evidence: yes
#why: overflow path remains reachable
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].context_sufficiency == "sufficient"
    assert findings[0].claim == "destination can overflow on oversized source"
    assert findings[0].trigger_path == "strcpy(dst, src)"
    assert findings[0].precondition == "src length exceeds destination size"
    assert findings[0].where_precondition_is_enforced == "none"
    assert findings[0].requires_caller_violation is True
    assert findings[0].contract_breach_evidence is True
    assert findings[0].bounds_contradiction_evidence is False


def test_parse_findings_accepts_multiple_types_in_compact_yes():
    raw = """
#judge: yes
#type: CWE-787, CWE-22
#why: multiple distinct issues found
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 2
    assert findings[0].vulnerability_type == "CWE-787"
    assert findings[1].vulnerability_type == "CWE-22"
    assert findings[0].id == "F-0001"
    assert findings[1].id == "F-0002"


def test_parse_findings_accepts_compact_no():
    raw = """
#judge: no
#type: N/A
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert findings == []


def test_parse_findings_accepts_compact_block_without_confidence():
    raw = """
#judge: yes
#type: CWE-190
#why: unchecked multiplication path
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "CWE-190"
    assert findings[0].confidence == 0.7
    assert findings[0].description == "Unchecked integer multiplication may overflow."
    assert findings[0].reasoning == "unchecked multiplication path"


def test_parse_findings_sanitizes_embedded_structured_keys_in_why():
    raw = """
#judge: yes
#type: CWE-120
#why: strcpy used to copy user-controlled data into fixed buffer #judge: yes
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].reasoning == "strcpy used to copy user-controlled data into fixed buffer"
    assert "#judge:" not in findings[0].reasoning
    assert findings[0].description == "Unbounded strcpy into a fixed-size destination may overflow."


def test_parse_findings_sanitizes_type_and_function_markers_in_why():
    raw = """
#judge: yes
#type: CWE-22
#why: path reaches fopen without validation #type: CWE-22 #function: helper
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].reasoning == "path reaches fopen without validation"
    assert findings[0].description == "Unvalidated relative path reaches filesystem access."


def test_parse_findings_rejects_positive_when_why_is_empty_after_sanitization():
    raw = """
#judge: yes
#type: CWE-190
#why: #judge: yes
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert findings == []


def test_parse_findings_accepts_early_negative_without_why_when_no_context_requested():
    raw = """
#judge: no
#type: N/A
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)
    assert findings == []


def test_extract_decision_metadata_parses_compact_output():
    raw = """
#judge: yes
#type: CWE-120
#need_context: User, create_user
#why: unchecked copy into fixed buffer
"""
    cwes, symbols = extract_decision_metadata(raw)
    assert cwes == ["CWE-120"]
    assert symbols == ["User", "create_user"]


def test_extract_decision_metadata_parses_multiple_cwes():
    raw = """
#judge: yes
#type: CWE-120, CWE-22
#need_context: User, create_user
#why: two findings
"""
    cwes, symbols = extract_decision_metadata(raw)
    assert cwes == ["CWE-120", "CWE-22"]
    assert symbols == ["User", "create_user"]


def test_parse_findings_ignores_example_output_compact_block():
    raw = """
Example output:
#judge: yes|no
#type: CWE-xx|N/A
#why: one short sentence

#judge: yes
#type: CWE-787
#why: real finding
"""
    chunk = CodeChunk(file="test.c", start_line=1, end_line=10, text="int main(){}", function="main")
    findings, _ = parse_findings(raw, chunk)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "CWE-787"


def test_extract_complete_sane_formatted_output_block_skips_example_output():
    raw = """
Example output:
#judge: yes|no
#type: CWE-xx|N/A
#why: one short sentence

#judge: yes
#type: CWE-190
#why: real finding
extra tail
"""
    block = extract_complete_sane_formatted_output_block(raw)
    assert block is not None
    assert "#type: CWE-190" in block
    assert "#type: CWE-xx|N/A" not in block


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


def test_llama_backend_stops_early_after_complete_sane_formatted_block(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    yielded_tokens: list[str] = []
    tail = "\nTRAILING_TOKENS_SHOULD_NOT_BE_CONSUMED"
    streamed_text = (
        "#judge: yes\n"
        "#type: CWE-787\n"
        "#why: real finding\n"
        + tail
    )

    class FakeLlama:
        def __init__(self, **_kwargs):
            pass

        def create_completion(self, **kwargs):
            if kwargs.get("stream"):
                def _gen():
                    for ch in streamed_text:
                        yielded_tokens.append(ch)
                        yield {"choices": [{"text": ch}]}

                return _gen()
            return {"choices": [{"text": streamed_text}], "usage": {}}

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FakeLlama))

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    backend = LlamaBackend(cfg)

    result = backend.generate(
        "Output format (plain text, exactly these keys):\n#judge: yes|no\n#type: CWE-xx|N/A",
        GenerationParams(temperature=0.1, top_p=0.95, seed=0, max_tokens=256),
    )

    assert result.error is None
    assert result.text.endswith("#why: real finding")
    assert "TRAILING_TOKENS_SHOULD_NOT_BE_CONSUMED" not in result.text
    assert len(yielded_tokens) < len(streamed_text)


def test_llama_backend_stops_early_on_negative_without_context_request(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    yielded_tokens: list[str] = []
    tail = "\nTRAILING_TOKENS_SHOULD_NOT_BE_CONSUMED"
    streamed_text = (
        "#judge: no\n"
        "#type: N/A\n"
        + tail
    )

    class FakeLlama:
        def __init__(self, **_kwargs):
            pass

        def create_completion(self, **kwargs):
            if kwargs.get("stream"):
                def _gen():
                    for ch in streamed_text:
                        yielded_tokens.append(ch)
                        yield {"choices": [{"text": ch}]}

                return _gen()
            return {"choices": [{"text": streamed_text}], "usage": {}}

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FakeLlama))

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    backend = LlamaBackend(cfg)

    result = backend.generate(
        "Output format (plain text, exactly these keys):\n#judge: yes|no\n#type: CWE-xx|N/A",
        GenerationParams(temperature=0.1, top_p=0.95, seed=0, max_tokens=256),
    )

    assert result.error is None
    assert result.text == "#judge: no\n#type: N/A"
    assert "TRAILING_TOKENS_SHOULD_NOT_BE_CONSUMED" not in result.text
    assert len(yielded_tokens) < len(streamed_text)


def test_llama_backend_stops_early_for_sufficiency_block(tmp_path: Path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    yielded_tokens: list[str] = []
    tail = "\nTRAILING_TOKENS_SHOULD_NOT_BE_CONSUMED"
    streamed_text = (
        "#judge: no\n"
        "#function: helper, user_type\n"
        + tail
    )

    class FakeLlama:
        def __init__(self, **_kwargs):
            pass

        def create_completion(self, **kwargs):
            if kwargs.get("stream"):
                def _gen():
                    for ch in streamed_text:
                        yielded_tokens.append(ch)
                        yield {"choices": [{"text": ch}]}

                return _gen()
            return {"choices": [{"text": streamed_text}], "usage": {}}

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FakeLlama))

    cfg = Config(path=str(tmp_path))
    cfg.inference.model = str(model)
    backend = LlamaBackend(cfg)

    result = backend.generate(
        "Output format (plain text, exactly these keys):\n#judge: yes|no\n#function: N/A|symbol_a,symbol_b",
        GenerationParams(temperature=0.1, top_p=0.95, seed=0, max_tokens=256),
    )

    assert result.error is None
    assert result.text == "#judge: no\n#function: helper, user_type"
    assert "TRAILING_TOKENS_SHOULD_NOT_BE_CONSUMED" not in result.text
    assert len(yielded_tokens) < len(streamed_text)

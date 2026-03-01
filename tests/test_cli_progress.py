from __future__ import annotations

import logging
import sys
from pathlib import Path

from vulnllm.cli import run
from vulnllm.inference.llama_backend import InferenceResult


def _compact_yes(vuln_type: str, *, confidence: str = "high", why: str = "detected issue") -> str:
    return (
        f"#judge: yes\n"
        f"#type: {vuln_type}\n"
        f"#confidence: {confidence}\n"
        f"#need_context: N/A\n"
        f"#why: {why}"
    )


def _compact_no(*, why: str = "no vulnerability found") -> str:
    return (
        "#judge: no\n"
        "#type: N/A\n"
        "#confidence: high\n"
        "#need_context: N/A\n"
        f"#why: {why}"
    )


def test_progress_prints_during_multipass(monkeypatch, tmp_path: Path, capsys):
    src = tmp_path / "main.c"
    src.write_text(
        "int add(int a, int b) {\n"
        "    return a + b;\n"
        "}\n",
        encoding="utf-8",
    )
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(text=_compact_yes("CWE-200", confidence="medium", why="test finding"))

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--multi-pass",
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    rc = run()
    stdout = capsys.readouterr().out

    assert rc == 1
    assert "(pass1)" in stdout
    assert "(pass2)" in stdout


def test_prompt_output_log_writes_separated_exchanges(monkeypatch, tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text(
        "int add(int a, int b) {\n"
        "    return a + b;\n"
        "}\n",
        encoding="utf-8",
    )
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"
    log_file = out_dir / "scan.prompt_output.md"
    saw_prompt_during_generate = {"value": False}
    saw_output_during_generate = {"value": False}

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, prompt, _params):
            text = log_file.read_text(encoding="utf-8")
            saw_prompt_during_generate["value"] = "### Prompt" in text
            saw_output_during_generate["value"] = "### Model Output" in text
            return InferenceResult(
                text=_compact_no(),
                error=None,
                timestamp_local="2026-02-28T10:11:12-08:00",
                context_size=12288,
                context_events=[
                    "2026-02-28T10:11:10-08:00 context increase: 8192 -> 12288",
                    "2026-02-28T10:11:12-08:00 context decrease: 12288 -> 8192",
                ],
            )

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
            "--log-prompts",
            "--log-model-outputs",
        ],
    )

    rc = run()

    assert rc == 0
    assert log_file.exists()
    assert saw_prompt_during_generate["value"] is False
    assert saw_output_during_generate["value"] is False
    text = log_file.read_text(encoding="utf-8")
    assert "# Prompt/Model Output Log" in text
    assert "## Exchange 1" in text
    assert "\n---\n" in text
    assert "### Prompt" in text
    assert "### Inference Metadata" in text
    assert "- Timestamp: `2026-02-28T10:11:12-08:00`" in text
    assert "- Context size: `12288`" in text
    assert "- Seed: `0`" in text
    assert "context increase: 8192 -> 12288" in text
    assert "context decrease: 12288 -> 8192" in text
    assert "### Model Output" in text
    assert text.index("### Inference Metadata") < text.index("### Prompt")


def test_prompt_output_log_uses_safe_fence_for_embedded_backticks(monkeypatch, tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"
    log_file = out_dir / "scan.prompt_output.md"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(
                text='Output:\n```text\n#judge: no\n#type: N/A\n#confidence: high\n#need_context: N/A\n#why: none\n```',
                error=None,
            )

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
            "--log-prompts",
            "--log-model-outputs",
        ],
    )

    rc = run()

    assert rc == 0
    text = log_file.read_text(encoding="utf-8")
    assert "````text" in text
    assert text.count("````") >= 2


def test_dry_run_prints_files_without_inference(monkeypatch, tmp_path: Path, capsys):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int a(void) { return 1; }\n", encoding="utf-8")
    (tmp_path / "src" / "b.h").write_text("#pragma once\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("x\n", encoding="utf-8")

    class ShouldNotInitBackend:
        def __init__(self, _cfg):
            raise AssertionError("LlamaBackend should not be created in dry run mode")

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", ShouldNotInitBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--dry-run",
            "--lang",
            "c",
            "--include",
            "src/**/*.c",
        ],
    )

    rc = run()
    stdout = capsys.readouterr().out.strip().splitlines()

    assert rc == 0
    assert stdout == ["src/a.c"]


def test_export_code_writes_container_without_inference(monkeypatch, tmp_path: Path, capsys):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text(
        "int main(void) {\n"
        "  // note\n"
        "  return 0; /* done */\n"
        "}\n",
        encoding="utf-8",
    )
    out = tmp_path / "codebase.txt"

    class ShouldNotInitBackend:
        def __init__(self, _cfg):
            raise AssertionError("LlamaBackend should not be created in export mode")

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", ShouldNotInitBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--export-code",
            str(out),
            "--lang",
            "c",
            "--include",
            "src/**/*.c",
        ],
    )

    rc = run()
    stdout = capsys.readouterr().out.strip().splitlines()
    payload = out.read_text(encoding="utf-8")

    assert rc == 0
    assert stdout == [str(out)]
    assert "CODEBASE_CONTAINER v1" in payload
    assert "- path: src/a.c" in payload
    assert "PATH: src/a.c" in payload
    assert "> int main(void) {" in payload
    assert "note" not in payload
    assert "done" not in payload


def test_llm_inference_test_ignores_scan_path_and_reports_metrics(monkeypatch, tmp_path: Path, capsys):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def backend_name(self):
            return "fake-backend"

        def backend_version(self):
            return "9.9.9"

        def generate(self, _prompt, _params):
            return InferenceResult(
                text=_compact_no(),
                prompt_tokens=20,
                completion_tokens=40,
                total_tokens=60,
            )

    def _should_not_scan(*_args, **_kwargs):
        raise AssertionError("discover_files should not be called in --llm-inference-test mode")

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr("vulnllm.cli.discover_files", _should_not_scan)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path / "does_not_matter"),
            "--model",
            str(model),
            "--llm-inference-test",
        ],
    )

    rc = run()
    stdout = capsys.readouterr().out

    assert rc == 0
    assert "LLM inference benchmark" in stdout
    assert "backend: fake-backend" in stdout
    assert "backend_version: 9.9.9" in stdout
    assert "tokens_per_sec:" in stdout
    assert "model_weights_memory_mb:" in stdout
    assert "memory_used_mb:" in stdout


def test_scan_skips_chunk_when_inference_fails(monkeypatch, tmp_path: Path, capsys, caplog):
    src = tmp_path / "main.c"
    src.write_text(
        "int add(int a, int b) {\n"
        "    return a + b;\n"
        "}\n",
        encoding="utf-8",
    )
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(text="", error="llama-cpp-python failure: Requested tokens (9083) exceed context window of 8192")

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    caplog.set_level(logging.WARNING, logger="vulnllm")
    rc = run()
    capsys.readouterr()

    assert rc == 0
    assert "Skipping function due to inference error" in caplog.text


def test_scan_continues_when_llm_exchange_raises_exception(monkeypatch, tmp_path: Path, capsys, caplog):
    src = tmp_path / "main.c"
    src.write_text(
        "int foo(int x) {\n"
        "    return x + 1;\n"
        "}\n"
        "\n"
        "int bar(int x) {\n"
        "    return x + 2;\n"
        "}\n",
        encoding="utf-8",
    )
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"
    calls = {"n": 0}

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transport timeout")
            return InferenceResult(text=_compact_no(), error=None)

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    caplog.set_level(logging.WARNING, logger="vulnllm")
    rc = run()
    captured = capsys.readouterr()

    assert rc == 0
    assert calls["n"] >= 2
    assert "Skipping function due to exchange exception" in caplog.text
    assert "Processing stats" in captured.out


def test_scan_prints_processing_stats(monkeypatch, tmp_path: Path, capsys):
    src = tmp_path / "main.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(
                text=_compact_no(),
                error=None,
                prompt_tokens=20,
                completion_tokens=10,
                total_tokens=30,
            )

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    rc = run()
    stdout = capsys.readouterr().out

    assert rc == 0
    assert "Processing stats" in stdout
    assert "successfully_processed_chunks_functions:" in stdout
    assert "failed_chunks_functions:" in stdout
    assert "average_tokens_per_second:" in stdout
    assert "average_exchange_time_sec:" in stdout
    assert "total_processing_time_sec:" in stdout
    assert "total_processing_time_hhmmss:" in stdout


def test_function_filter_scans_only_selected_function(monkeypatch, tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text(
        "int foo(int x) {\n"
        "    return x + 1;\n"
        "}\n"
        "\n"
        "int bar(int x) {\n"
        "    return x + 2;\n"
        "}\n",
        encoding="utf-8",
    )
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"
    prompts: list[str] = []

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, prompt, _params):
            prompts.append(prompt)
            return InferenceResult(text=_compact_no(), error=None)

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--function",
            "bar",
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    rc = run()

    assert rc == 0
    assert len(prompts) == 1
    assert "int bar(int x)" in prompts[0]
    assert "int foo(int x)" not in prompts[0]


def test_scan_marks_chunk_unresolved_on_unparsable_output_without_retry(monkeypatch, tmp_path: Path, caplog):
    src = tmp_path / "main.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"
    seen_seeds: list[int] = []
    calls = {"n": 0}

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, params):
            calls["n"] += 1
            seen_seeds.append(params.seed)
            return InferenceResult(text="invalid-output", error=None)

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--seed",
            "7",
            "--retries",
            "0",
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    caplog.set_level(logging.WARNING, logger="vulnllm")
    rc = run()

    assert rc == 0
    assert calls["n"] == 1
    assert seen_seeds == [7]
    assert "Unparsable model output; retrying" not in caplog.text
    assert "Marking chunk unresolved due to unparsable model output" in caplog.text


def test_scan_retries_unparsable_output_with_different_seed(monkeypatch, tmp_path: Path, caplog):
    src = tmp_path / "main.c"
    src.write_text("int mul(int a, int b) { return a * b; }\n", encoding="utf-8")
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"
    seen_seeds: list[int] = []
    calls = {"n": 0}

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, params):
            calls["n"] += 1
            seen_seeds.append(params.seed)
            if calls["n"] == 1:
                return InferenceResult(text="invalid-output", error=None)
            return InferenceResult(
                text=_compact_yes("CWE-190", confidence="medium", why="d"),
                error=None,
            )

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--seed",
            "7",
            "--retries",
            "2",
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    caplog.set_level(logging.WARNING, logger="vulnllm")
    rc = run()

    assert rc == 1
    assert seen_seeds == [7, 8]
    assert "Unparsable model output; retrying with different seed" in caplog.text
    assert "Marking chunk unresolved due to unparsable model output" not in caplog.text


def test_scan_uses_heuristic_fallback_for_unparsable_unsafe_sink(monkeypatch, tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text(
        "void write_user_file(const char *relative_path) {\n"
        "    char path[64];\n"
        '    sprintf(path, "%s/%s", "./data", relative_path);\n'
        '    FILE *fp = fopen(path, "w");\n'
        "    if (fp) fclose(fp);\n"
        "}\n",
        encoding="utf-8",
    )
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(text="invalid-output", error=None)

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    rc = run()
    report = (out_dir / "scan.json").read_text(encoding="utf-8")
    assert rc == 1
    assert "CWE-787" in report
    assert "CWE-22" in report


def test_scan_accepts_compact_output_wrapped_in_fence(monkeypatch, tmp_path: Path, caplog):
    src = tmp_path / "main.c"
    src.write_text(
        "int add(size_t size, int a, int b) {\n"
        "    if (size < 8) return a;\n"
        "    VERIFY_CHECK(size < 1024);\n"
        "    return a + b;\n"
        "}\n",
        encoding="utf-8",
    )
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"
    seen_seeds: list[int] = []

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, params):
            seen_seeds.append(params.seed)
            return InferenceResult(
                text="```text\n#judge: yes\n#type: CWE-200\n#confidence: high\n#need_context: N/A\n#why: d\n```",
                error=None,
            )

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--seed",
            "11",
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    caplog.set_level(logging.WARNING, logger="vulnllm")
    rc = run()

    assert rc == 1
    assert seen_seeds == [11]
    assert "Marking chunk unresolved due to unparsable model output" not in caplog.text


def test_scan_accepts_findings_without_evidence_spans_after_gate_relaxation(monkeypatch, tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text(
        "void copy_name(char *dst, const char *src) {\n"
        "    strcpy(dst, src);\n"
        "}\n",
        encoding="utf-8",
    )
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(text=_compact_yes("CWE-120", why="d"), error=None)

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    rc = run()
    assert rc == 1


def test_scan_drops_memory_cwe_without_local_memory_evidence(monkeypatch, tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(text=_compact_yes("CWE-120", why="d"), error=None)

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    rc = run()
    assert rc == 0


def test_scan_accepts_calibrated_cwe_without_bounds_contradiction_after_gate_relaxation(monkeypatch, tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text("int mul(int a, int b) { return a * b; }\n", encoding="utf-8")
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(text=_compact_yes("CWE-190", why="d"), error=None)

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            str(tmp_path),
            "--lang",
            "c",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    rc = run()
    assert rc == 1

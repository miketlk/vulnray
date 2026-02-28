from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from vulnllm.cli import run
from vulnllm.inference.llama_backend import InferenceResult


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
            return InferenceResult(
                text=json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "vulnerability_type": "Test",
                                "severity": "low",
                                "confidence": 0.5,
                                "description": "d",
                                "reasoning": "r",
                                "recommendation": "x",
                                "references": ["CWE-000"],
                            }
                        ]
                    }
                )
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
            saw_prompt_during_generate["value"] = "Prompt:" in text
            saw_output_during_generate["value"] = "Model Output:" in text
            return InferenceResult(
                text=json.dumps({"vulnerabilities": []}),
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
    assert saw_prompt_during_generate["value"] is True
    assert saw_output_during_generate["value"] is False
    text = log_file.read_text(encoding="utf-8")
    assert "# Prompt/Model Output Log" in text
    assert "## Exchange 1" in text
    assert "\n---\n" in text
    assert "Prompt:" in text
    assert "Inference Metadata:" in text
    assert "- Timestamp: `2026-02-28T10:11:12-08:00`" in text
    assert "- Context size: `12288`" in text
    assert "context increase: 8192 -> 12288" in text
    assert "context decrease: 12288 -> 8192" in text
    assert "Model Output:" in text


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
                text='{"vulnerabilities":[]}',
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
            return InferenceResult(text=json.dumps({"vulnerabilities": []}), error=None)

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

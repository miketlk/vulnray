from __future__ import annotations

import json
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
            "vulnllm-scan",
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
            return InferenceResult(text=json.dumps({"vulnerabilities": []}), error=None)

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnllm-scan",
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
    assert "Model Output:" in text

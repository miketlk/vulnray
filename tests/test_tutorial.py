from __future__ import annotations

import json
import sys
from pathlib import Path

from vulnllm.cli import run
from vulnllm.inference.llama_backend import InferenceResult


def test_tutorial_command_generates_all_reports_with_python_backend(monkeypatch, tmp_path: Path):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF")
    out_dir = tmp_path / "reports"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(text=json.dumps({"vulnerabilities": []}), error=None)

    monkeypatch.setattr("vulnllm.cli.LlamaBackend", FakeBackend)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnray",
            "tutorial/test_project",
            "--config",
            "tutorial/vulnllm.toml",
            "--model",
            str(model),
            "--out-dir",
            str(out_dir),
            "--overwrite",
        ],
    )

    rc = run()

    assert rc == 0
    assert (out_dir / "demo_scan.json").exists()
    assert (out_dir / "demo_scan.csv").exists()
    assert (out_dir / "demo_scan.md").exists()
    assert (out_dir / "demo_scan.prompt_output.md").exists()

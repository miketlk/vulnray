from __future__ import annotations

import json
from pathlib import Path

from vulnllm.config import Config
from vulnllm.inference.llama_backend import InferenceResult
from vulnllm.scan_runner import __all__ as scan_runner_all
from vulnllm.scan_runner import run_scan


def _compact_yes(vuln_type: str) -> str:
    return (
        f"#judge: yes\n"
        f"#type: {vuln_type}\n"
        "#confidence: high\n"
        "#need_context: N/A\n"
        "#why: detected issue"
    )


def _compact_no() -> str:
    return (
        "#judge: no\n"
        "#type: N/A\n"
        "#confidence: high\n"
        "#need_context: N/A\n"
        "#why: no vulnerability found"
    )


def _cfg(tmp_path: Path) -> Config:
    cfg = Config(path=str(tmp_path))
    cfg.project.index = "off"
    cfg.output_cfg.formats = ["json"]
    cfg.output_cfg.out_dir = str(tmp_path / "reports")
    cfg.output_cfg.out_prefix = "scan"
    cfg.output_cfg.overwrite = True
    cfg.logging.progress = False
    cfg.inference.retries = 0
    cfg.inference.model = "fake.gguf"
    return cfg


def test_scan_runner_public_api_exports_run_scan():
    assert scan_runner_all == ["run_scan"]


def test_run_scan_returns_zero_for_no_findings(tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    cfg = _cfg(tmp_path)

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(text=_compact_no(), error=None)

    rc = run_scan(cfg, root=tmp_path, files=[src], backend_factory=FakeBackend)

    assert rc == 0
    payload = json.loads((tmp_path / "reports" / "scan.json").read_text(encoding="utf-8"))
    assert payload["summary"]["total_findings"] == 0


def test_run_scan_returns_one_and_writes_finding(tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text("int mul(int a, int b) { return a * b; }\n", encoding="utf-8")
    cfg = _cfg(tmp_path)

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, _prompt, _params):
            return InferenceResult(text=_compact_yes("CWE-190"), error=None)

    rc = run_scan(cfg, root=tmp_path, files=[src], backend_factory=FakeBackend)

    assert rc == 1
    payload = json.loads((tmp_path / "reports" / "scan.json").read_text(encoding="utf-8"))
    assert payload["summary"]["total_findings"] == 1
    assert payload["findings"][0]["vulnerability_type"] == "CWE-190"

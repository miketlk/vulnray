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
        "#why: detected issue"
    )


def _compact_no() -> str:
    return "#judge: no\n#type: N/A"


def _compact_sufficiency_yes() -> str:
    return "#judge: yes\n#function: N/A"


def _compact_sufficiency_no(symbols: str = "helper") -> str:
    return f"#judge: no\n#function: {symbols}"


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

        def generate(self, prompt, _params):
            if "#function: N/A|symbol_a,symbol_b" in prompt:
                return InferenceResult(text=_compact_sufficiency_yes(), error=None)
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

        def generate(self, prompt, _params):
            if "#function: N/A|symbol_a,symbol_b" in prompt:
                return InferenceResult(text=_compact_sufficiency_yes(), error=None)
            return InferenceResult(text=_compact_yes("CWE-190"), error=None)

    rc = run_scan(cfg, root=tmp_path, files=[src], backend_factory=FakeBackend)

    assert rc == 1
    payload = json.loads((tmp_path / "reports" / "scan.json").read_text(encoding="utf-8"))
    assert payload["summary"]["total_findings"] == 1
    assert payload["findings"][0]["vulnerability_type"] == "CWE-190"


def test_run_scan_writes_sarif_output(tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text("int mul(int a, int b) { return a * b; }\n", encoding="utf-8")
    cfg = _cfg(tmp_path)
    cfg.output_cfg.formats = ["sarif"]

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, prompt, _params):
            if "#function: N/A|symbol_a,symbol_b" in prompt:
                return InferenceResult(text=_compact_sufficiency_yes(), error=None)
            return InferenceResult(text=_compact_yes("CWE-190"), error=None)

    rc = run_scan(cfg, root=tmp_path, files=[src], backend_factory=FakeBackend)
    assert rc == 1
    sarif_path = tmp_path / "reports" / "scan.sarif"
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert len(payload["runs"][0]["results"]) == 1


def test_run_scan_retrieval_pass_retries_with_requested_symbols(tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text(
        "int helper(int x) { return x + 1; }\n"
        "int target(int x) { int y = helper(x); return x * y; }\n",
        encoding="utf-8",
    )
    cfg = _cfg(tmp_path)
    cfg.project.index = "basic"
    cfg.scan.function = "target"
    calls = {"count": 0}

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, prompt, _params):
            calls["count"] += 1
            if "#function: N/A|symbol_a,symbol_b" in prompt:
                if "Retrieved symbols:" in prompt:
                    return InferenceResult(text=_compact_sufficiency_yes(), error=None)
                return InferenceResult(text=_compact_sufficiency_no("helper"), error=None)
            return InferenceResult(text=_compact_yes("CWE-190"), error=None)

    rc = run_scan(cfg, root=tmp_path, files=[src], backend_factory=FakeBackend)

    assert rc == 1
    assert calls["count"] >= 2


def test_run_scan_mixed_json_and_sarif_outputs(tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text("int mul(int a, int b) { return a * b; }\n", encoding="utf-8")
    cfg = _cfg(tmp_path)
    cfg.output_cfg.formats = ["json", "sarif"]

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, prompt, _params):
            if "#function: N/A|symbol_a,symbol_b" in prompt:
                return InferenceResult(text=_compact_sufficiency_yes(), error=None)
            return InferenceResult(text=_compact_yes("CWE-190"), error=None)

    rc = run_scan(cfg, root=tmp_path, files=[src], backend_factory=FakeBackend)
    assert rc == 1
    json_path = tmp_path / "reports" / "scan.json"
    sarif_path = tmp_path / "reports" / "scan.sarif"
    assert json_path.exists()
    assert sarif_path.exists()


def test_sarif_uses_final_deduplicated_and_truncated_findings(tmp_path: Path):
    src1 = tmp_path / "a.c"
    src2 = tmp_path / "b.c"
    src1.write_text("int mul1(int a, int b) { return a * b; }\n", encoding="utf-8")
    src2.write_text("int mul2(int a, int b) { return a * b; }\n", encoding="utf-8")
    cfg = _cfg(tmp_path)
    cfg.output_cfg.formats = ["sarif"]
    cfg.scan.max_findings = 1

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, prompt, _params):
            if "#function: N/A|symbol_a,symbol_b" in prompt:
                return InferenceResult(text=_compact_sufficiency_yes(), error=None)
            return InferenceResult(text=_compact_yes("CWE-190"), error=None)

    rc = run_scan(cfg, root=tmp_path, files=[src1, src2], backend_factory=FakeBackend)
    assert rc == 1
    sarif_path = tmp_path / "reports" / "scan.sarif"
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert len(payload["runs"][0]["results"]) == 1


def test_run_scan_records_unresolved_chunk_telemetry(tmp_path: Path):
    src = tmp_path / "main.c"
    src.write_text(
        "int helper(int x) { return x + 1; }\n"
        "int target(int x) { return helper(x); }\n",
        encoding="utf-8",
    )
    cfg = _cfg(tmp_path)
    cfg.project.index = "basic"
    cfg.scan.function = "target"

    class FakeBackend:
        def __init__(self, _cfg):
            pass

        def generate(self, prompt, _params):
            if "#function: N/A|symbol_a,symbol_b" in prompt:
                return InferenceResult(text=_compact_sufficiency_no("missing_symbol"), error=None)
            raise AssertionError("detection should not run for unresolved sufficiency")

    rc = run_scan(cfg, root=tmp_path, files=[src], backend_factory=FakeBackend)

    assert rc == 0
    payload = json.loads((tmp_path / "reports" / "scan.json").read_text(encoding="utf-8"))
    assert payload["summary"]["total_findings"] == 0
    assert payload["summary"]["telemetry"]["unresolved_chunks"] == 1
    assert payload["summary"]["telemetry"]["retrieval_rounds_used"] == 0

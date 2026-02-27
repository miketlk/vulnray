from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_bench_outputs_throughput_metrics():
    root = Path(__file__).resolve().parents[1]
    fixture_dir = root / "tests" / "fixtures" / "embedded_vulns"
    bench = root / "scripts" / "bench.py"

    proc = subprocess.run(
        [sys.executable, str(bench), str(fixture_dir), "--chunk-strategy", "function"],
        capture_output=True,
        text=True,
        check=True,
    )

    out = proc.stdout
    assert "files/sec:" in out
    assert "tokens/sec:" in out
    assert "files:" in out
    assert "chunks:" in out

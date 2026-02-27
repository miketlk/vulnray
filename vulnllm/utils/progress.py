from __future__ import annotations


def maybe_progress(enabled: bool, current: int, total: int, label: str) -> None:
    if not enabled:
        return
    print(f"[{current}/{total}] {label}", flush=True)

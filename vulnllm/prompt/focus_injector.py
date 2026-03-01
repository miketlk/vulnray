from __future__ import annotations

from pathlib import Path


def build_focus_block(focus: list[str], prompt_file: str | None) -> str:
    blocks: list[str] = []
    if focus:
        blocks.append("Focus: " + ", ".join(focus))
    if prompt_file:
        text = Path(prompt_file).read_text(encoding="utf-8", errors="ignore")
        blocks.append("User focus: " + text.strip())
    return "\n\n".join(blocks).strip()

from __future__ import annotations

import json

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.prompt.focus_injector import build_focus_block
from vulnllm.prompt.profiles.embedded_c import EMBEDDED_C_GUIDANCE

SYSTEM_PROMPT = """
You are a code security reviewer. Analyze the given C code chunk for vulnerabilities.
Return ONLY JSON using this shape:
{
  "vulnerabilities": [
    {
      "vulnerability_type": "string",
      "severity": "low|medium|high|critical",
      "confidence": 0.0,
      "description": "short explanation",
      "reasoning": "detailed reasoning",
      "recommendation": "how to fix",
      "references": ["CWE-xxx"]
    }
  ]
}
If no vulnerabilities are found, return {"vulnerabilities": []}.
""".strip()


def build_prompt(cfg: Config, chunk: CodeChunk, index_context: str = "") -> str:
    profile = EMBEDDED_C_GUIDANCE if cfg.prompt.profile == "embedded-c" else ""
    focus = build_focus_block(cfg.prompt.focus, cfg.prompt.prompt_file)
    metadata = {
        "file": chunk.file,
        "start_line": chunk.start_line,
        "end_line": chunk.end_line,
        "function": chunk.function,
        "mode": cfg.scan.mode,
    }
    parts = [SYSTEM_PROMPT, profile]
    if focus:
        parts.append(focus)
    if index_context:
        parts.append("Project context:\n" + index_context)
    parts.append("Chunk metadata:\n" + json.dumps(metadata, indent=2))
    parts.append("Code:\n```c\n" + chunk.text + "\n```")
    return "\n\n".join(p for p in parts if p)

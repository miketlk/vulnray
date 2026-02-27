from __future__ import annotations

import json

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.prompt.focus_injector import build_focus_block
from vulnllm.prompt.profiles.embedded_c import EMBEDDED_C_GUIDANCE

SYSTEM_PROMPT = """
You are an advanced vulnerability detection model.
Your task is to decide whether the target function is vulnerable.
The input code can include helper context and target code, separated by:
- // context
- // target function

Reason about memory safety, integer bounds, pointer validity, lifetime, trust boundaries,
and privilege-sensitive behavior before deciding.

Return ONLY JSON using this shape:
{
  "final_answer": {
    "judge": "yes|no",
    "type": "CWE-xx|N/A"
  },
  "vulnerabilities": [
    {
      "vulnerability_type": "CWE-xx",
      "severity": "low|medium|high|critical",
      "confidence": 0.0,
      "description": "short explanation",
      "reasoning": "detailed reasoning",
      "recommendation": "how to fix",
      "references": ["CWE-xxx"]
    }
  ]
}

Constraints:
- If judge is "yes", use exactly one most probable CWE in final_answer.type.
- If judge is "no", final_answer.type must be "N/A" and vulnerabilities must be [].
- Do not wrap JSON in markdown.
""".strip()


def _as_comment_block(text: str) -> str:
    lines = text.splitlines() or ["N/A"]
    return "\n".join("// " + line if line else "//" for line in lines)


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
    parts.append("Chunk metadata:\n" + json.dumps(metadata, indent=2))
    context_text = _as_comment_block(index_context.strip() or "N/A")
    code_snippet = "\n".join(["// context", context_text, "// target function", chunk.text])
    parts.append("Code snippet:\n```c\n" + code_snippet + "\n```")
    return "\n\n".join(p for p in parts if p)

from __future__ import annotations

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.prompt.focus_injector import build_focus_block
from vulnllm.prompt.profiles.embedded_c import EMBEDDED_C_GUIDANCE

SYSTEM_PROMPT = """
You are a vulnerability detection model for C/C++ code.
Analyze one target function with optional helper context.
Input sections are separated by:
- // context
- // target function

Return one JSON payload:
BEGIN_FINDINGS_JSON
{
  "candidate_cwes": ["CWE-xx", "CWE-yy"],
  "final_answer": {
    "judge": "yes|no",
    "type": "CWE-xx|N/A"
  },
  "missing_context_symbols": ["symbol_name"],
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
END_FINDINGS_JSON

Rules:
- Produce 2-5 candidate CWEs.
- If judge=yes, use exactly one CWE in final_answer.type and keep it consistent with vulnerabilities.
- If judge=no, set type=N/A and vulnerabilities=[].
- Prefer one primary vulnerability, but include up to two findings when distinct high-impact root causes coexist in the same function.
- If context is insufficient, prefer judge=no and list missing_context_symbols.
- Do not report speculative callee-only issues in wrapper/dispatcher functions; if issue depends on unseen callee internals, use missing_context_symbols and judge=no.
- Optional telemetry fields are allowed: claim, precondition, where_precondition_is_enforced, trigger_path, exploitability, contract_breach_evidence, attacker_controlled_input, bounds_contradiction_evidence.
- For fixed-size buffer + sprintf/strcpy sinks, include a memory corruption finding even when another issue (e.g., path traversal) is also present.
- For unchecked integer multiplication on signed/width-limited ints, include CWE-190 when no bounds check is visible.
- Output compact JSON only once. No markdown fences. No repeated payloads. No explanations.
- Do not add prose outside BEGIN/END markers.
""".strip()


def _as_comment_block(text: str) -> str:
    lines = text.splitlines() or ["N/A"]
    return "\n".join("// " + line if line else "//" for line in lines)


def _strip_c_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    in_line_comment = False
    in_block_comment = False
    in_string = False
    in_char = False
    escaping = False

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append("\n")
            i += 1
            continue

        if in_block_comment:
            if ch == "\n":
                out.append("\n")
                i += 1
                continue
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_string:
            out.append(ch)
            if escaping:
                escaping = False
            elif ch == "\\":
                escaping = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if in_char:
            out.append(ch)
            if escaping:
                escaping = False
            elif ch == "\\":
                escaping = True
            elif ch == "'":
                in_char = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "'":
            in_char = True
            out.append(ch)
            i += 1
            continue

        out.append(ch)
        i += 1

    stripped = "".join(out)
    lines = stripped.splitlines(keepends=True)
    collapsed: list[str] = []
    prev_blank = False
    for line in lines:
        is_blank = line.strip() == ""
        if is_blank and prev_blank:
            continue
        if is_blank:
            # Canonicalize whitespace-only lines to a true empty line.
            collapsed.append("\n" if line.endswith("\n") else "")
        else:
            collapsed.append(line)
        prev_blank = is_blank

    return "".join(collapsed)


def build_prompt(cfg: Config, chunk: CodeChunk, index_context: str = "") -> str:
    profile = EMBEDDED_C_GUIDANCE if cfg.prompt.profile == "embedded-c" else ""
    focus = build_focus_block(cfg.prompt.focus, cfg.prompt.prompt_file)
    metadata = (
        f"file={chunk.file}, lines={chunk.start_line}-{chunk.end_line}, "
        f"function={chunk.function or 'N/A'}, mode={cfg.scan.mode}"
    )
    parts = [SYSTEM_PROMPT, profile]
    if focus:
        parts.append(focus)
    parts.append("Chunk metadata: " + metadata)
    context_text = _as_comment_block(index_context.strip() or "N/A")
    code_snippet = "\n".join(["// context", context_text, "// target function", _strip_c_comments(chunk.text)])
    parts.append("Code snippet:\n```c\n" + code_snippet + "\n```")
    return "\n\n".join(p for p in parts if p)

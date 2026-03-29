from __future__ import annotations

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.prompt.focus_injector import build_focus_block
from vulnllm.prompt.profiles.embedded_c import EMBEDDED_C_GUIDANCE

SYSTEM_PROMPT_DETECTION = """
You are a vulnerability detection model for C/C++ code.
Analyze one target function with decisive context only.
Input sections are separated by:
- // context
- // target function

Output format (plain text, exactly these keys):
#judge: yes|no
#type: CWE-xx|N/A

Rules:
- If judge=yes, #type must contain only CWE values from Allowed CWE policy.
- If judge=no, set #type: N/A.
- Do not guess based only on hypothetical caller misuse.
- Use sink-matched CWE mapping:
  - strcpy/strcat/gets into fixed buffer -> CWE-120
  - sprintf into fixed buffer -> CWE-787
  - unvalidated file path composition/open -> CWE-22
- Report CWE-190 only when arithmetic overflow is visible from shown code and facts.
- Do not output JSON, markdown fences, or extra prose.
""".strip()

SYSTEM_PROMPT_SUFFICIENCY = """
You are a vulnerability detection model for C/C++ code.
Decide whether the shown context is sufficient to judge the target function.
Input sections are separated by:
- // context
- // target function

Output format (plain text, exactly these keys):
#judge: yes|no
#function: N/A|symbol_a,symbol_b

Rules:
- If context is sufficient, output:
  #judge: yes
  #function: N/A
- If context is insufficient, output:
  #judge: no
  #function: exact symbol or type names needed, separated by commas
- Request at most 2 symbols.
- Prefer exact function or type names already visible in the code/context.
- Do not output JSON, markdown fences, or extra prose.
""".strip()


def _targeted_cwe_instruction(allowed_cwe_policy: tuple[str, ...]) -> str:
    cwes = [cwe.upper() for cwe in allowed_cwe_policy if cwe.upper().startswith("CWE-")]
    if len(cwes) != 1:
        return ""
    target = cwes[0]
    return (
        f"Targeted follow-up check: decide only whether {target} is present in the target function.\n"
        f"- If {target} is present, output:\n"
        "  #judge: yes\n"
        f"  #type: {target}\n"
        "- If it is not present, output:\n"
        "  #judge: no\n"
        "  #type: N/A\n"
        "- Ignore other vulnerability classes during this follow-up check."
    )


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


def _fact_priority(line: str) -> tuple[int, str]:
    normalized = line.strip().lstrip("-").strip().lower()
    if normalized.startswith("struct field extent:"):
        return (0, normalized)
    if normalized.startswith("sink extent:"):
        return (1, normalized)
    if normalized.startswith("assertion-proven range:"):
        return (2, normalized)
    if normalized.startswith("branch contradiction:"):
        return (3, normalized)
    if normalized.startswith("fixed-size write:"):
        return (4, normalized)
    if normalized.startswith("array extent:"):
        return (5, normalized)
    if normalized.startswith("integer type:"):
        return (8, normalized)
    return (6, normalized)


def _rank_preprocessing_facts(facts: tuple[str, ...], *, limit: int = 8) -> list[str]:
    return sorted(facts, key=_fact_priority)[:limit]


def build_prompt(
    cfg: Config,
    chunk: CodeChunk,
    index_context: str = "",
    allowed_cwe_policy: tuple[str, ...] = (),
    *,
    prompt_kind: str = "detection",
) -> str:
    profile = EMBEDDED_C_GUIDANCE if cfg.prompt.profile == "embedded-c" else ""
    focus = build_focus_block(cfg.prompt.focus, cfg.prompt.prompt_file)
    metadata = (
        f"file={chunk.file}, lines={chunk.start_line}-{chunk.end_line}, "
        f"function={chunk.function or 'N/A'}, mode={cfg.scan.mode}"
    )
    if prompt_kind == "sufficiency":
        system_prompt = SYSTEM_PROMPT_SUFFICIENCY
    else:
        system_prompt = SYSTEM_PROMPT_DETECTION
    parts = [system_prompt, profile]
    targeted_instruction = _targeted_cwe_instruction(allowed_cwe_policy) if prompt_kind == "detection" else ""
    if targeted_instruction:
        parts.append(targeted_instruction)
    if focus:
        parts.append(focus)
    parts.append("Chunk metadata: " + metadata)
    context_sections: list[str] = []
    ranked_facts = _rank_preprocessing_facts(chunk.preprocessing_facts)
    if ranked_facts:
        context_sections.append("Deterministic facts:")
        context_sections.extend(ranked_facts)
    if index_context.strip():
        context_sections.append(index_context.strip())
    if allowed_cwe_policy:
        context_sections.append("Allowed CWE policy: " + ", ".join(allowed_cwe_policy))
    context_lines = [line for section in context_sections for line in section.splitlines()]
    deduped_lines: list[str] = []
    seen_lines: set[str] = set()
    for line in context_lines:
        key = line.strip()
        if key in seen_lines:
            continue
        seen_lines.add(key)
        deduped_lines.append(line)
    context_text = _as_comment_block("\n".join(deduped_lines).strip() or "N/A")
    code_snippet = "\n".join(["// context", context_text, "// target function", _strip_c_comments(chunk.text)])
    parts.append("Code snippet:\n```c\n" + code_snippet + "\n```")
    return "\n\n".join(p for p in parts if p)

from __future__ import annotations

from vulnllm.chunking.function_chunker import CodeChunk
from vulnllm.config import Config
from vulnllm.prompt.focus_injector import build_focus_block
from vulnllm.prompt.profiles.embedded_c import EMBEDDED_C_GUIDANCE

SYSTEM_PROMPT_SINGLE_PASS = """
You are a vulnerability detection model for C/C++ code.
Analyze one target function with optional helper context.
Input sections are separated by:
- // context
- // target function

Output format (plain text, exactly these keys):
#judge: yes|no
#type: CWE-xx|N/A
#confidence: low|medium|high
#need_context: N/A|symbol_a,symbol_b
#why: one short sentence

Rules:
- Output one most probable CWE only when judge=yes.
- If judge=no, set type=N/A.
- Keep #why concise and evidence-grounded.
- If a Contract Summary is present in context, treat it as high-priority evidence.
- If issue depends on unseen callee internals, set #judge: no and request symbols via #need_context.
- Report CWE-190 only when overflow is demonstrable from visible bounds/constants/call-path values; otherwise set #judge: no.
- Do not flag a vulnerability in the target function based only on hypothetical caller misuse when the shown call path is safe.
- Use sink-matched CWE mapping:
  - strcpy/strcat/gets into fixed buffer -> CWE-120
  - sprintf into fixed buffer -> CWE-787
  - unvalidated file path composition/open -> CWE-22
- Do not output CWE-78 unless command execution APIs are present (system/popen/exec*).
- Do not output CWE-190 for pure string/path handling functions without relevant numeric arithmetic.
- Do not output JSON, markdown fences, or extra prose.
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
    system_prompt = SYSTEM_PROMPT_SINGLE_PASS
    parts = [system_prompt, profile]
    if focus:
        parts.append(focus)
    parts.append("Chunk metadata: " + metadata)
    context_text = _as_comment_block(index_context.strip() or "N/A")
    code_snippet = "\n".join(["// context", context_text, "// target function", _strip_c_comments(chunk.text)])
    parts.append("Code snippet:\n```c\n" + code_snippet + "\n```")
    return "\n\n".join(p for p in parts if p)

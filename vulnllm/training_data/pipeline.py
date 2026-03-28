from __future__ import annotations

from dataclasses import dataclass

from vulnllm.preprocessing.c_family import sanitize_source_text


@dataclass(frozen=True)
class ReasoningSample:
    prompt: str
    output: str
    correct: bool
    category: str = "generic"

    @property
    def total_tokens(self) -> int:
        return max(1, (len(self.prompt) + len(self.output)) // 4)


def drop_oversized_samples(samples: list[ReasoningSample], *, max_tokens: int = 32_000) -> list[ReasoningSample]:
    return [sample for sample in samples if sample.total_tokens <= max_tokens]


def select_shortest_correct_sample(samples: list[ReasoningSample], *, max_attempts: int = 8) -> ReasoningSample | None:
    if max_attempts <= 0:
        return None
    candidates = [sample for sample in samples[:max_attempts] if sample.correct]
    if not candidates:
        return None
    return min(candidates, key=lambda sample: (sample.total_tokens, len(sample.output), len(sample.prompt)))


def apply_constitution_corrections(
    samples: list[ReasoningSample],
    *,
    corrections: dict[str, str],
) -> list[ReasoningSample]:
    out: list[ReasoningSample] = []
    for sample in samples:
        correction = corrections.get(sample.category)
        if not correction:
            out.append(sample)
            continue
        fixed_output = f"{sample.output.rstrip()}\n{correction.strip()}\n"
        out.append(ReasoningSample(prompt=sample.prompt, output=fixed_output, correct=True, category=sample.category))
    return out


def compress_reasoning_trace(text: str, *, max_lines: int = 6) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) <= max_lines:
        return "\n".join(lines)
    keep_head = max(1, max_lines // 2)
    keep_tail = max(1, max_lines - keep_head)
    compact = lines[:keep_head] + ["[...]"] + lines[-keep_tail:]
    return "\n".join(compact[: max_lines + 1])


def sanitize_training_text(
    text: str,
    *,
    strip_comments: bool = True,
    sanitize_identifiers: bool = True,
) -> str:
    return sanitize_source_text(
        text,
        strip_comments=strip_comments,
        sanitize_identifiers=sanitize_identifiers,
    )

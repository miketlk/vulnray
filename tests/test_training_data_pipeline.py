from __future__ import annotations

from vulnllm.training_data import (
    ReasoningSample,
    apply_constitution_corrections,
    compress_reasoning_trace,
    drop_oversized_samples,
    sanitize_training_text,
    select_shortest_correct_sample,
)


def test_training_data_public_api_reasoning_sample_tokens():
    sample = ReasoningSample(prompt="abcd", output="efgh", correct=True)
    assert sample.total_tokens >= 1


def test_drop_oversized_samples_filters_large_entries():
    small = ReasoningSample(prompt="a" * 10, output="b" * 10, correct=True)
    large = ReasoningSample(prompt="a" * 1000, output="b" * 1000, correct=True)
    kept = drop_oversized_samples([small, large], max_tokens=50)
    assert kept == [small]


def test_select_shortest_correct_sample_uses_attempt_cap():
    attempts = [
        ReasoningSample(prompt="x" * 100, output="y", correct=True),
        ReasoningSample(prompt="x" * 10, output="y", correct=True),
        ReasoningSample(prompt="x", output="y", correct=False),
    ]
    selected = select_shortest_correct_sample(attempts, max_attempts=2)
    assert selected == attempts[1]
    assert select_shortest_correct_sample(attempts, max_attempts=0) is None


def test_apply_constitution_corrections_marks_sample_correct():
    sample = ReasoningSample(prompt="p", output="o", correct=False, category="overflow")
    corrected = apply_constitution_corrections([sample], corrections={"overflow": "Use checked bounds."})
    assert corrected[0].correct is True
    assert "Use checked bounds." in corrected[0].output


def test_compress_reasoning_trace_keeps_head_and_tail():
    trace = "\n".join(f"step {i}" for i in range(10))
    compressed = compress_reasoning_trace(trace, max_lines=4)
    assert "step 0" in compressed
    assert "step 9" in compressed
    assert "[...]" in compressed


def test_sanitize_training_text_strips_comments_and_sanitizes_identifiers():
    text = "int copy_name(void) {\n // comment\n return 0;\n}\n"
    out = sanitize_training_text(text, strip_comments=True, sanitize_identifiers=True)
    assert "comment" not in out
    assert "copy_name" not in out

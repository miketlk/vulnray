from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Any

from vulnllm.config import Config
from vulnllm.inference.parameters import GenerationParams
from vulnllm.utils.model_paths import resolve_model_path


@dataclass
class InferenceResult:
    text: str
    error: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    timestamp_local: str | None = None
    context_size: int | None = None
    context_events: list[str] = field(default_factory=list)


class LlamaBackend:
    _CTX_ERR_RE = re.compile(r"Requested tokens \((\d+)\) exceed context window of (\d+)")

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._llm = None
        self._llama_cls = None
        self._load_error: str | None = None
        self._backend_name = "llama-cpp-python"
        self._backend_version: str | None = None
        self._resolved_model_path = resolve_model_path(self.cfg.inference.model)
        self._base_context = int(self.cfg.inference.context)
        self._context_max = int(self.cfg.inference.context_max or (self._base_context * 4))
        self._llm_by_context: dict[int, Any] = {}
        self._load_backend()

    @staticmethod
    def _now_local_iso() -> str:
        return datetime.now().astimezone().isoformat(timespec="seconds")

    def _llama_kwargs(self, *, n_ctx: int) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model_path": self._resolved_model_path,
            "n_ctx": n_ctx,
            "n_gpu_layers": self.cfg.inference.gpu_layers,
            "seed": self.cfg.inference.seed,
            "verbose": False,
        }
        if self.cfg.inference.threads is not None:
            kwargs["n_threads"] = self.cfg.inference.threads
        if self.cfg.inference.batch is not None:
            kwargs["n_batch"] = self.cfg.inference.batch
        return kwargs

    def _load_backend(self) -> None:
        try:
            import llama_cpp  # type: ignore
            from llama_cpp import Llama  # type: ignore

            self._backend_version = getattr(llama_cpp, "__version__", None)
            self._llama_cls = Llama
            self._llm = Llama(**self._llama_kwargs(n_ctx=self._base_context))
            self._llm_by_context = {self._base_context: self._llm}
            self._load_error = None
        except Exception as e:
            self._llm = None
            self._llama_cls = None
            self._llm_by_context = {}
            self._load_error = str(e)

    def backend_name(self) -> str:
        return self._backend_name

    def backend_version(self) -> str:
        return self._backend_version or "unknown"

    def _create_completion(self, llm: Any, prompt: str, params: GenerationParams) -> dict[str, Any]:
        return llm.create_completion(
            prompt=prompt,
            max_tokens=params.max_tokens,
            temperature=params.temperature,
            top_p=params.top_p,
            seed=params.seed,
        )

    def _from_output(
        self,
        out: dict[str, Any],
        *,
        context_size: int,
        context_events: list[str] | None = None,
    ) -> InferenceResult:
        text = out["choices"][0]["text"].strip()
        usage = out.get("usage") if isinstance(out, dict) else None
        prompt_tokens = None
        completion_tokens = None
        total_tokens = None
        if isinstance(usage, dict):
            if usage.get("prompt_tokens") is not None:
                prompt_tokens = int(usage["prompt_tokens"])
            if usage.get("completion_tokens") is not None:
                completion_tokens = int(usage["completion_tokens"])
            if usage.get("total_tokens") is not None:
                total_tokens = int(usage["total_tokens"])
        return InferenceResult(
            text=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            timestamp_local=self._now_local_iso(),
            context_size=context_size,
            context_events=list(context_events or []),
        )

    @classmethod
    def _parse_context_error(cls, message: str) -> tuple[int | None, int | None]:
        m = cls._CTX_ERR_RE.search(message)
        if not m:
            return None, None
        return int(m.group(1)), int(m.group(2))

    @staticmethod
    def _estimate_required_tokens(prompt: str, max_tokens: int) -> int:
        prompt_tokens = max(1, len(prompt) // 4)
        return prompt_tokens + max(0, max_tokens)

    def _next_retry_context(self, *, current_ctx: int, required_tokens: int) -> int | None:
        if current_ctx >= self._context_max:
            return None
        target = max(required_tokens, current_ctx * 2)
        next_ctx = min(self._context_max, target)
        if next_ctx <= current_ctx:
            return None
        return next_ctx

    def _get_or_create_context_llm(self, n_ctx: int) -> tuple[Any | None, str | None]:
        if n_ctx in self._llm_by_context:
            return self._llm_by_context[n_ctx], None
        if self._llama_cls is None:
            return None, "backend unavailable"
        try:
            llm = self._llama_cls(**self._llama_kwargs(n_ctx=n_ctx))
        except Exception as e:
            return None, str(e)
        self._llm_by_context[n_ctx] = llm
        return llm, None

    def _generate_with_expanded_context(
        self,
        prompt: str,
        params: GenerationParams,
        first_error: str,
    ) -> InferenceResult | None:
        if self._llama_cls is None:
            return None

        requested_tokens, reported_window = self._parse_context_error(first_error)
        if requested_tokens is None and reported_window is None:
            return None

        errors: list[str] = [first_error]
        events: list[str] = []
        required_tokens = max(
            requested_tokens or 0,
            self._estimate_required_tokens(prompt, params.max_tokens),
        )
        current_ctx = max(self._base_context, reported_window or self._base_context)
        retry_ctx = self._next_retry_context(current_ctx=current_ctx, required_tokens=required_tokens)

        if retry_ctx is None:
            return InferenceResult(
                text="",
                error=(
                    "llama-cpp-python failure: "
                    f"{first_error}; requested context exceeds configured maximum ({self._context_max})"
                ),
                timestamp_local=self._now_local_iso(),
                context_size=self._base_context,
                context_events=events,
            )

        while retry_ctx is not None:
            events.append(f"{self._now_local_iso()} context increase: {current_ctx} -> {retry_ctx}")
            temp_llm, init_error = self._get_or_create_context_llm(retry_ctx)
            if temp_llm is None:
                errors.append(f"context={retry_ctx} init failed: {init_error}")
                events.append(f"{self._now_local_iso()} context decrease: {retry_ctx} -> {self._base_context}")
                break

            try:
                out = self._create_completion(temp_llm, prompt, params)
                events.append(f"{self._now_local_iso()} context decrease: {retry_ctx} -> {self._base_context}")
                return self._from_output(out, context_size=retry_ctx, context_events=events)
            except Exception as e:
                msg = str(e)
                errors.append(f"context={retry_ctx} inference failed: {msg}")
                events.append(f"{self._now_local_iso()} context decrease: {retry_ctx} -> {self._base_context}")
                next_requested, _ = self._parse_context_error(msg)
                if next_requested is None:
                    break
                required_tokens = max(required_tokens, next_requested)
                current_ctx = retry_ctx
                retry_ctx = self._next_retry_context(current_ctx=current_ctx, required_tokens=required_tokens)
                continue

        return InferenceResult(
            text="",
            error=f"llama-cpp-python failure: {'; '.join(errors)}",
            timestamp_local=self._now_local_iso(),
            context_size=self._base_context,
            context_events=events,
        )

    def generate(self, prompt: str, params: GenerationParams) -> InferenceResult:
        if self._llm is None:
            detail = f": {self._load_error}" if self._load_error else ""
            return InferenceResult(text="", error=f"llama-cpp-python backend unavailable{detail}")

        try:
            out = self._create_completion(self._llm, prompt, params)
            return self._from_output(out, context_size=self._base_context)
        except Exception as e:
            original_error = str(e)
            retried = self._generate_with_expanded_context(prompt, params, original_error)
            if retried is not None:
                return retried
            return InferenceResult(
                text="",
                error=f"llama-cpp-python failure: {original_error}",
                timestamp_local=self._now_local_iso(),
                context_size=self._base_context,
            )

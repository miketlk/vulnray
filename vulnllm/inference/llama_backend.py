from __future__ import annotations

from dataclasses import dataclass

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


class LlamaBackend:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._llm = None
        self._load_error: str | None = None
        self._backend_name = "llama-cpp-python"
        self._backend_version: str | None = None
        self._resolved_model_path = resolve_model_path(self.cfg.inference.model)
        self._load_backend()

    def _load_backend(self) -> None:
        try:
            import llama_cpp  # type: ignore
            from llama_cpp import Llama  # type: ignore

            self._backend_version = getattr(llama_cpp, "__version__", None)
            kwargs = {
                "model_path": self._resolved_model_path,
                "n_ctx": self.cfg.inference.context,
                "n_gpu_layers": self.cfg.inference.gpu_layers,
                "seed": self.cfg.inference.seed,
                "verbose": False,
            }
            if self.cfg.inference.threads is not None:
                kwargs["n_threads"] = self.cfg.inference.threads
            if self.cfg.inference.batch is not None:
                kwargs["n_batch"] = self.cfg.inference.batch

            self._llm = Llama(**kwargs)
            self._load_error = None
        except Exception as e:
            self._llm = None
            self._load_error = str(e)

    def backend_name(self) -> str:
        return self._backend_name

    def backend_version(self) -> str:
        return self._backend_version or "unknown"

    def generate(self, prompt: str, params: GenerationParams) -> InferenceResult:
        if self._llm is None:
            detail = f": {self._load_error}" if self._load_error else ""
            return InferenceResult(text="", error=f"llama-cpp-python backend unavailable{detail}")

        try:
            out = self._llm.create_completion(
                prompt=prompt,
                max_tokens=params.max_tokens,
                temperature=params.temperature,
                top_p=params.top_p,
            )
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
            )
        except Exception as e:
            return InferenceResult(text="", error=f"llama-cpp-python failure: {e}")

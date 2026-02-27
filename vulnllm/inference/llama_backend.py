from __future__ import annotations

from dataclasses import dataclass

from vulnllm.config import Config
from vulnllm.inference.parameters import GenerationParams
from vulnllm.utils.model_paths import resolve_model_path


@dataclass
class InferenceResult:
    text: str
    error: str | None = None


class LlamaBackend:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._llm = None
        self._load_error: str | None = None
        self._resolved_model_path = resolve_model_path(self.cfg.inference.model)
        self._load_backend()

    def _load_backend(self) -> None:
        try:
            from llama_cpp import Llama  # type: ignore

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
            return InferenceResult(text=text)
        except Exception as e:
            return InferenceResult(text="", error=f"llama-cpp-python failure: {e}")

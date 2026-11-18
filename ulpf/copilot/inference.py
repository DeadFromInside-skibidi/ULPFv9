"""
Local, air-gapped inference for the SecOps copilot.

Backends (first that loads wins, in the configured order):

``llama_cpp``  GGUF models through ``llama-cpp-python`` (Llama 3.x Instruct, Mistral 7B,
               Qwen 2.5 Coder, ...). GPU offload (CUDA / Metal / Vulkan builds) with
               ``n_gpu_layers``; when the GPU is absent or the build is CPU-only it
               falls back to CPU (AVX2/AVX-512 kernels picked by llama.cpp at run time).
``onnx_genai`` ONNX Runtime GenAI models; the DirectML build runs on any Windows
               DX12 GPU/NPU, the CUDA build on NVIDIA, otherwise the CPU provider.
``rules``      No model: the deterministic engines (grammar-based NL->query,
               evidence-driven narratives). Always available, never wrong about
               what the evidence says, and the safety net for the others.

Sovereignty controls:

* model paths must be local files (URLs and hub ids are refused); the SHA-256 of
  the model can be pinned (``model_sha256``) and is verified before loading;
* ``HF_HUB_OFFLINE``/``TRANSFORMERS_OFFLINE`` are forced and no backend is
  given network access; prompts, context and outputs never leave the process;
* decoding is deterministic: temperature 0, fixed seed, top-k 1;
* prompts are fitted into the context window by ``Budget`` (priority-ordered
  sections, oldest evidence dropped first), never silently truncated mid-section.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading

logger = logging.getLogger(__name__)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")


class ModelError(RuntimeError):
    pass


def _check_local(path: str, sha256: str | None) -> str:
    if not path or "://" in path:
        raise ModelError("the copilot only loads local model files (no URLs or hub ids)")
    if not os.path.exists(path):
        raise ModelError(f"model not found: {path}")
    if sha256:
        side = path + ".sha256"
        st = os.stat(path)
        stamp = f"{st.st_size}:{int(st.st_mtime)}"
        cached = None
        if os.path.isfile(path) and os.path.exists(side):
            with open(side, "r", encoding="utf-8") as f:
                cached = f.read().split()
        if not cached or cached[1:] != [stamp]:
            h = hashlib.sha256()
            files = [path] if os.path.isfile(path) else sorted(
                os.path.join(r, n) for r, _, ns in os.walk(path) for n in ns)
            for fp in files:
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(8 * 2**20), b""):
                        h.update(chunk)
            digest = h.hexdigest()
            if os.path.isfile(path):
                try:
                    with open(side, "w", encoding="utf-8") as f:
                        f.write(f"{digest} {stamp}")
                except OSError:
                    pass
        else:
            digest = cached[0]
        if digest.lower() != sha256.lower():
            raise ModelError(f"model SHA-256 {digest} does not match the pinned {sha256}")
    return path


class Backend:
    name = "rules"
    device = "cpu"
    n_ctx = 4096

    def available(self) -> bool:
        return True

    def generate(self, system: str, prompt: str, max_tokens: int = 512, grammar_json: bool = False) -> str:
        raise ModelError("no language model loaded (rules backend)")

    def count_tokens(self, text: str) -> int:
        return max(1, len(text) // 4)

    def info(self) -> dict:
        return {"backend": self.name, "device": self.device, "n_ctx": self.n_ctx, "offline": True}


class LlamaCppBackend(Backend):
    name = "llama_cpp"

    def __init__(self, model_path: str, n_ctx: int = 8192, n_gpu_layers: int = -1, threads: int | None = None,
                 seed: int = 42, sha256: str | None = None):
        try:
            import llama_cpp
        except ImportError as e:
            raise ModelError("llama-cpp-python is not installed (pip install 'ulpf[copilot]')") from e
        _check_local(model_path, sha256)
        self.n_ctx = n_ctx
        kw = dict(model_path=model_path, n_ctx=n_ctx, seed=seed, verbose=False, n_threads=threads or os.cpu_count())
        self.device = "gpu"
        try:
            self.llm = llama_cpp.Llama(n_gpu_layers=n_gpu_layers, **kw)
            if not getattr(llama_cpp, "llama_supports_gpu_offload", lambda: False)():
                self.device = "cpu"
        except Exception as e:           # GPU init failure: graceful CPU fallback
            logger.warning(f"copilot: GPU offload failed ({e}); using CPU")
            self.llm = llama_cpp.Llama(n_gpu_layers=0, **kw)
            self.device = "cpu"
        self._lock = threading.Lock()
        self.model = os.path.basename(model_path)

    def count_tokens(self, text: str) -> int:
        return len(self.llm.tokenize(text.encode("utf-8"), add_bos=False))

    def generate(self, system, prompt, max_tokens=512, grammar_json=False):
        kw = {}
        if grammar_json:
            kw["response_format"] = {"type": "json_object"}
        with self._lock:
            out = self.llm.create_chat_completion(
                messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                temperature=0.0, top_k=1, top_p=1.0, seed=42, max_tokens=max_tokens, **kw)
        return out["choices"][0]["message"]["content"]

    def info(self):
        return {**super().info(), "model": self.model}


class OnnxGenAIBackend(Backend):
    name = "onnx_genai"

    def __init__(self, model_dir: str, n_ctx: int = 4096, sha256: str | None = None):
        try:
            import onnxruntime_genai as og
        except ImportError as e:
            raise ModelError("onnxruntime-genai (or -directml / -cuda) is not installed") from e
        _check_local(model_dir, sha256)
        self.og = og
        self.model = og.Model(model_dir)
        self.tok = og.Tokenizer(self.model)
        self.n_ctx = n_ctx
        self.device = getattr(self.model, "device_type", "auto")
        self._lock = threading.Lock()

    def count_tokens(self, text):
        return len(self.tok.encode(text))

    def generate(self, system, prompt, max_tokens=512, grammar_json=False):
        og = self.og
        text = f"<|system|>\n{system}<|end|>\n<|user|>\n{prompt}<|end|>\n<|assistant|>\n"
        params = og.GeneratorParams(self.model)
        params.set_search_options(max_length=min(self.n_ctx, self.count_tokens(text) + max_tokens),
                                  do_sample=False, top_k=1, temperature=0.0)
        with self._lock:
            gen = og.Generator(self.model, params)
            gen.append_tokens(self.tok.encode(text))
            out = []
            while not gen.is_done():
                gen.generate_next_token()
                out.append(gen.get_next_tokens()[0])
        return self.tok.decode(out)


def load_backend(cfg: dict | None) -> Backend:
    cfg = cfg or {}
    order = cfg.get("backends") or ["llama_cpp", "onnx_genai", "rules"]
    errors = []
    for name in order:
        try:
            if name == "llama_cpp" and cfg.get("model_path"):
                return LlamaCppBackend(cfg["model_path"], int(cfg.get("n_ctx", 8192)),
                                       int(cfg.get("n_gpu_layers", -1)), cfg.get("threads"),
                                       int(cfg.get("seed", 42)), cfg.get("model_sha256"))
            if name == "onnx_genai" and cfg.get("onnx_model_dir"):
                return OnnxGenAIBackend(cfg["onnx_model_dir"], int(cfg.get("n_ctx", 4096)), cfg.get("model_sha256"))
            if name == "rules":
                b = Backend()
                b.errors = errors
                return b
        except ModelError as e:
            errors.append(f"{name}: {e}")
            logger.warning(f"copilot backend {name} unavailable: {e}")
    b = Backend()
    b.errors = errors
    return b


class Budget:
    """Fit prioritised sections into the context window: (priority, title, items) — lower priority drops first,
    and within a section the oldest items are dropped first."""

    def __init__(self, backend: Backend, reserve_output: int = 768):
        self.b = backend
        self.limit = max(512, backend.n_ctx - reserve_output)

    def fit(self, header: str, sections: list[tuple[int, str, list[str]]]) -> tuple[str, dict]:
        used = self.b.count_tokens(header)
        kept: dict[str, list[str]] = {}
        dropped = 0
        for prio, title, items in sorted(sections, key=lambda s: s[0]):
            room = self.limit - used - self.b.count_tokens(title) - 8
            keep: list[str] = []
            for it in reversed(items):            # newest first
                t = self.b.count_tokens(it) + 1
                if t > room:
                    dropped += 1
                    continue
                keep.append(it)
                room -= t
            kept[title] = list(reversed(keep))
            used = self.limit - room
        body = header + "".join(f"\n## {t}\n" + "\n".join(v) for t, v in kept.items() if v)
        return body, {"tokens": self.b.count_tokens(body), "limit": self.limit, "items_dropped": dropped}


def parse_json(text: str) -> dict | None:
    s = text.find("{")
    e = text.rfind("}")
    if s < 0 or e <= s:
        return None
    try:
        return json.loads(text[s:e + 1])
    except ValueError:
        return None

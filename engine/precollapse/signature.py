"""Pre-collapse signatures: read a model's activation shape for a piece of code.

The thesis's claim is that a small model, as soon as it parses code, forms a
representation of that code's latent vulnerability class -- upstream of, and more
stable than, whatever it would say if prompted. This module turns that representation
into a fixed-length vector we can index and compare.

Two backends produce signatures:

  * ModelBackend -- the real thing. Runs the model, takes the mean-pooled hidden state
    at each layer, and reduces a deep band of layers to one L2-normalized vector.
    Deep layers are used deliberately: linear-probe accuracy for abstract properties
    sharpens with depth (Alain & Bengio 2016), and the shallow layers still encode
    surface form, which is exactly what we want the signature to be invariant to.

  * FixtureBackend -- cached vectors on disk, so the database, matcher, oracle, and the
    full loop are runnable and testable without model weights (e.g. in CI). Fixtures
    are regenerated from a real model with tools/compute_signatures.py; see
    signatures/MODEL_CARD.md for exactly which model produced the committed set.

A signature is just a unit vector; similarity is cosine. Signatures are only comparable
within one model, so every signature file records the model that produced it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Protocol

import numpy as np


def normalize_code(code: str) -> str:
    """Whitespace-normalize so a trivially reformatted clone hashes identically."""
    return "\n".join(line.rstrip() for line in code.strip().splitlines())


def code_key(code: str) -> str:
    return hashlib.sha256(normalize_code(code).encode("utf-8")).hexdigest()[:16]


def reduce_signature(layer_stack: np.ndarray, deep_fraction: float = 0.5) -> np.ndarray:
    """Reduce a (n_layers, hidden) stack to one L2-normalized signature vector.

    Averages the deep band (the last ``deep_fraction`` of layers, excluding the final
    layer which is pulled toward the output distribution), then normalizes.
    """
    n_layers = layer_stack.shape[0]
    start = max(1, int(n_layers * (1.0 - deep_fraction)))
    end = max(start + 1, n_layers - 1)  # drop the very last layer
    band = layer_stack[start:end]
    vec = band.mean(axis=0).astype(np.float64)
    norm = np.linalg.norm(vec)
    return (vec / norm) if norm > 0 else vec


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


class SignatureBackend(Protocol):
    model_name: str

    def encode(self, code: str) -> np.ndarray:
        """Return the pre-collapse signature vector for ``code``."""
        ...


class ModelBackend:
    """Real signatures from a causal LM's hidden states. Requires torch + transformers."""

    def __init__(
        self,
        model_name: str = "microsoft/phi-1_5",
        device: str = "cpu",
        dtype: str | None = None,
        max_length: int = 1024,
        deep_fraction: float = 0.5,
    ):
        import torch  # local import: only the model path needs torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.model_name = model_name
        self.device = device
        self.max_length = max_length
        self.deep_fraction = deep_fraction
        td = {"float16": torch.float16, "float32": torch.float32, "bfloat16": torch.bfloat16}
        # Activations want full precision on CPU (quantized activations are noisy).
        self._dtype = td.get(dtype or ("float16" if device == "cuda" else "float32"))
        self._torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
        self.model = (
            AutoModelForCausalLM.from_pretrained(
                model_name, torch_dtype=self._dtype, trust_remote_code=True,
                output_hidden_states=True,
            )
            .to(device)
            .eval()
        )

    def layer_stack(self, code: str) -> np.ndarray:
        torch = self._torch
        ins = self.tok(code, return_tensors="pt", truncation=True,
                       max_length=self.max_length).to(self.device)
        with torch.no_grad():
            out = self.model(**ins, output_hidden_states=True)
        # mean-pool tokens at each layer -> (n_layers, hidden)
        stack = torch.stack([h[0].float().mean(0) for h in out.hidden_states])
        return stack.cpu().numpy()

    def encode(self, code: str) -> np.ndarray:
        return reduce_signature(self.layer_stack(code), self.deep_fraction)


class FixtureBackend:
    """Serve precomputed signatures from a JSON file, keyed by whitespace-normalized code.

    For code not present in the fixture set, ``encode`` raises: without a model there is
    no honest way to produce a *new* semantic signature, and the fixtures deliberately do
    not pretend otherwise. Use ModelBackend to sign novel code.
    """

    def __init__(self, path: str | Path):
        blob = json.loads(Path(path).read_text())
        self.model_name = blob["model_name"]
        self.dim = blob["dim"]
        self._by_key = {e["key"]: np.asarray(e["signature"], dtype=np.float64)
                        for e in blob["signatures"]}
        self._meta = {e["key"]: e for e in blob["signatures"]}

    def has(self, code: str) -> bool:
        return code_key(code) in self._by_key

    def encode(self, code: str) -> np.ndarray:
        k = code_key(code)
        if k not in self._by_key:
            raise KeyError(
                "no fixture signature for this code (key="
                f"{k}). Fixtures cover the corpus only; run with a ModelBackend "
                "(--model) to sign novel code, or regenerate fixtures with "
                "tools/compute_signatures.py."
            )
        return self._by_key[k]


def load_fixture_backend(path: str | Path) -> FixtureBackend:
    return FixtureBackend(path)


def save_signatures(path: str | Path, model_name: str, entries: list[dict]) -> None:
    """entries: [{key, id, class_id, signature(list[float])}, ...]"""
    dim = len(entries[0]["signature"]) if entries else 0
    blob = {"model_name": model_name, "dim": dim, "signatures": entries}
    Path(path).write_text(json.dumps(blob, indent=2))

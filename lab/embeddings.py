"""Embedding backends.

The default is a deterministic hashed bag-of-words embedder. It is not a good
semantic model, but it is *reproducible with zero dependencies*, which matters
more here: the findings in this lab are authorization and control-flow bugs, and
none of them depend on embedding quality. Reviewers can clone and run the whole
attack suite with numpy alone.

Swap in `SentenceTransformerEmbedder` when you want realistic retrieval
behaviour (for example when measuring rank-manipulation attacks, which *do*
depend on the embedding space).
"""

from __future__ import annotations

import hashlib
import re
from typing import Protocol

import numpy as np

_TOKEN = re.compile(r"[a-z0-9]+")
DIM = 256


class Embedder(Protocol):
    dim: int

    def embed(self, text: str) -> np.ndarray: ...


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class HashEmbedder:
    """Deterministic hashed bag-of-words with sublinear term weighting."""

    def __init__(self, dim: int = DIM) -> None:
        self.dim = dim

    def _bucket(self, token: str) -> int:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        return int.from_bytes(digest, "big") % self.dim

    def embed(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        counts: dict[int, int] = {}
        for tok in _tokens(text):
            b = self._bucket(tok)
            counts[b] = counts.get(b, 0) + 1
        for b, c in counts.items():
            vec[b] = 1.0 + np.log(c)
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else vec


class SentenceTransformerEmbedder:
    """Optional realistic embedder. Requires `sentence-transformers`."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415

        self._model = SentenceTransformer(model_name)
        self.dim = int(self._model.get_sentence_embedding_dimension())

    def embed(self, text: str) -> np.ndarray:
        vec = self._model.encode(text, normalize_embeddings=True)
        return np.asarray(vec, dtype=np.float32)


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    return 0.0 if denom == 0.0 else float(np.dot(a, b) / denom)

from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence
from typing import Protocol


class EmbeddingProvider(Protocol):
    dimension: int

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return one normalized vector for each input text."""


class DeterministicEmbedder:
    """Dependency-free embedder for tests and development wiring."""

    def __init__(self, dimension: int = 128) -> None:
        if dimension < 8:
            raise ValueError("embedding dimension must be at least 8")
        self.dimension = dimension

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]

    def _embed(self, text: str) -> list[float]:
        values = [0.0] * self.dimension
        words = text.casefold().split()
        for index, word in enumerate(words):
            digest = hashlib.sha256(f"{index}:{word}".encode()).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dimension
            sign = 1.0 if digest[4] & 1 else -1.0
            values[bucket] += sign

        norm = math.sqrt(sum(value * value for value in values))
        if norm == 0:
            return values
        return [value / norm for value in values]

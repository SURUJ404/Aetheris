from __future__ import annotations

from collections.abc import Iterator


def chunk_text(text: str, *, size: int = 1_200, overlap: int = 120) -> Iterator[str]:
    if size <= 0:
        raise ValueError("chunk size must be positive")
    if overlap < 0 or overlap >= size:
        raise ValueError("chunk overlap must be between zero and size - 1")

    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        chunk = text[start:end].strip()
        if chunk:
            yield chunk
        if end == len(text):
            break
        start = end - overlap

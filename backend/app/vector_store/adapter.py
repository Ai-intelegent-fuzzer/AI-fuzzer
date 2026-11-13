import hashlib
import math
import re
from typing import Protocol

from app.vector_store.models import VectorDocument


class VectorStoreAdapter(Protocol):
    def upsert(self, document: VectorDocument) -> None: ...

    def delete(self, document_id: str) -> None: ...

    def search(
        self,
        query: str,
        documents: list[VectorDocument],
        limit: int,
    ) -> list[tuple[VectorDocument, float]]: ...


class LocalHashedVectorAdapter:
    """Deterministic local hashed-token vectors; suitable for fixtures, not semantic production search."""

    _dimensions = 128

    @classmethod
    def _embed(cls, text: str) -> list[float]:
        vector = [0.0] * cls._dimensions
        tokens = re.findall(r"[a-zA-Z0-9_-]{2,}", text.casefold())
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % cls._dimensions
            vector[index] += 1.0 if digest[4] & 1 else -1.0
        magnitude = math.sqrt(sum(value * value for value in vector))
        return [value / magnitude for value in vector] if magnitude else vector

    def upsert(self, _document: VectorDocument) -> None:
        return None

    def delete(self, _document_id: str) -> None:
        return None

    def search(
        self,
        query: str,
        documents: list[VectorDocument],
        limit: int,
    ) -> list[tuple[VectorDocument, float]]:
        query_vector = self._embed(query)
        ranked: list[tuple[VectorDocument, float]] = []
        for document in documents:
            content_vector = self._embed(f"{document.title} {document.content} {' '.join(document.metadata.values())}")
            similarity = sum(left * right for left, right in zip(query_vector, content_vector))
            if similarity > 0:
                ranked.append((document, similarity))
        ranked.sort(key=lambda result: (-result[1], result[0].document_id))
        return ranked[:limit]

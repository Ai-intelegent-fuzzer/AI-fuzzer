import re
from typing import Protocol

from app.rag.models import RAGDocument


class RAGAdapter(Protocol):
    def retrieve(
        self,
        query: str,
        documents: list[RAGDocument],
        limit: int,
    ) -> list[RAGDocument]: ...


class LocalSyntheticRAGAdapter:
    """Deterministic local retrieval over controlled synthetic documents."""

    @staticmethod
    def _tokens(value: str) -> set[str]:
        return {token.casefold() for token in re.findall(r"[a-zA-Z0-9_-]{2,}", value)}

    def retrieve(
        self,
        query: str,
        documents: list[RAGDocument],
        limit: int,
    ) -> list[RAGDocument]:
        normalized_query = query.casefold().strip()
        exact_matches = [
            document
            for document in documents
            if normalized_query in " ".join(
                [document.title, document.content, *document.metadata.values()]
            ).casefold()
        ]
        if exact_matches:
            return exact_matches[:limit]

        query_tokens = self._tokens(query)
        ranked: list[tuple[int, str, RAGDocument]] = []
        for document in documents:
            searchable = " ".join(
                [document.title, document.content, *document.metadata.values()]
            )
            score = len(query_tokens.intersection(self._tokens(searchable)))
            if score:
                ranked.append((score, document.document_id, document))
        ranked.sort(key=lambda result: (-result[0], result[1]))
        if not ranked:
            return []
        best_score = ranked[0][0]
        return [
            document
            for score, _, document in ranked
            if score == best_score
        ][:limit]

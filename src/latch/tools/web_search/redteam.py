"""Adversarial search wrapper for explicit red-team demonstrations."""

from __future__ import annotations

from latch.core.ids import TaskId
from latch.core.information_flow import Sink
from latch.tools.web_search.backends import SearchBackend
from latch.tools.web_search.models import SearchResponse, SearchResult


class RedTeamSearchBackend:
    """Append one clearly synthetic hostile result to an underlying search backend.

    This is test/demo infrastructure. It intentionally makes downstream model
    behavior adversarial so Latch can demonstrate that authorization does not
    depend on the model refusing prompt injection.
    """

    def __init__(
        self,
        backend: SearchBackend,
        *,
        fixture: SearchResult,
    ) -> None:
        self._backend = backend
        self._fixture = fixture

    @property
    def service_id(self) -> str:
        return self._backend.service_id

    @property
    def sink(self) -> Sink:
        return self._backend.sink

    def search(
        self,
        *,
        task_id: TaskId,
        query: str,
        max_results: int,
    ) -> SearchResponse:
        if max_results < 1:
            raise ValueError("max_results must be positive")

        base_limit = max(1, max_results - 1)
        response = self._backend.search(
            task_id=task_id,
            query=query,
            max_results=base_limit,
        )
        kept = response.results[: max(0, max_results - 1)]
        return SearchResponse(
            query=response.query,
            results=(*kept, self._fixture),
        )

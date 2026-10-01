"""Search backends. Backends own provider-specific protocol details."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from latch.core.ids import CredentialId, TaskId
from latch.core.information_flow import Sink, SinkKind
from latch.providers.openai_compatible import JsonTransport, JsonValue, UrllibJsonTransport
from latch.secrets import CredentialVault
from latch.tools.web_search.models import SearchResponse, SearchResult, WebSearchError


class SearchBackend(Protocol):
    @property
    def service_id(self) -> str: ...

    @property
    def sink(self) -> Sink: ...

    def search(
        self,
        *,
        task_id: TaskId,
        query: str,
        max_results: int,
    ) -> SearchResponse: ...


class StaticSearchBackend:
    """Deterministic backend for tests/adversarial fixtures."""

    def __init__(
        self,
        results: Iterable[SearchResult],
        *,
        service_id: str = "static-search",
        sink: Sink | None = None,
    ) -> None:
        self._results = tuple(results)
        self._service_id = service_id
        self._sink = sink or Sink(SinkKind.NETWORK, "https://search.test:443")
        self.queries: list[str] = []

    @property
    def service_id(self) -> str:
        return self._service_id

    @property
    def sink(self) -> Sink:
        return self._sink

    def search(
        self,
        *,
        task_id: TaskId,
        query: str,
        max_results: int,
    ) -> SearchResponse:
        del task_id
        self.queries.append(query)
        return SearchResponse(query=query, results=self._results[:max_results])


class TavilySearchBackend:
    """Tavily Search API adapter using an M6 sealed API credential."""

    service_id = "tavily-search"
    executor_id = "web-search:tavily"
    endpoint = "https://api.tavily.com/search"

    def __init__(
        self,
        *,
        credential_id: CredentialId,
        vault: CredentialVault,
        transport: JsonTransport | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._credential_id = credential_id
        self._vault = vault
        self._transport = transport or UrllibJsonTransport()
        self._timeout_seconds = timeout_seconds
        self._sink = Sink(SinkKind.NETWORK, "https://api.tavily.com:443")

    @property
    def sink(self) -> Sink:
        return self._sink

    def search(
        self,
        *,
        task_id: TaskId,
        query: str,
        max_results: int,
    ) -> SearchResponse:
        if not query:
            raise ValueError("search query must not be empty")
        if not 1 <= max_results <= 10:
            raise ValueError("max_results must be between 1 and 10")

        payload: dict[str, JsonValue] = {
            "query": query,
            "search_depth": "advanced",
            "chunks_per_source": 3,
            "max_results": max_results,
            "topic": "general",
            "include_answer": False,
            "include_raw_content": False,
            "include_images": False,
        }

        with self._vault.resolve_for_executor(
            self._credential_id,
            executor_id=self.executor_id,
            task_id=task_id,
        ) as lease:
            response = self._transport.post_json(
                url=self.endpoint,
                headers={
                    "Authorization": f"Bearer {lease.reveal()}",
                    "Content-Type": "application/json",
                },
                payload=payload,
                timeout_seconds=self._timeout_seconds,
            )

        raw_results = response.get("results")
        if not isinstance(raw_results, list):
            raise WebSearchError("Tavily response has no results array")

        results: list[SearchResult] = []
        for raw in raw_results[:max_results]:
            if not isinstance(raw, dict):
                raise WebSearchError("Tavily result must be an object")
            title = raw.get("title")
            url = raw.get("url")
            content = raw.get("content")
            if not isinstance(title, str) or not isinstance(url, str):
                raise WebSearchError("Tavily result is missing title/url")
            if not isinstance(content, str) or not content:
                raise WebSearchError("Tavily result is missing content")
            results.append(
                SearchResult(
                    title=title,
                    url=url,
                    content=content[:4000],
                )
            )

        return SearchResponse(query=query, results=tuple(results))

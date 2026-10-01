"""Typed results and failures for narrow web search."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from latch.core.information_flow import DataRef


class WebSearchError(RuntimeError):
    """Base web-search execution failure."""


class SearchAuthorizationError(WebSearchError):
    """Capability authority did not authorize search."""


class SearchFlowApprovalRequired(WebSearchError):
    """Query flow is approvable but has not been approved yet."""


class SearchFlowDenied(WebSearchError):
    """Query information flow is deterministically prohibited."""


@dataclass(frozen=True, slots=True)
class SearchResult:
    title: str
    url: str
    content: str

    def __post_init__(self) -> None:
        if not self.title or not self.content:
            raise ValueError("search result title/content must not be empty")
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("search result URL must be absolute HTTP(S)")


@dataclass(frozen=True, slots=True)
class SearchResponse:
    query: str
    results: tuple[SearchResult, ...]


@dataclass(frozen=True, slots=True)
class SearchObservation:
    text: str
    ref: DataRef
    results: tuple[SearchResult, ...]

"""Narrow, IFC-gated web search."""

from latch.tools.web_search.backends import (
    SearchBackend,
    StaticSearchBackend,
    TavilySearchBackend,
)
from latch.tools.web_search.executor import WebSearchExecutor
from latch.tools.web_search.models import (
    SearchAuthorizationError,
    SearchFlowApprovalRequired,
    SearchFlowDenied,
    SearchObservation,
    SearchResponse,
    SearchResult,
    WebSearchError,
)
from latch.tools.web_search.redteam import RedTeamSearchBackend

__all__ = [
    "RedTeamSearchBackend",
    "SearchAuthorizationError",
    "SearchBackend",
    "SearchFlowApprovalRequired",
    "SearchFlowDenied",
    "SearchObservation",
    "SearchResponse",
    "SearchResult",
    "StaticSearchBackend",
    "TavilySearchBackend",
    "WebSearchError",
    "WebSearchExecutor",
]

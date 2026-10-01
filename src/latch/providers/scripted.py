"""Deterministic provider used for tests and adversarial fixtures."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable

from latch.core.information_flow import Sink, SinkKind
from latch.providers.base import ProviderError, ProviderRequest, ProviderResponse


class ScriptedProvider:
    def __init__(
        self,
        responses: Iterable[str],
        *,
        provider_id: str = "scripted",
        sink: Sink | None = None,
    ) -> None:
        self._responses = deque(responses)
        self._provider_id = provider_id
        self._sink = sink or Sink(SinkKind.LOCAL_MODEL, f"{provider_id}:local")
        self.requests: list[ProviderRequest] = []

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def sink(self) -> Sink:
        return self._sink

    def generate(self, request: ProviderRequest) -> ProviderResponse:
        self.requests.append(request)
        if not self._responses:
            raise ProviderError("scripted provider has no response remaining")
        return ProviderResponse(self._responses.popleft())

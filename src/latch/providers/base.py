"""Provider-neutral request/response types.

Providers are untrusted decision sources. They receive context only after the
agent runtime has passed information-flow policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from latch.core.ids import TaskId
from latch.core.information_flow import Sink


class ProviderError(RuntimeError):
    """A model provider or transport returned an unusable response."""


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    OBSERVATION = "observation"


@dataclass(frozen=True, slots=True)
class ModelMessage:
    role: MessageRole
    content: str

    def __post_init__(self) -> None:
        if not self.content:
            raise ValueError("model message content must not be empty")


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Semantic action exposed to a model, never an authority token."""

    action: str
    description: str
    arguments: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.action or not self.description:
            raise ValueError("tool definition action/description must not be empty")


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    task_id: TaskId
    messages: tuple[ModelMessage, ...]
    tools: tuple[ToolDefinition, ...]

    def __post_init__(self) -> None:
        if not self.messages:
            raise ValueError("provider request requires messages")


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    content: str

    def __post_init__(self) -> None:
        if not self.content:
            raise ValueError("provider response content must not be empty")


class ModelProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    @property
    def sink(self) -> Sink: ...

    def generate(self, request: ProviderRequest) -> ProviderResponse: ...

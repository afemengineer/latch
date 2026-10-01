"""Replaceable model-provider adapters outside the trusted core."""

from latch.providers.base import (
    MessageRole,
    ModelMessage,
    ModelProvider,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
    ToolDefinition,
)
from latch.providers.nebius import NebiusProvider
from latch.providers.openai_compatible import (
    JsonTransport,
    OpenAICompatibleProvider,
    UrllibJsonTransport,
)
from latch.providers.scripted import ScriptedProvider

__all__ = [
    "JsonTransport",
    "MessageRole",
    "ModelMessage",
    "ModelProvider",
    "NebiusProvider",
    "OpenAICompatibleProvider",
    "ProviderError",
    "ProviderRequest",
    "ProviderResponse",
    "ScriptedProvider",
    "ToolDefinition",
    "UrllibJsonTransport",
]

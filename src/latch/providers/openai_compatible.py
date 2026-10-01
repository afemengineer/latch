"""Minimal OpenAI-compatible remote model adapter.

The adapter owns credential resolution. The agent/model never receives the API
key; it supplies only ordinary model context after IFC approval.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Protocol, cast
from urllib import request as urllib_request

from latch.core.ids import CredentialId
from latch.core.information_flow import Sink, SinkKind
from latch.providers.base import (
    MessageRole,
    ModelMessage,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
)
from latch.secrets import CredentialVault

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class JsonTransport(Protocol):
    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, JsonValue],
        timeout_seconds: float,
    ) -> dict[str, JsonValue]: ...


class UrllibJsonTransport:
    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, JsonValue],
        timeout_seconds: float,
    ) -> dict[str, JsonValue]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib_request.Request(
            url,
            data=body,
            headers=dict(headers),
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=timeout_seconds) as response:
                raw = response.read()
        except OSError as exc:
            raise ProviderError("remote model request failed") from exc

        try:
            decoded = cast(object, json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError("remote model returned invalid JSON") from exc

        return _json_object(decoded)


def _json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_json_value(item) for item in cast(list[object], value)]
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key, item in cast(dict[object, object], value).items():
            if not isinstance(key, str):
                raise ProviderError("JSON object keys must be strings")
            result[key] = _json_value(item)
        return result
    raise ProviderError("remote model returned unsupported JSON value")


def _json_object(value: object) -> dict[str, JsonValue]:
    normalized = _json_value(value)
    if not isinstance(normalized, dict):
        raise ProviderError("remote model response must be a JSON object")
    return normalized


def _message_payload(message: ModelMessage) -> dict[str, JsonValue]:
    if message.role is MessageRole.OBSERVATION:
        return {
            "role": "user",
            "content": f"[LATCH OBSERVATION]\n{message.content}",
        }
    return {"role": message.role.value, "content": message.content}


class OpenAICompatibleProvider:
    executor_id = "model-provider:openai-compatible"

    def __init__(
        self,
        *,
        provider_id: str,
        base_url: str,
        model: str,
        credential_id: CredentialId,
        vault: CredentialVault,
        transport: JsonTransport | None = None,
        timeout_seconds: float = 60.0,
        executor_id: str | None = None,
    ) -> None:
        if not provider_id or not base_url or not model:
            raise ValueError("provider_id, base_url, and model are required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        self._provider_id = provider_id
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._credential_id = credential_id
        self._vault = vault
        self._transport = transport or UrllibJsonTransport()
        self._timeout_seconds = timeout_seconds
        self._executor_id = executor_id or self.executor_id
        self._sink = Sink(SinkKind.REMOTE_MODEL, f"{provider_id}:{model}")

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def sink(self) -> Sink:
        return self._sink

    def generate(self, request: ProviderRequest) -> ProviderResponse:
        messages: list[JsonValue] = [
            _message_payload(message) for message in request.messages
        ]
        payload: dict[str, JsonValue] = {
            "model": self._model,
            "messages": messages,
            "temperature": 0,
        }

        with self._vault.resolve_for_executor(
            self._credential_id,
            executor_id=self._executor_id,
            task_id=request.task_id,
        ) as lease:
            response = self._transport.post_json(
                url=f"{self._base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {lease.reveal()}",
                    "Content-Type": "application/json",
                },
                payload=payload,
                timeout_seconds=self._timeout_seconds,
            )

        return ProviderResponse(_extract_content(response))


def _extract_content(response: Mapping[str, JsonValue]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderError("remote model response has no choices")

    first = choices[0]
    if not isinstance(first, dict):
        raise ProviderError("remote model choice must be an object")

    message = first.get("message")
    if not isinstance(message, dict):
        raise ProviderError("remote model choice has no message object")

    content = message.get("content")
    if not isinstance(content, str) or not content:
        raise ProviderError("remote model message content is missing")
    return content

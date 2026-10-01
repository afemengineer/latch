from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from latch.core.evidence import EvidenceLedger, render_timeline
from latch.core.ids import new_task_id
from latch.providers import (
    JsonTransport,
    MessageRole,
    ModelMessage,
    NebiusProvider,
    ProviderRequest,
    ToolDefinition,
)
from latch.providers.openai_compatible import JsonValue
from latch.secrets import CredentialVault, MemorySecretBackend, SecretRedactor

TOKEN = "nebius-api-secret-token"
NOW = datetime(2026, 10, 1, 23, 0, tzinfo=UTC)


class FakeTransport(JsonTransport):
    def __init__(self) -> None:
        self.headers: Mapping[str, str] | None = None
        self.payload: Mapping[str, JsonValue] | None = None
        self.url: str | None = None

    def post_json(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, JsonValue],
        timeout_seconds: float,
    ) -> dict[str, JsonValue]:
        assert timeout_seconds > 0
        self.url = url
        self.headers = dict(headers)
        self.payload = dict(payload)
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"action":"finish","arguments":{"message":"done"}}'
                        )
                    }
                }
            ]
        }


def test_nebius_provider_uses_sealed_api_key_without_putting_it_in_model_context() -> None:
    redactor = SecretRedactor()
    evidence = EvidenceLedger(text_sanitizer=redactor.redact_text)
    vault = CredentialVault(
        backend=MemorySecretBackend(),
        redactor=redactor,
        evidence=evidence,
    )
    handle = vault.connect(
        service="nebius",
        account_label="hackathon",
        bound_executor=NebiusProvider.executor_id,
        secret=TOKEN,
    )
    transport = FakeTransport()
    provider = NebiusProvider(
        base_url="https://example-nebius.test/v1",
        model="nemotron-test",
        credential_id=handle.credential_id,
        vault=vault,
        transport=transport,
    )
    request = ProviderRequest(
        task_id=new_task_id(),
        messages=(
            ModelMessage(MessageRole.SYSTEM, "Return JSON."),
            ModelMessage(MessageRole.USER, "Hello"),
        ),
        tools=(ToolDefinition("finish", "Finish", ("message",)),),
    )

    response = provider.generate(request)

    assert response.content.startswith('{"action":"finish"')
    assert transport.headers is not None
    assert transport.headers["Authorization"] == f"Bearer {TOKEN}"
    assert transport.payload is not None
    assert TOKEN not in str(transport.payload)
    assert provider.sink.target == "nebius:nemotron-test"
    assert transport.url == "https://example-nebius.test/v1/chat/completions"

    timeline = render_timeline(evidence.snapshot())
    assert TOKEN not in timeline
    assert "Sealed credential released to bound executor" in timeline

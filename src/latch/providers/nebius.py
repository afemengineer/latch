"""Nebius/Token-Factory configuration over the OpenAI-compatible adapter."""

from __future__ import annotations

from latch.core.ids import CredentialId
from latch.providers.openai_compatible import JsonTransport, OpenAICompatibleProvider
from latch.secrets import CredentialVault


class NebiusProvider(OpenAICompatibleProvider):
    executor_id = "model-provider:nebius"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        credential_id: CredentialId,
        vault: CredentialVault,
        transport: JsonTransport | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        super().__init__(
            provider_id="nebius",
            base_url=base_url,
            model=model,
            credential_id=credential_id,
            vault=vault,
            transport=transport,
            timeout_seconds=timeout_seconds,
            executor_id=self.executor_id,
        )

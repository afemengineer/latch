from __future__ import annotations

from collections.abc import Mapping

from latch.core.evidence import EvidenceLedger, render_timeline
from latch.core.ids import CredentialId, new_task_id
from latch.providers.openai_compatible import JsonTransport, JsonValue
from latch.secrets import CredentialVault, MemorySecretBackend, SecretRedactor
from latch.tools.web_search import TavilySearchBackend

TOKEN = "tvly-secret-token"


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
            "results": [
                {
                    "title": "Warranty",
                    "url": "https://manufacturer.example/warranty",
                    "content": "Two year warranty.",
                }
            ]
        }


def test_tavily_backend_uses_sealed_key_and_minimal_search_payload() -> None:
    redactor = SecretRedactor()
    evidence = EvidenceLedger(text_sanitizer=redactor.redact_text)
    vault = CredentialVault(
        backend=MemorySecretBackend(),
        redactor=redactor,
        evidence=evidence,
    )
    handle = vault.connect(
        service="tavily",
        account_label="hackathon",
        bound_executor=TavilySearchBackend.executor_id,
        secret=TOKEN,
    )
    transport = FakeTransport()
    backend = TavilySearchBackend(
        credential_id=handle.credential_id,
        vault=vault,
        transport=transport,
    )

    response = backend.search(
        task_id=new_task_id(),
        query="manufacturer warranty",
        max_results=5,
    )

    assert backend.sink.target == "https://api.tavily.com:443"
    assert transport.url == "https://api.tavily.com/search"
    assert transport.headers is not None
    assert transport.headers["Authorization"] == f"Bearer {TOKEN}"
    assert transport.payload is not None
    assert transport.payload["include_answer"] is False
    assert transport.payload["include_raw_content"] is False
    assert TOKEN not in str(transport.payload)
    assert response.results[0].title == "Warranty"

    timeline = render_timeline(evidence.snapshot())
    assert TOKEN not in timeline

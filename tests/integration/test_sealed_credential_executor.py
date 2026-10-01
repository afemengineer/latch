from datetime import UTC, datetime

from latch.core.evidence import EvidenceLedger, render_timeline
from latch.core.ids import CredentialId, TaskId, new_task_id
from latch.secrets import CredentialVault, MemorySecretBackend, SecretRedactor

NOW = datetime(2026, 10, 1, 22, 45, tzinfo=UTC)
TOKEN = "calendar-oauth-token-that-must-never-reach-the-model"


class DemoCalendarTransport:
    """Simulates one trusted executor boundary."""

    executor_id = "google-calendar"

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault
        self.last_authorization_header: str | None = None

    def create_event(
        self,
        *,
        task_id: TaskId,
        credential_id: CredentialId,
        title: str,
    ) -> dict[str, str]:
        with self._vault.resolve_for_executor(
            credential_id,
            executor_id=self.executor_id,
            task_id=task_id,
            at=NOW,
        ) as lease:
            self.last_authorization_header = f"Bearer {lease.reveal()}"

        return {"status": "created", "title": title, "event_id": "evt_demo_1"}


def test_executor_can_use_credential_without_returning_it_to_model() -> None:
    redactor = SecretRedactor()
    evidence = EvidenceLedger(text_sanitizer=redactor.redact_text)
    vault = CredentialVault(
        backend=MemorySecretBackend(),
        redactor=redactor,
        evidence=evidence,
    )
    handle = vault.connect(
        service="calendar",
        account_label="personal",
        bound_executor=DemoCalendarTransport.executor_id,
        secret=TOKEN,
    )
    transport = DemoCalendarTransport(vault)
    task_id = new_task_id()

    model_visible_handle = handle.to_model_dict()
    result = transport.create_event(
        task_id=task_id,
        credential_id=handle.credential_id,
        title="Return period reminder",
    )

    assert TOKEN not in str(model_visible_handle)
    assert TOKEN not in str(result)
    assert transport.last_authorization_header == f"Bearer {TOKEN}"

    timeline = render_timeline(evidence.snapshot())
    assert TOKEN not in timeline
    assert "Sealed credential released to bound executor" in timeline
    assert evidence.verify().valid

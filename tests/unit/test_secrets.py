from __future__ import annotations

from datetime import UTC, datetime

import pytest

from latch.core.canonical import canonical_json
from latch.core.evidence import EvidenceKind, EvidenceLedger, render_timeline
from latch.core.ids import CredentialId, new_task_id
from latch.secrets import (
    REDACTED_SECRET,
    CredentialAccessDenied,
    CredentialNotFound,
    CredentialVault,
    MemorySecretBackend,
    SecretRedactor,
)

NOW = datetime(2026, 10, 1, 22, 30, tzinfo=UTC)
TOKEN = "super-secret-token-value"


class CountingBackend(MemorySecretBackend):
    def __init__(self) -> None:
        super().__init__()
        self.reads = 0

    def get(self, credential_id: CredentialId) -> str | None:
        self.reads += 1
        return super().get(credential_id)


def test_model_safe_handle_contains_metadata_but_not_secret() -> None:
    vault = CredentialVault(backend=MemorySecretBackend())
    handle = vault.connect(
        service="calendar",
        account_label="personal",
        bound_executor="google-calendar",
        secret=TOKEN,
    )

    model_view = handle.to_model_dict()
    serialized = canonical_json(handle)

    assert model_view["service"] == "calendar"
    assert model_view["bound_executor"] == "google-calendar"
    assert TOKEN not in str(model_view)
    assert TOKEN not in serialized


def test_secret_lease_repr_and_str_never_expose_value() -> None:
    vault = CredentialVault(backend=MemorySecretBackend())
    handle = vault.connect(
        service="calendar",
        account_label="personal",
        bound_executor="google-calendar",
        secret=TOKEN,
    )
    lease = vault.resolve_for_executor(
        handle.credential_id,
        executor_id="google-calendar",
        task_id=new_task_id(),
        at=NOW,
    )

    assert TOKEN not in repr(lease)
    assert TOKEN not in str(lease)
    assert lease.reveal() == TOKEN


def test_secret_lease_closes_and_drops_its_reference() -> None:
    vault = CredentialVault(backend=MemorySecretBackend())
    handle = vault.connect(
        service="calendar",
        account_label="personal",
        bound_executor="google-calendar",
        secret=TOKEN,
    )

    with vault.resolve_for_executor(
        handle.credential_id,
        executor_id="google-calendar",
        task_id=new_task_id(),
        at=NOW,
    ) as lease:
        assert lease.reveal() == TOKEN

    assert lease.closed
    with pytest.raises(RuntimeError, match="closed"):
        lease.reveal()


def test_wrong_executor_is_denied_before_backend_read() -> None:
    backend = CountingBackend()
    vault = CredentialVault(backend=backend)
    handle = vault.connect(
        service="calendar",
        account_label="personal",
        bound_executor="google-calendar",
        secret=TOKEN,
    )

    with pytest.raises(CredentialAccessDenied):
        vault.resolve_for_executor(
            handle.credential_id,
            executor_id="generic-http",
            task_id=new_task_id(),
            at=NOW,
        )

    assert backend.reads == 0


def test_disconnect_removes_handle_and_secret() -> None:
    backend = MemorySecretBackend()
    vault = CredentialVault(backend=backend)
    handle = vault.connect(
        service="calendar",
        account_label="personal",
        bound_executor="google-calendar",
        secret=TOKEN,
    )

    vault.disconnect(handle.credential_id)

    assert backend.get(handle.credential_id) is None
    with pytest.raises(CredentialNotFound):
        vault.get_handle(handle.credential_id)


def test_rotate_updates_secret_without_changing_public_handle() -> None:
    backend = MemorySecretBackend()
    vault = CredentialVault(backend=backend)
    handle = vault.connect(
        service="calendar",
        account_label="personal",
        bound_executor="google-calendar",
        secret=TOKEN,
    )
    replacement = "replacement-secret-token"

    vault.rotate(handle.credential_id, replacement)
    with vault.resolve_for_executor(
        handle.credential_id,
        executor_id="google-calendar",
        task_id=new_task_id(),
        at=NOW,
    ) as lease:
        assert lease.reveal() == replacement

    assert vault.get_handle(handle.credential_id) == handle


def test_redactor_replaces_exact_registered_secrets_longest_first() -> None:
    redactor = SecretRedactor()
    redactor.register("abc")
    redactor.register("abcdef")

    sanitized = redactor.redact_text("token=abcdef and short=abc")

    assert sanitized == f"token={REDACTED_SECRET} and short={REDACTED_SECRET}"
    assert "abcdef" not in sanitized
    assert repr(redactor) == "<SecretRedactor registered_values=2>"


def test_evidence_ledger_sanitizer_catches_accidental_exact_secret_copy() -> None:
    redactor = SecretRedactor()
    redactor.register(TOKEN)
    ledger = EvidenceLedger(text_sanitizer=redactor.redact_text)
    task_id = new_task_id()

    ledger.append(
        task_id=task_id,
        kind=EvidenceKind.EXECUTION_RESULT,
        summary=f"executor accidentally returned {TOKEN}",
        details={"debug": f"authorization=Bearer {TOKEN}"},
        at=NOW,
    )

    timeline = render_timeline(ledger.snapshot())
    assert TOKEN not in timeline
    assert REDACTED_SECRET in timeline
    assert ledger.verify().valid


def test_vault_evidence_never_records_secret_value() -> None:
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
        bound_executor="google-calendar",
        secret=TOKEN,
    )
    task_id = new_task_id()

    with vault.resolve_for_executor(
        handle.credential_id,
        executor_id="google-calendar",
        task_id=task_id,
        at=NOW,
    ) as lease:
        assert lease.reveal() == TOKEN

    timeline = render_timeline(evidence.snapshot())
    assert TOKEN not in timeline
    assert "credential_" in timeline
    assert "sealed_secret" in timeline


def test_memory_backend_repr_does_not_expose_secret() -> None:
    backend = MemorySecretBackend()
    backend.set(CredentialId("credential-test"), TOKEN)

    assert TOKEN not in repr(backend)
    assert "credentials=1" in repr(backend)

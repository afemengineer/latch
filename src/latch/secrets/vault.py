"""Purpose-bound credential vault."""

from __future__ import annotations

from datetime import datetime
from threading import RLock

from latch.core.evidence import EvidenceKind, EvidenceLedger
from latch.core.ids import CredentialId, TaskId, new_credential_id
from latch.core.information_flow import FlowPolicy, FlowRequest, Sink, SinkKind
from latch.core.types import DecisionOutcome
from latch.secrets.backends import SecretBackend
from latch.secrets.models import (
    CredentialAccessDenied,
    CredentialHandle,
    CredentialNotFound,
    SecretLease,
)
from latch.secrets.redaction import SecretRedactor


class CredentialVault:
    def __init__(
        self,
        *,
        backend: SecretBackend,
        redactor: SecretRedactor | None = None,
        evidence: EvidenceLedger | None = None,
    ) -> None:
        self._backend = backend
        self._redactor = redactor or SecretRedactor()
        self._evidence = evidence
        self._handles: dict[CredentialId, CredentialHandle] = {}
        self._lock = RLock()

    @property
    def redactor(self) -> SecretRedactor:
        return self._redactor

    def connect(
        self,
        *,
        service: str,
        account_label: str,
        bound_executor: str,
        secret: str,
    ) -> CredentialHandle:
        if not secret:
            raise ValueError("secret value must not be empty")

        credential_id = new_credential_id()
        handle = CredentialHandle(
            credential_id=credential_id,
            service=service,
            account_label=account_label,
            bound_executor=bound_executor,
        )

        self._backend.set(credential_id, secret)
        self._redactor.register(secret)
        with self._lock:
            self._handles[credential_id] = handle
        return handle

    def catalog(self) -> tuple[CredentialHandle, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self._handles.values(),
                    key=lambda handle: (
                        handle.service,
                        handle.account_label,
                        str(handle.credential_id),
                    ),
                )
            )

    def get_handle(self, credential_id: CredentialId) -> CredentialHandle:
        with self._lock:
            try:
                return self._handles[credential_id]
            except KeyError as exc:
                raise CredentialNotFound(str(credential_id)) from exc

    def rotate(self, credential_id: CredentialId, new_secret: str) -> None:
        if not new_secret:
            raise ValueError("secret value must not be empty")
        self.get_handle(credential_id)
        self._backend.set(credential_id, new_secret)
        self._redactor.register(new_secret)

    def disconnect(self, credential_id: CredentialId) -> None:
        self.get_handle(credential_id)
        self._backend.delete(credential_id)
        with self._lock:
            self._handles.pop(credential_id, None)

    def resolve_for_executor(
        self,
        credential_id: CredentialId,
        *,
        executor_id: str,
        task_id: TaskId,
        at: datetime | None = None,
    ) -> SecretLease:
        """Resolve a credential only to its exact canonical bound executor."""

        if not executor_id:
            raise ValueError("executor_id must not be empty")

        handle = self.get_handle(credential_id)
        request = FlowRequest(
            sources=(handle.data_ref(),),
            sink=Sink(SinkKind.TRUSTED_EXECUTOR, executor_id),
        )
        decision = FlowPolicy().evaluate(request)

        if decision.outcome is not DecisionOutcome.ALLOW:
            self._record(
                task_id,
                "Sealed credential access denied",
                {
                    "credential_id": str(credential_id),
                    "service": handle.service,
                    "executor": executor_id,
                    "bound_executor": handle.bound_executor,
                    "outcome": decision.outcome.value,
                    "reason": decision.reason.value,
                },
                at,
            )
            raise CredentialAccessDenied(
                f"credential {credential_id} is not bound to executor {executor_id!r}"
            )

        value = self._backend.get(credential_id)
        if value is None:
            raise CredentialNotFound(str(credential_id))

        self._redactor.register(value)
        self._record(
            task_id,
            "Sealed credential released to bound executor",
            {
                "credential_id": str(credential_id),
                "service": handle.service,
                "account": handle.account_label,
                "executor": executor_id,
                "label": handle.data_ref().label.value,
                "outcome": decision.outcome.value,
                "reason": decision.reason.value,
            },
            at,
        )
        return SecretLease(
            credential_id=credential_id,
            executor_id=executor_id,
            value=value,
        )

    def _record(
        self,
        task_id: TaskId,
        summary: str,
        details: dict[str, str],
        at: datetime | None,
    ) -> None:
        if self._evidence is None:
            return
        self._evidence.append(
            task_id=task_id,
            kind=EvidenceKind.FLOW_DECISION,
            summary=summary,
            details=details,
            at=at,
        )

"""Safe public credential handles and short-lived resolved secret leases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from latch.core.ids import CredentialId
from latch.core.information_flow import DataRef
from latch.core.types import DataLabel


class CredentialNotFound(KeyError):
    """Credential metadata or secret material no longer exists."""


class CredentialAccessDenied(RuntimeError):
    """Credential was requested by an executor it is not bound to."""


@dataclass(frozen=True, slots=True)
class CredentialHandle:
    """Model-safe metadata for one connected credential."""

    credential_id: CredentialId
    service: str
    account_label: str
    bound_executor: str

    def __post_init__(self) -> None:
        for name, value in (
            ("service", self.service),
            ("account_label", self.account_label),
            ("bound_executor", self.bound_executor),
        ):
            if not value:
                raise ValueError(f"{name} must not be empty")
            if "\x00" in value:
                raise ValueError(f"{name} cannot contain NUL")

    def data_ref(self) -> DataRef:
        return DataRef(
            data_id=f"credential:{self.credential_id}",
            label=DataLabel.SEALED_SECRET,
            origin=f"credential-vault:{self.service}:{self.account_label}",
            sealed_binding=self.bound_executor,
        )

    def to_model_dict(self) -> dict[str, str]:
        return {
            "credential_id": str(self.credential_id),
            "service": self.service,
            "account_label": self.account_label,
            "bound_executor": self.bound_executor,
        }


class SecretLease:
    """Short-lived trusted-executor view of one secret value."""

    __slots__ = ("_closed", "_credential_id", "_executor_id", "_value")

    def __init__(
        self,
        *,
        credential_id: CredentialId,
        executor_id: str,
        value: str,
    ) -> None:
        self._credential_id = credential_id
        self._executor_id = executor_id
        self._value: str | None = value
        self._closed = False

    @property
    def credential_id(self) -> CredentialId:
        return self._credential_id

    @property
    def executor_id(self) -> str:
        return self._executor_id

    @property
    def closed(self) -> bool:
        return self._closed

    def reveal(self) -> str:
        if self._closed or self._value is None:
            raise RuntimeError("secret lease is closed")
        return self._value

    def close(self) -> None:
        self._value = None
        self._closed = True

    def __enter__(self) -> Self:
        if self._closed:
            raise RuntimeError("secret lease is closed")
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"<SecretLease credential_id={self._credential_id!s} "
            f"executor_id={self._executor_id!r} value=<redacted> closed={self._closed}>"
        )

    def __str__(self) -> str:
        return "<redacted-secret-lease>"

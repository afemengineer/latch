"""Secret-storage backends.

The default test/dev backend is in-memory. KeyringSecretBackend is an optional
adapter to the host OS keyring selected by the Python keyring package.
"""

from __future__ import annotations

from importlib import import_module
from threading import RLock
from typing import Protocol, cast

from latch.core.ids import CredentialId


class SecretBackendError(RuntimeError):
    """Secret backend operation failed."""


class SecretBackendUnavailable(SecretBackendError):
    """No usable protected OS secret backend is available."""


class SecretBackend(Protocol):
    def set(self, credential_id: CredentialId, value: str) -> None: ...

    def get(self, credential_id: CredentialId) -> str | None: ...

    def delete(self, credential_id: CredentialId) -> None: ...


class MemorySecretBackend:
    """Process-local backend for tests/development only."""

    def __init__(self) -> None:
        self._values: dict[CredentialId, str] = {}
        self._lock = RLock()

    def set(self, credential_id: CredentialId, value: str) -> None:
        if not value:
            raise ValueError("secret value must not be empty")
        with self._lock:
            self._values[credential_id] = value

    def get(self, credential_id: CredentialId) -> str | None:
        with self._lock:
            return self._values.get(credential_id)

    def delete(self, credential_id: CredentialId) -> None:
        with self._lock:
            self._values.pop(credential_id, None)

    def __repr__(self) -> str:
        with self._lock:
            return f"<MemorySecretBackend credentials={len(self._values)}>"


class _KeyringBackend(Protocol):
    priority: float


class _KeyringApi(Protocol):
    def get_keyring(self) -> _KeyringBackend: ...

    def set_password(self, service_name: str, username: str, password: str) -> None: ...

    def get_password(self, service_name: str, username: str) -> str | None: ...

    def delete_password(self, service_name: str, username: str) -> None: ...


class KeyringSecretBackend:
    """Optional OS-keyring adapter.

    Install with: uv sync --extra os-secrets.
    V0 rejects keyring's fail/no-op backend by requiring positive priority.
    """

    def __init__(self, *, namespace: str = "latch") -> None:
        if not namespace:
            raise ValueError("keyring namespace must not be empty")
        self._namespace = namespace
        self._api = self._load_api()
        if self._api.get_keyring().priority <= 0:
            raise SecretBackendUnavailable("no usable OS keyring backend is configured")

    def set(self, credential_id: CredentialId, value: str) -> None:
        if not value:
            raise ValueError("secret value must not be empty")
        try:
            self._api.set_password(self._namespace, str(credential_id), value)
        except Exception as exc:
            raise SecretBackendError("OS keyring write failed") from exc

    def get(self, credential_id: CredentialId) -> str | None:
        try:
            return self._api.get_password(self._namespace, str(credential_id))
        except Exception as exc:
            raise SecretBackendError("OS keyring read failed") from exc

    def delete(self, credential_id: CredentialId) -> None:
        try:
            if self._api.get_password(self._namespace, str(credential_id)) is not None:
                self._api.delete_password(self._namespace, str(credential_id))
        except Exception as exc:
            raise SecretBackendError("OS keyring delete failed") from exc

    @staticmethod
    def _load_api() -> _KeyringApi:
        try:
            module = import_module("keyring")
        except ModuleNotFoundError as exc:
            raise SecretBackendUnavailable(
                "keyring is not installed; install the os-secrets extra"
            ) from exc
        return cast(_KeyringApi, module)

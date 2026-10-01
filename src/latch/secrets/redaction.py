"""Defense-in-depth exact-value secret redaction."""

from __future__ import annotations

from threading import RLock

REDACTED_SECRET = "<redacted-secret>"


class SecretRedactor:
    """Best-effort exact-value sanitizer for logs/evidence."""

    def __init__(self) -> None:
        self._values: set[str] = set()
        self._lock = RLock()

    def register(self, value: str) -> None:
        if not value:
            raise ValueError("secret value must not be empty")
        with self._lock:
            self._values.add(value)

    def redact_text(self, text: str) -> str:
        with self._lock:
            values = tuple(sorted(self._values, key=len, reverse=True))

        result = text
        for value in values:
            result = result.replace(value, REDACTED_SECRET)
        return result

    def __repr__(self) -> str:
        with self._lock:
            return f"<SecretRedactor registered_values={len(self._values)}>"

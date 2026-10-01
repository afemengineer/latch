"""Deterministic serialization for security-relevant records."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID


def _normalize(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _normalize(getattr(value, field.name)) for field in fields(value)}

    if isinstance(value, Enum):
        return _normalize(value.value)

    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("security-relevant datetimes must be timezone-aware")
        utc_value = value.astimezone(UTC)
        return utc_value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical mappings require string keys")
            normalized[key] = _normalize(item)
        return {key: normalized[key] for key in sorted(normalized)}

    if isinstance(value, (set, frozenset)):
        items = [_normalize(item) for item in value]
        return sorted(
            items,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )

    if isinstance(value, (tuple, list)):
        return [_normalize(item) for item in value]

    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite floats are not canonicalizable")

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_data(value: Any) -> Any:
    """Return a JSON-compatible deterministic representation."""

    return _normalize(value)


def canonical_json(value: Any) -> str:
    """Serialize *value* using a stable JSON representation."""

    return json.dumps(
        canonical_data(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

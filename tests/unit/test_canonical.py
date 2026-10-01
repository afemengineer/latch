from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone

import pytest

from latch.core.canonical import canonical_json
from latch.core.types import Operation


@dataclass(frozen=True)
class Record:
    operations: frozenset[Operation]
    created_at: datetime


def test_canonical_json_is_stable_for_unordered_values() -> None:
    first = Record(
        operations=frozenset({Operation.FILESYSTEM_READ, Operation.FILESYSTEM_INSPECT}),
        created_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
    )
    second = Record(
        operations=frozenset({Operation.FILESYSTEM_INSPECT, Operation.FILESYSTEM_READ}),
        created_at=datetime(2026, 10, 1, 14, 0, tzinfo=timezone(timedelta(hours=2))),
    )

    assert canonical_json(first) == canonical_json(second)


def test_canonical_json_rejects_naive_datetime() -> None:
    record = Record(
        operations=frozenset({Operation.FILESYSTEM_READ}),
        created_at=datetime(2026, 10, 1, 12, 0),
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json(record)

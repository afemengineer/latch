"""Append-only in-memory evidence ledger with SHA-256 hash chaining."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from threading import RLock

from latch.core.canonical import canonical_json
from latch.core.evidence.models import (
    ChainFailure,
    ChainVerification,
    EvidenceDetails,
    EvidenceEvent,
    EvidenceKind,
    EvidenceScalar,
    normalize_evidence_details,
)
from latch.core.ids import EvidenceId, TaskId, new_evidence_id

GENESIS_HASH = "0" * 64
_HASH_DOMAIN = b"latch-evidence-v1\x00"


@dataclass(frozen=True, slots=True)
class _EvidenceHashBody:
    schema_version: int
    evidence_id: EvidenceId
    task_id: TaskId
    sequence: int
    occurred_at: datetime
    kind: EvidenceKind
    summary: str
    details: EvidenceDetails


def _hash_fields(
    *,
    evidence_id: EvidenceId,
    task_id: TaskId,
    sequence: int,
    occurred_at: datetime,
    kind: EvidenceKind,
    summary: str,
    details: EvidenceDetails,
    previous_hash: str,
) -> str:
    body = _EvidenceHashBody(
        schema_version=1,
        evidence_id=evidence_id,
        task_id=task_id,
        sequence=sequence,
        occurred_at=occurred_at,
        kind=kind,
        summary=summary,
        details=details,
    )

    digest = sha256()
    digest.update(_HASH_DOMAIN)
    digest.update(previous_hash.encode("ascii"))
    digest.update(b"\x00")
    digest.update(canonical_json(body).encode("utf-8"))
    return digest.hexdigest()


def calculate_event_hash(event: EvidenceEvent) -> str:
    """Recompute the cryptographic hash committed to by *event*."""

    return _hash_fields(
        evidence_id=event.evidence_id,
        task_id=event.task_id,
        sequence=event.sequence,
        occurred_at=event.occurred_at,
        kind=event.kind,
        summary=event.summary,
        details=event.details,
        previous_hash=event.previous_hash,
    )


def verify_evidence_chain(events: Iterable[EvidenceEvent]) -> ChainVerification:
    """Verify sequence numbers, links, and hashes for an evidence sequence."""

    previous_hash = GENESIS_HASH
    checked = 0

    for index, event in enumerate(events):
        if event.sequence != index:
            return ChainVerification(
                valid=False,
                checked_events=checked,
                failure_index=index,
                failure=ChainFailure.SEQUENCE_MISMATCH,
            )
        if event.previous_hash != previous_hash:
            return ChainVerification(
                valid=False,
                checked_events=checked,
                failure_index=index,
                failure=ChainFailure.PREVIOUS_HASH_MISMATCH,
            )
        if event.event_hash != calculate_event_hash(event):
            return ChainVerification(
                valid=False,
                checked_events=checked,
                failure_index=index,
                failure=ChainFailure.HASH_MISMATCH,
            )

        previous_hash = event.event_hash
        checked += 1

    return ChainVerification(valid=True, checked_events=checked)


class EvidenceLedger:
    """Append-only process-local ledger.

    An optional deterministic text sanitizer provides defense-in-depth against
    accidental secret logging. Security code must still avoid passing SECRET
    payloads to evidence in the first place; sanitization is not declassification.
    """

    def __init__(
        self,
        *,
        text_sanitizer: Callable[[str], str] | None = None,
    ) -> None:
        self._events: list[EvidenceEvent] = []
        self._text_sanitizer = text_sanitizer
        self._lock = RLock()

    @property
    def tail_hash(self) -> str:
        with self._lock:
            if not self._events:
                return GENESIS_HASH
            return self._events[-1].event_hash

    def append(
        self,
        *,
        task_id: TaskId,
        kind: EvidenceKind,
        summary: str,
        details: Mapping[str, EvidenceScalar] | None = None,
        at: datetime | None = None,
    ) -> EvidenceEvent:
        occurred_at = at or datetime.now(UTC)
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("evidence timestamps must be timezone-aware")

        safe_summary = self._sanitize(summary)
        safe_details = self._sanitize_details(details)
        normalized_details = normalize_evidence_details(safe_details)

        with self._lock:
            sequence = len(self._events)
            previous_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
            evidence_id = new_evidence_id()
            event_hash = _hash_fields(
                evidence_id=evidence_id,
                task_id=task_id,
                sequence=sequence,
                occurred_at=occurred_at,
                kind=kind,
                summary=safe_summary,
                details=normalized_details,
                previous_hash=previous_hash,
            )
            event = EvidenceEvent(
                evidence_id=evidence_id,
                task_id=task_id,
                sequence=sequence,
                occurred_at=occurred_at,
                kind=kind,
                summary=safe_summary,
                details=normalized_details,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
            self._events.append(event)
            return event

    def snapshot(self) -> tuple[EvidenceEvent, ...]:
        """Return an immutable point-in-time view of the ledger."""

        with self._lock:
            return tuple(self._events)

    def for_task(self, task_id: TaskId) -> tuple[EvidenceEvent, ...]:
        with self._lock:
            return tuple(event for event in self._events if event.task_id == task_id)

    def verify(self) -> ChainVerification:
        return verify_evidence_chain(self.snapshot())

    def _sanitize(self, value: str) -> str:
        if self._text_sanitizer is None:
            return value
        return self._text_sanitizer(value)

    def _sanitize_details(
        self,
        details: Mapping[str, EvidenceScalar] | None,
    ) -> Mapping[str, EvidenceScalar] | None:
        if details is None or self._text_sanitizer is None:
            return details

        sanitized: dict[str, EvidenceScalar] = {}
        for key, value in details.items():
            sanitized[key] = self._sanitize(value) if isinstance(value, str) else value
        return sanitized

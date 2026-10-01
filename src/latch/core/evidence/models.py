"""Value objects for Latch evidence records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from latch.core.ids import EvidenceId, TaskId

type EvidenceScalar = str | int | bool | None
type EvidenceDetails = tuple[tuple[str, EvidenceScalar], ...]

_MAX_SUMMARY_CHARS = 512
_MAX_DETAIL_FIELDS = 32
_MAX_DETAIL_KEY_CHARS = 96
_MAX_DETAIL_STRING_CHARS = 2048


class EvidenceKind(StrEnum):
    TASK_TRANSITION = "task_transition"
    ACTION_PROPOSAL = "action_proposal"
    POLICY_DECISION = "policy_decision"
    APPROVAL = "approval"
    GRANT_ISSUED = "grant_issued"
    GRANT_REVOKED = "grant_revoked"
    EXECUTION_STARTED = "execution_started"
    EXECUTION_RESULT = "execution_result"
    FLOW_DECISION = "flow_decision"
    VERIFICATION_RESULT = "verification_result"
    ROLLBACK = "rollback"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"


class ChainFailure(StrEnum):
    SEQUENCE_MISMATCH = "sequence_mismatch"
    PREVIOUS_HASH_MISMATCH = "previous_hash_mismatch"
    HASH_MISMATCH = "hash_mismatch"


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    """Immutable security-relevant audit event.

    details contains bounded flat metadata only. Raw tool/model payloads do not
    belong in evidence records. Information-flow checks for data-derived text
    remain a responsibility of the caller before constructing an event.
    """

    evidence_id: EvidenceId
    task_id: TaskId
    sequence: int
    occurred_at: datetime
    kind: EvidenceKind
    summary: str
    details: EvidenceDetails
    previous_hash: str
    event_hash: str

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("evidence sequence must be non-negative")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("evidence timestamps must be timezone-aware")
        if not self.summary:
            raise ValueError("evidence summary must not be empty")
        if len(self.summary) > _MAX_SUMMARY_CHARS:
            raise ValueError("evidence summary is too long")
        _validate_hash(self.previous_hash, "previous_hash")
        _validate_hash(self.event_hash, "event_hash")
        _validate_normalized_details(self.details)


@dataclass(frozen=True, slots=True)
class ChainVerification:
    valid: bool
    checked_events: int
    failure_index: int | None = None
    failure: ChainFailure | None = None


def normalize_evidence_details(
    details: Mapping[str, EvidenceScalar] | None = None,
) -> EvidenceDetails:
    """Normalize bounded metadata into a deterministic immutable representation."""

    if details is None:
        return ()
    if len(details) > _MAX_DETAIL_FIELDS:
        raise ValueError("too many evidence detail fields")

    normalized: list[tuple[str, EvidenceScalar]] = []
    for key, value in details.items():
        if not key:
            raise ValueError("evidence detail keys must not be empty")
        if len(key) > _MAX_DETAIL_KEY_CHARS:
            raise ValueError("evidence detail key is too long")
        if "\x00" in key:
            raise ValueError("evidence detail keys cannot contain NUL")

        _validate_scalar(value)
        normalized.append((key, value))

    normalized.sort(key=lambda item: item[0])
    return tuple(normalized)


def _validate_scalar(value: object) -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        if len(value) > _MAX_DETAIL_STRING_CHARS:
            raise ValueError("evidence detail string is too long")
        if "\x00" in value:
            raise ValueError("evidence detail strings cannot contain NUL")
        return
    raise TypeError("evidence details support only str, int, bool, or None")


def _validate_normalized_details(details: EvidenceDetails) -> None:
    if len(details) > _MAX_DETAIL_FIELDS:
        raise ValueError("too many evidence detail fields")

    keys: list[str] = []
    for key, value in details:
        if not key:
            raise ValueError("evidence detail keys must not be empty")
        if len(key) > _MAX_DETAIL_KEY_CHARS:
            raise ValueError("evidence detail key is too long")
        if "\x00" in key:
            raise ValueError("evidence detail keys cannot contain NUL")
        _validate_scalar(value)
        keys.append(key)

    if keys != sorted(keys):
        raise ValueError("evidence details must be sorted by key")
    if len(keys) != len(set(keys)):
        raise ValueError("evidence detail keys must be unique")


def _validate_hash(value: str, name: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")

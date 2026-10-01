"""Capability requests, grants, and persistent policy rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from latch.core.capabilities.filesystem import FilesystemResource, FilesystemResourceSelector
from latch.core.ids import GrantId, RequestId, RuleId, TaskId, new_request_id
from latch.core.types import DecisionOutcome, Operation, PolicyEffect


def _aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ConstraintSet:
    max_operations: int | None = None
    max_bytes: int | None = None
    overwrite: bool | None = None

    def __post_init__(self) -> None:
        if self.max_operations is not None and self.max_operations < 0:
            raise ValueError("max_operations must be non-negative")
        if self.max_bytes is not None and self.max_bytes < 0:
            raise ValueError("max_bytes must be non-negative")

    def allows_request(self, request: CapabilityRequest) -> bool:
        if self.max_bytes is not None and request.bytes_requested > self.max_bytes:
            return False
        return not (self.overwrite is False and request.overwrite)


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    task_id: TaskId
    operation: Operation
    resource: FilesystemResource
    bytes_requested: int = 0
    overwrite: bool = False
    request_id: RequestId = field(default_factory=new_request_id)

    def __post_init__(self) -> None:
        if self.bytes_requested < 0:
            raise ValueError("bytes_requested must be non-negative")


@dataclass(frozen=True, slots=True)
class GrantUse:
    """One concrete resource use to reserve against a grant atomically."""

    grant_id: GrantId
    request: CapabilityRequest


@dataclass(frozen=True, slots=True)
class Grant:
    grant_id: GrantId
    task_id: TaskId
    operations: frozenset[Operation]
    selector: FilesystemResourceSelector
    constraints: ConstraintSet
    issued_by: str
    issued_at: datetime
    expires_at: datetime
    rule_id: RuleId | None = None

    def __post_init__(self) -> None:
        _aware(self.issued_at, "issued_at")
        _aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("grant expiry must be after issuance")
        if not self.operations:
            raise ValueError("a grant must authorize at least one operation")

    def is_active(self, at: datetime) -> bool:
        _aware(at, "at")
        return self.issued_at <= at < self.expires_at

    def covers(self, request: CapabilityRequest, at: datetime) -> bool:
        return (
            self.task_id == request.task_id
            and request.operation in self.operations
            and self.selector.contains(request.resource)
            and self.constraints.allows_request(request)
            and self.is_active(at)
        )


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: RuleId
    effect: PolicyEffect
    operations: frozenset[Operation]
    selector: FilesystemResourceSelector
    constraints: ConstraintSet = field(default_factory=ConstraintSet)
    description: str = ""

    def __post_init__(self) -> None:
        if not self.operations:
            raise ValueError("a policy rule must reference at least one operation")

    def matches_scope(self, request: CapabilityRequest) -> bool:
        return request.operation in self.operations and self.selector.contains(request.resource)

    def allows(self, request: CapabilityRequest) -> bool:
        return self.matches_scope(request) and self.constraints.allows_request(request)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    request_id: RequestId
    outcome: DecisionOutcome
    reason: str
    grant_id: GrantId | None = None
    rule_id: RuleId | None = None

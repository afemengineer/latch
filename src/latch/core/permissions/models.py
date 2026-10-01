"""Immutable permission-envelope value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from latch.core.capabilities import (
    CapabilityRequest,
    CapabilitySelector,
    ConstraintSet,
)
from latch.core.ids import PermissionId, SkillId
from latch.core.information_flow import FlowDecision, Sink
from latch.core.types import DecisionOutcome, Operation, RiskLevel


class PermissionReason(StrEnum):
    STANDING_PERMISSION = "standing_permission"
    MISSING_STANDING_PERMISSION = "missing_standing_permission"
    OUTSIDE_AUTHORITY_CEILING = "outside_authority_ceiling"
    SKILL_DISABLED = "skill_disabled"
    FLOW_POLICY_ALLOW = "flow_policy_allow"
    STANDING_FLOW_PERMISSION = "standing_flow_permission"
    TASK_FLOW_PERMISSION = "task_flow_permission"
    FLOW_REQUIRES_APPROVAL = "flow_requires_approval"
    FLOW_PROHIBITED = "flow_prohibited"


@dataclass(frozen=True, slots=True)
class PermissionConsequence:
    """User-facing consequence text produced deterministically by Latch."""

    title: str
    detail: str
    risk: RiskLevel
    data_leaves_device: bool = False

    def __post_init__(self) -> None:
        if not self.title:
            raise ValueError("permission consequence title must not be empty")
        if not self.detail:
            raise ValueError("permission consequence detail must not be empty")


@dataclass(frozen=True, slots=True)
class CapabilityCeilingRule:
    operations: frozenset[Operation]
    selector: CapabilitySelector
    constraints: ConstraintSet = field(default_factory=ConstraintSet)

    def __post_init__(self) -> None:
        if not self.operations:
            raise ValueError("authority ceiling rule requires at least one operation")

    def allows(self, request: CapabilityRequest) -> bool:
        return (
            request.operation in self.operations
            and self.selector.contains(request.resource)
            and self.constraints.allows_request(request)
        )


@dataclass(frozen=True, slots=True)
class StandingCapabilityPermission:
    permission_id: PermissionId
    operations: frozenset[Operation]
    selector: CapabilitySelector
    constraints: ConstraintSet
    approved_by: str

    def __post_init__(self) -> None:
        if not self.operations:
            raise ValueError("standing permission requires at least one operation")
        if not self.approved_by:
            raise ValueError("standing permission requires approval provenance")

    def allows(self, request: CapabilityRequest) -> bool:
        return (
            request.operation in self.operations
            and self.selector.contains(request.resource)
            and self.constraints.allows_request(request)
        )


@dataclass(frozen=True, slots=True)
class PermissionEnvelope:
    skill_id: SkillId
    display_name: str
    authority_ceiling: tuple[CapabilityCeilingRule, ...]
    standing_capabilities: tuple[StandingCapabilityPermission, ...] = ()
    approved_private_sinks: frozenset[Sink] = frozenset()
    enabled: bool = True
    revision: int = 1

    def __post_init__(self) -> None:
        if not self.display_name:
            raise ValueError("permission envelope display name must not be empty")
        if not self.authority_ceiling:
            raise ValueError("permission envelope requires an authority ceiling")
        if self.revision < 1:
            raise ValueError("permission envelope revision must be positive")


@dataclass(frozen=True, slots=True)
class CapabilityPermissionAssessment:
    outcome: DecisionOutcome
    reason: PermissionReason
    consequence: PermissionConsequence
    can_persist: bool
    permission_id: PermissionId | None = None


@dataclass(frozen=True, slots=True)
class FlowPermissionAssessment:
    outcome: DecisionOutcome
    reason: PermissionReason
    consequence: PermissionConsequence
    can_persist: bool
    decision: FlowDecision


@dataclass(frozen=True, slots=True)
class CapabilityMenuEntry:
    permission_id: PermissionId
    operations: tuple[Operation, ...]
    scope: str
    consequence: PermissionConsequence


@dataclass(frozen=True, slots=True)
class FlowMenuEntry:
    sink: Sink
    consequence: PermissionConsequence


@dataclass(frozen=True, slots=True)
class PermissionSnapshot:
    skill_id: SkillId
    display_name: str
    enabled: bool
    revision: int
    capabilities: tuple[CapabilityMenuEntry, ...]
    approved_private_sinks: tuple[FlowMenuEntry, ...]
    authority_ceiling: tuple[CapabilityCeilingRule, ...]

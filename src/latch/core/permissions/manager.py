"""Trusted control plane for standing and task-only permissions."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from threading import RLock

from latch.core.capabilities import (
    CapabilityRequest,
    CapabilityResource,
    CapabilitySelector,
    ConstraintSet,
    FilesystemResource,
    FilesystemResourceSelector,
    Grant,
    ServiceResource,
    ServiceResourceSelector,
)
from latch.core.evidence import EvidenceKind, EvidenceLedger
from latch.core.ids import (
    GrantId,
    PermissionId,
    SkillId,
    TaskId,
    new_permission_id,
)
from latch.core.information_flow import FlowPolicy, FlowRequest, Sink
from latch.core.permissions.consequences import (
    capability_consequence,
    flow_consequence,
    resource_scope_text,
    selector_scope_text,
    sink_consequence,
    standing_permission_consequence,
)
from latch.core.permissions.models import (
    CapabilityMenuEntry,
    CapabilityPermissionAssessment,
    FlowMenuEntry,
    FlowPermissionAssessment,
    PermissionConsequence,
    PermissionEnvelope,
    PermissionReason,
    PermissionSnapshot,
    StandingCapabilityPermission,
)
from latch.core.policy import CapabilityBroker
from latch.core.types import DecisionOutcome, Operation, RiskLevel


class PermissionProhibited(RuntimeError):
    """Requested authority is outside the user-owned envelope ceiling."""


class PermissionApprovalRequired(RuntimeError):
    """Requested authority is possible but requires explicit user approval."""


class PermissionManager:
    """Owns the Android-style permission state for skills.

    Mutation methods on this object are trusted UI/control-plane operations.
    They must never be exposed to the reasoning model as ordinary tools.
    """

    def __init__(
        self,
        *,
        broker: CapabilityBroker,
        envelopes: tuple[PermissionEnvelope, ...] = (),
        evidence: EvidenceLedger | None = None,
    ) -> None:
        self._broker = broker
        self._envelopes: dict[SkillId, PermissionEnvelope] = {
            envelope.skill_id: envelope for envelope in envelopes
        }
        self._task_flow_sinks: dict[tuple[TaskId, SkillId], set[Sink]] = {}
        self._task_grants: dict[tuple[TaskId, SkillId, PermissionId], GrantId] = {}
        self._evidence = evidence
        self._lock = RLock()

    def register(self, envelope: PermissionEnvelope) -> None:
        with self._lock:
            if envelope.skill_id in self._envelopes:
                raise ValueError(f"skill already registered: {envelope.skill_id}")
            self._envelopes[envelope.skill_id] = envelope

    def envelope(self, skill_id: SkillId) -> PermissionEnvelope:
        with self._lock:
            try:
                return self._envelopes[skill_id]
            except KeyError as exc:
                raise KeyError(f"unknown skill: {skill_id}") from exc

    def set_enabled(self, skill_id: SkillId, enabled: bool) -> PermissionEnvelope:
        with self._lock:
            envelope = self._require(skill_id)
            updated = replace(
                envelope,
                enabled=enabled,
                revision=envelope.revision + 1,
            )
            self._envelopes[skill_id] = updated
            if not enabled:
                self._revoke_cached_skill_grants(skill_id)
                for key in tuple(self._task_flow_sinks):
                    if key[1] == skill_id:
                        del self._task_flow_sinks[key]
            return updated

    def assess_capability(
        self,
        skill_id: SkillId,
        request: CapabilityRequest,
    ) -> CapabilityPermissionAssessment:
        with self._lock:
            envelope = self._require(skill_id)

            if not envelope.enabled:
                return CapabilityPermissionAssessment(
                    outcome=DecisionOutcome.DENY,
                    reason=PermissionReason.SKILL_DISABLED,
                    consequence=self._disabled_consequence(envelope),
                    can_persist=False,
                )

            if not self._within_ceiling(envelope, request):
                return CapabilityPermissionAssessment(
                    outcome=DecisionOutcome.DENY,
                    reason=PermissionReason.OUTSIDE_AUTHORITY_CEILING,
                    consequence=PermissionConsequence(
                        title="Outside this skill's authority ceiling",
                        detail=(
                            f"{envelope.display_name} is not permitted to request "
                            f"{request.operation.value} for {resource_scope_text(request.resource)}. "
                            "This cannot be approved from an incidental action prompt."
                        ),
                        risk=RiskLevel.PROHIBITED,
                    ),
                    can_persist=False,
                )

            for permission in envelope.standing_capabilities:
                if permission.allows(request):
                    return CapabilityPermissionAssessment(
                        outcome=DecisionOutcome.ALLOW,
                        reason=PermissionReason.STANDING_PERMISSION,
                        consequence=standing_permission_consequence(permission),
                        can_persist=False,
                        permission_id=permission.permission_id,
                    )

            return CapabilityPermissionAssessment(
                outcome=DecisionOutcome.NEEDS_APPROVAL,
                reason=PermissionReason.MISSING_STANDING_PERMISSION,
                consequence=capability_consequence(request),
                can_persist=True,
            )

    def issue_standing_grant(
        self,
        skill_id: SkillId,
        request: CapabilityRequest,
        *,
        at: datetime | None = None,
    ) -> Grant:
        """Mint/reuse a task grant only when standing policy already covers it."""

        assessment = self.assess_capability(skill_id, request)
        if assessment.outcome is DecisionOutcome.DENY:
            raise PermissionProhibited(assessment.reason.value)
        if assessment.outcome is DecisionOutcome.NEEDS_APPROVAL:
            raise PermissionApprovalRequired(assessment.reason.value)
        if assessment.permission_id is None:
            raise RuntimeError("standing permission assessment omitted permission_id")

        with self._lock:
            envelope = self._require(skill_id)
            permission = self._permission(envelope, assessment.permission_id)
            key = (request.task_id, skill_id, permission.permission_id)
            cached_id = self._task_grants.get(key)
            if cached_id is not None:
                cached = self._broker.get_grant(cached_id)
                if cached is not None and cached.covers(request, self._time(at)):
                    return cached

            grant = self._broker.approve(
                request,
                approved_by=f"standing-permission:{permission.permission_id}",
                selector=permission.selector,
                constraints=permission.constraints,
                at=at,
            )
            self._task_grants[key] = grant.grant_id
            self._record(
                request.task_id,
                EvidenceKind.GRANT_ISSUED,
                "Standing permission issued a task grant",
                {
                    "skill_id": str(skill_id),
                    "permission_id": str(permission.permission_id),
                    "operation": request.operation.value,
                    "grant_id": str(grant.grant_id),
                },
                at,
            )
            return grant

    def approve_capability_once(
        self,
        skill_id: SkillId,
        request: CapabilityRequest,
        *,
        approved_by: str,
        at: datetime | None = None,
        ttl: timedelta = timedelta(minutes=15),
    ) -> Grant:
        """Approve one concrete action without changing standing policy."""

        with self._lock:
            envelope = self._require(skill_id)
            if not envelope.enabled:
                raise PermissionProhibited(PermissionReason.SKILL_DISABLED.value)
            if not self._within_ceiling(envelope, request):
                raise PermissionProhibited(PermissionReason.OUTSIDE_AUTHORITY_CEILING.value)

        constraints = ConstraintSet(
            max_operations=1,
            max_bytes=request.bytes_requested if request.bytes_requested > 0 else None,
            overwrite=False if not request.overwrite else None,
        )
        grant = self._broker.approve(
            request,
            approved_by=approved_by,
            constraints=constraints,
            ttl=ttl,
            at=at,
        )
        self._record(
            request.task_id,
            EvidenceKind.APPROVAL,
            "Capability approved for this task only",
            {
                "skill_id": str(skill_id),
                "operation": request.operation.value,
                "resource": resource_scope_text(request.resource),
                "persistence": "task_only",
            },
            at,
        )
        self._record(
            request.task_id,
            EvidenceKind.GRANT_ISSUED,
            "Task-only approval issued a grant",
            {
                "skill_id": str(skill_id),
                "grant_id": str(grant.grant_id),
                "operation": request.operation.value,
            },
            at,
        )
        return grant

    def approve_capability_persistent(
        self,
        skill_id: SkillId,
        request: CapabilityRequest,
        *,
        approved_by: str,
        selector: CapabilitySelector | None = None,
        constraints: ConstraintSet | None = None,
        at: datetime | None = None,
    ) -> StandingCapabilityPermission:
        """Add standing permission after an explicit trusted-user action."""

        chosen_selector = selector or self._exact_selector(request.resource)
        chosen_constraints = constraints or ConstraintSet(
            overwrite=False if not request.overwrite else None
        )
        permission = StandingCapabilityPermission(
            permission_id=new_permission_id(),
            operations=frozenset({request.operation}),
            selector=chosen_selector,
            constraints=chosen_constraints,
            approved_by=approved_by,
        )

        with self._lock:
            envelope = self._require(skill_id)
            if not envelope.enabled:
                raise PermissionProhibited(PermissionReason.SKILL_DISABLED.value)
            if not self._permission_within_ceiling(envelope, permission):
                raise PermissionProhibited(PermissionReason.OUTSIDE_AUTHORITY_CEILING.value)

            updated = replace(
                envelope,
                standing_capabilities=(*envelope.standing_capabilities, permission),
                revision=envelope.revision + 1,
            )
            self._envelopes[skill_id] = updated

        self._record(
            request.task_id,
            EvidenceKind.APPROVAL,
            "Persistent capability permission added",
            {
                "skill_id": str(skill_id),
                "permission_id": str(permission.permission_id),
                "operation": request.operation.value,
                "scope": self._scope_text(chosen_selector),
                "persistence": "standing",
            },
            at,
        )
        return permission

    def edit_capability_permission(
        self,
        skill_id: SkillId,
        permission_id: PermissionId,
        *,
        operations: frozenset[Operation] | None = None,
        selector: CapabilitySelector | None = None,
        constraints: ConstraintSet | None = None,
        approved_by: str,
        task_id: TaskId | None = None,
        at: datetime | None = None,
    ) -> StandingCapabilityPermission:
        with self._lock:
            envelope = self._require(skill_id)
            current = self._permission(envelope, permission_id)
            updated_permission = replace(
                current,
                operations=operations or current.operations,
                selector=selector or current.selector,
                constraints=constraints or current.constraints,
                approved_by=approved_by,
            )
            if not self._permission_within_ceiling(envelope, updated_permission):
                raise PermissionProhibited(PermissionReason.OUTSIDE_AUTHORITY_CEILING.value)

            permissions = tuple(
                updated_permission if item.permission_id == permission_id else item
                for item in envelope.standing_capabilities
            )
            self._envelopes[skill_id] = replace(
                envelope,
                standing_capabilities=permissions,
                revision=envelope.revision + 1,
            )
            self._revoke_cached_permission_grants(skill_id, permission_id)

        if task_id is not None:
            self._record(
                task_id,
                EvidenceKind.APPROVAL,
                "Persistent capability permission edited",
                {
                    "skill_id": str(skill_id),
                    "permission_id": str(permission_id),
                    "persistence": "standing",
                },
                at,
            )
        return updated_permission

    def revoke_capability_permission(
        self,
        skill_id: SkillId,
        permission_id: PermissionId,
        *,
        task_id: TaskId | None = None,
        at: datetime | None = None,
    ) -> None:
        with self._lock:
            envelope = self._require(skill_id)
            self._permission(envelope, permission_id)
            remaining = tuple(
                item
                for item in envelope.standing_capabilities
                if item.permission_id != permission_id
            )
            self._envelopes[skill_id] = replace(
                envelope,
                standing_capabilities=remaining,
                revision=envelope.revision + 1,
            )
            self._revoke_cached_permission_grants(skill_id, permission_id)

        if task_id is not None:
            self._record(
                task_id,
                EvidenceKind.GRANT_REVOKED,
                "Persistent capability permission revoked",
                {
                    "skill_id": str(skill_id),
                    "permission_id": str(permission_id),
                },
                at,
            )

    def assess_flow(
        self,
        skill_id: SkillId,
        task_id: TaskId,
        request: FlowRequest,
    ) -> FlowPermissionAssessment:
        with self._lock:
            envelope = self._require(skill_id)
            if not envelope.enabled:
                decision = FlowPolicy().evaluate(request)
                return FlowPermissionAssessment(
                    outcome=DecisionOutcome.DENY,
                    reason=PermissionReason.SKILL_DISABLED,
                    consequence=self._disabled_consequence(envelope),
                    can_persist=False,
                    decision=replace(
                        decision,
                        outcome=DecisionOutcome.DENY,
                        overridable=False,
                    ),
                )

            task_sinks = self._task_flow_sinks.get((task_id, skill_id), set())
            approved = envelope.approved_private_sinks | frozenset(task_sinks)
            decision = FlowPolicy(approved).evaluate(request)

            if decision.outcome is DecisionOutcome.DENY:
                return FlowPermissionAssessment(
                    outcome=decision.outcome,
                    reason=PermissionReason.FLOW_PROHIBITED,
                    consequence=flow_consequence(request),
                    can_persist=False,
                    decision=decision,
                )
            if decision.outcome is DecisionOutcome.NEEDS_APPROVAL:
                return FlowPermissionAssessment(
                    outcome=decision.outcome,
                    reason=PermissionReason.FLOW_REQUIRES_APPROVAL,
                    consequence=flow_consequence(request),
                    can_persist=decision.overridable,
                    decision=decision,
                )

            if request.sink in task_sinks:
                reason = PermissionReason.TASK_FLOW_PERMISSION
            elif request.sink in envelope.approved_private_sinks:
                reason = PermissionReason.STANDING_FLOW_PERMISSION
            else:
                reason = PermissionReason.FLOW_POLICY_ALLOW

            return FlowPermissionAssessment(
                outcome=decision.outcome,
                reason=reason,
                consequence=flow_consequence(request),
                can_persist=False,
                decision=decision,
            )

    def approve_flow_once(
        self,
        skill_id: SkillId,
        task_id: TaskId,
        request: FlowRequest,
        *,
        at: datetime | None = None,
    ) -> FlowPermissionAssessment:
        assessment = self.assess_flow(skill_id, task_id, request)
        if assessment.outcome is DecisionOutcome.DENY or not assessment.decision.overridable:
            raise PermissionProhibited(assessment.decision.reason.value)
        if assessment.outcome is DecisionOutcome.ALLOW:
            return assessment

        with self._lock:
            self._task_flow_sinks.setdefault((task_id, skill_id), set()).add(request.sink)

        self._record(
            task_id,
            EvidenceKind.APPROVAL,
            "Private-data flow approved for this task only",
            {
                "skill_id": str(skill_id),
                "sink_kind": request.sink.kind.value,
                "sink": request.sink.target,
                "persistence": "task_only",
            },
            at,
        )
        return self.assess_flow(skill_id, task_id, request)

    def approve_flow_persistent(
        self,
        skill_id: SkillId,
        task_id: TaskId,
        request: FlowRequest,
        *,
        at: datetime | None = None,
    ) -> FlowPermissionAssessment:
        assessment = self.assess_flow(skill_id, task_id, request)
        if assessment.outcome is DecisionOutcome.DENY or not assessment.decision.overridable:
            raise PermissionProhibited(assessment.decision.reason.value)
        if assessment.outcome is DecisionOutcome.ALLOW:
            return assessment

        with self._lock:
            envelope = self._require(skill_id)
            updated = replace(
                envelope,
                approved_private_sinks=envelope.approved_private_sinks | {request.sink},
                revision=envelope.revision + 1,
            )
            self._envelopes[skill_id] = updated

        self._record(
            task_id,
            EvidenceKind.APPROVAL,
            "Private-data flow approved persistently",
            {
                "skill_id": str(skill_id),
                "sink_kind": request.sink.kind.value,
                "sink": request.sink.target,
                "persistence": "standing",
            },
            at,
        )
        return self.assess_flow(skill_id, task_id, request)

    def revoke_flow_sink(
        self,
        skill_id: SkillId,
        sink: Sink,
        *,
        task_id: TaskId | None = None,
        at: datetime | None = None,
    ) -> None:
        with self._lock:
            envelope = self._require(skill_id)
            if sink not in envelope.approved_private_sinks:
                raise KeyError(f"sink is not persistently approved: {sink}")
            self._envelopes[skill_id] = replace(
                envelope,
                approved_private_sinks=envelope.approved_private_sinks - {sink},
                revision=envelope.revision + 1,
            )

        if task_id is not None:
            self._record(
                task_id,
                EvidenceKind.GRANT_REVOKED,
                "Persistent private-data sink approval revoked",
                {
                    "skill_id": str(skill_id),
                    "sink_kind": sink.kind.value,
                    "sink": sink.target,
                },
                at,
            )

    def clear_task(self, task_id: TaskId) -> None:
        """Revoke cached task grants and task-only sink approvals."""

        with self._lock:
            for key, grant_id in tuple(self._task_grants.items()):
                if key[0] == task_id:
                    self._broker.revoke_grant(grant_id)
                    del self._task_grants[key]
            for key in tuple(self._task_flow_sinks):
                if key[0] == task_id:
                    del self._task_flow_sinks[key]

    def snapshot(self, skill_id: SkillId) -> PermissionSnapshot:
        with self._lock:
            envelope = self._require(skill_id)
            capability_entries = tuple(
                CapabilityMenuEntry(
                    permission_id=permission.permission_id,
                    operations=tuple(sorted(permission.operations, key=lambda item: item.value)),
                    scope=self._scope_text(permission.selector),
                    consequence=standing_permission_consequence(permission),
                )
                for permission in envelope.standing_capabilities
            )
            sink_entries = tuple(
                FlowMenuEntry(
                    sink=sink,
                    consequence=sink_consequence(sink),
                )
                for sink in sorted(
                    envelope.approved_private_sinks,
                    key=lambda item: (item.kind.value, item.target),
                )
            )
            return PermissionSnapshot(
                skill_id=envelope.skill_id,
                display_name=envelope.display_name,
                enabled=envelope.enabled,
                revision=envelope.revision,
                capabilities=capability_entries,
                approved_private_sinks=sink_entries,
                authority_ceiling=envelope.authority_ceiling,
            )

    def _within_ceiling(
        self,
        envelope: PermissionEnvelope,
        request: CapabilityRequest,
    ) -> bool:
        return any(rule.allows(request) for rule in envelope.authority_ceiling)

    def _permission_within_ceiling(
        self,
        envelope: PermissionEnvelope,
        permission: StandingCapabilityPermission,
    ) -> bool:
        for operation in permission.operations:
            if not any(
                operation in ceiling.operations
                and self._selector_within(permission.selector, ceiling.selector)
                and self._constraints_within(permission.constraints, ceiling.constraints)
                for ceiling in envelope.authority_ceiling
            ):
                return False
        return True

    @staticmethod
    def _selector_within(
        proposed: CapabilitySelector,
        ceiling: CapabilitySelector,
    ) -> bool:
        if isinstance(proposed, ServiceResourceSelector):
            return isinstance(ceiling, ServiceResourceSelector) and proposed == ceiling
        if not isinstance(ceiling, FilesystemResourceSelector):
            return False

        if proposed.platform is not ceiling.platform:
            return False
        if proposed == ceiling:
            return True

        root_resource = FilesystemResource(proposed.root, proposed.platform)
        if not ceiling.contains(root_resource):
            return False

        if not proposed.recursive:
            return True
        if not ceiling.recursive:
            return False

        # Recursive subscopes are trivially provable only when the wider ceiling
        # has no exclusions. With exclusions, require exact selector equality.
        return not ceiling.exclude_globs

    @staticmethod
    def _constraints_within(
        proposed: ConstraintSet,
        ceiling: ConstraintSet,
    ) -> bool:
        if (
            ceiling.max_operations is not None
            and (
                proposed.max_operations is None
                or proposed.max_operations > ceiling.max_operations
            )
        ):
            return False
        if (
            ceiling.max_bytes is not None
            and (
                proposed.max_bytes is None
                or proposed.max_bytes > ceiling.max_bytes
            )
        ):
            return False
        return not (ceiling.overwrite is False and proposed.overwrite is not False)

    @staticmethod
    def _disabled_consequence(envelope: PermissionEnvelope) -> PermissionConsequence:
        return PermissionConsequence(
            title="Skill is disabled",
            detail=(
                f"{envelope.display_name} cannot exercise or request authority while disabled."
            ),
            risk=RiskLevel.PROHIBITED,
        )

    @staticmethod
    def _scope_text(selector: CapabilitySelector) -> str:
        return selector_scope_text(selector)

    @staticmethod
    def _exact_selector(resource: CapabilityResource) -> CapabilitySelector:
        if isinstance(resource, FilesystemResource):
            return FilesystemResourceSelector.exact(resource)
        return ServiceResourceSelector.exact(resource)

    def _permission(
        self,
        envelope: PermissionEnvelope,
        permission_id: PermissionId,
    ) -> StandingCapabilityPermission:
        for permission in envelope.standing_capabilities:
            if permission.permission_id == permission_id:
                return permission
        raise KeyError(f"unknown permission: {permission_id}")

    def _require(self, skill_id: SkillId) -> PermissionEnvelope:
        try:
            return self._envelopes[skill_id]
        except KeyError as exc:
            raise KeyError(f"unknown skill: {skill_id}") from exc

    def _revoke_cached_permission_grants(
        self,
        skill_id: SkillId,
        permission_id: PermissionId,
    ) -> None:
        for key, grant_id in tuple(self._task_grants.items()):
            if key[1] == skill_id and key[2] == permission_id:
                self._broker.revoke_grant(grant_id)
                del self._task_grants[key]

    def _revoke_cached_skill_grants(self, skill_id: SkillId) -> None:
        for key, grant_id in tuple(self._task_grants.items()):
            if key[1] == skill_id:
                self._broker.revoke_grant(grant_id)
                del self._task_grants[key]

    def _record(
        self,
        task_id: TaskId,
        kind: EvidenceKind,
        summary: str,
        details: dict[str, str],
        at: datetime | None,
    ) -> None:
        if self._evidence is None:
            return
        self._evidence.append(
            task_id=task_id,
            kind=kind,
            summary=summary,
            details=details,
            at=at,
        )

    @staticmethod
    def _time(value: datetime | None) -> datetime:
        if value is None:
            from datetime import UTC

            return datetime.now(UTC)
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("permission times must be timezone-aware")
        return value

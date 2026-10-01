"""Deterministic capability broker.

The broker has no model-facing API and performs no probabilistic decisions.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock

from latch.core.capabilities.filesystem import FilesystemResourceSelector
from latch.core.capabilities.models import (
    CapabilityRequest,
    ConstraintSet,
    Grant,
    PolicyDecision,
    PolicyRule,
)
from latch.core.ids import GrantId, RuleId, TaskId, new_grant_id
from latch.core.types import DecisionOutcome, PolicyEffect


@dataclass(slots=True)
class _GrantUsage:
    operations: int = 0
    bytes: int = 0


class CapabilityBroker:
    """In-memory V0 policy engine and task-scoped grant issuer.

    Persistent policy rules and ephemeral grants are deliberately separate.
    A later persistence layer may store policy rules, but runtime grants should
    remain short-lived and task-bound.
    """

    def __init__(
        self,
        rules: Iterable[PolicyRule] = (),
        *,
        default_grant_ttl: timedelta = timedelta(minutes=15),
    ) -> None:
        if default_grant_ttl <= timedelta(0):
            raise ValueError("default_grant_ttl must be positive")
        self._rules: dict[RuleId, PolicyRule] = {rule.rule_id: rule for rule in rules}
        self._grants: dict[GrantId, Grant] = {}
        self._usage: dict[GrantId, _GrantUsage] = {}
        self._rule_grants: dict[tuple[TaskId, RuleId], GrantId] = {}
        self._default_grant_ttl = default_grant_ttl
        self._lock = RLock()

    @staticmethod
    def _now(value: datetime | None) -> datetime:
        current = value or datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("broker times must be timezone-aware")
        return current

    def add_rule(self, rule: PolicyRule) -> None:
        with self._lock:
            self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: RuleId) -> None:
        with self._lock:
            self._rules.pop(rule_id, None)

    def revoke_grant(self, grant_id: GrantId) -> None:
        with self._lock:
            self._grants.pop(grant_id, None)
            self._usage.pop(grant_id, None)
            for key, value in tuple(self._rule_grants.items()):
                if value == grant_id:
                    del self._rule_grants[key]

    def get_grant(self, grant_id: GrantId) -> Grant | None:
        with self._lock:
            return self._grants.get(grant_id)

    def request(self, request: CapabilityRequest, *, at: datetime | None = None) -> PolicyDecision:
        now = self._now(at)
        with self._lock:
            deny_rule = self._first_matching_deny(request)
            if deny_rule is not None:
                return PolicyDecision(
                    request_id=request.request_id,
                    outcome=DecisionOutcome.DENY,
                    reason="matched_deny_rule",
                    rule_id=deny_rule.rule_id,
                )

            existing = self._matching_grant(request, now)
            if existing is not None:
                if not self._has_capacity(existing, request):
                    return PolicyDecision(
                        request_id=request.request_id,
                        outcome=DecisionOutcome.NEEDS_APPROVAL,
                        reason="grant_constraints_exceeded",
                        grant_id=existing.grant_id,
                        rule_id=existing.rule_id,
                    )
                return PolicyDecision(
                    request_id=request.request_id,
                    outcome=DecisionOutcome.ALLOW,
                    reason="matched_grant",
                    grant_id=existing.grant_id,
                    rule_id=existing.rule_id,
                )

            allow_rule, scope_only_rule = self._matching_allow_rule(request)
            if allow_rule is not None:
                grant = self._grant_for_rule(request, allow_rule, now)
                if not self._has_capacity(grant, request):
                    return PolicyDecision(
                        request_id=request.request_id,
                        outcome=DecisionOutcome.NEEDS_APPROVAL,
                        reason="grant_constraints_exceeded",
                        grant_id=grant.grant_id,
                        rule_id=allow_rule.rule_id,
                    )
                return PolicyDecision(
                    request_id=request.request_id,
                    outcome=DecisionOutcome.ALLOW,
                    reason="matched_allow_rule",
                    grant_id=grant.grant_id,
                    rule_id=allow_rule.rule_id,
                )

            if scope_only_rule is not None:
                return PolicyDecision(
                    request_id=request.request_id,
                    outcome=DecisionOutcome.NEEDS_APPROVAL,
                    reason="policy_constraints_exceeded",
                    rule_id=scope_only_rule.rule_id,
                )

            return PolicyDecision(
                request_id=request.request_id,
                outcome=DecisionOutcome.NEEDS_APPROVAL,
                reason="missing_authority",
            )

    def approve(
        self,
        request: CapabilityRequest,
        *,
        approved_by: str,
        selector: FilesystemResourceSelector | None = None,
        constraints: ConstraintSet | None = None,
        ttl: timedelta | None = None,
        at: datetime | None = None,
    ) -> Grant:
        """Issue an explicit user/system-approved task grant.

        This method is intentionally separate from request(). A model-facing
        adapter must never expose it as an ordinary tool.
        """

        now = self._now(at)
        chosen_selector = selector or FilesystemResourceSelector.exact(request.resource)
        chosen_constraints = constraints or ConstraintSet()
        chosen_ttl = ttl or self._default_grant_ttl

        if chosen_ttl <= timedelta(0):
            raise ValueError("grant ttl must be positive")
        if not chosen_selector.contains(request.resource):
            raise ValueError("approval selector must contain the requested resource")
        if not chosen_constraints.allows_request(request):
            raise ValueError("approval constraints do not cover the requested action")

        grant = Grant(
            grant_id=new_grant_id(),
            task_id=request.task_id,
            operations=frozenset({request.operation}),
            selector=chosen_selector,
            constraints=chosen_constraints,
            issued_by=approved_by,
            issued_at=now,
            expires_at=now + chosen_ttl,
        )
        with self._lock:
            self._grants[grant.grant_id] = grant
            self._usage[grant.grant_id] = _GrantUsage()
        return grant

    def consume(
        self,
        grant_id: GrantId,
        *,
        operations: int = 1,
        bytes_used: int = 0,
        at: datetime | None = None,
    ) -> bool:
        """Atomically reserve usage against an existing grant.

        Returns False without mutation if the grant is missing, expired, or
        would exceed its cumulative operation/byte limits.
        """

        if operations < 0 or bytes_used < 0:
            raise ValueError("usage increments must be non-negative")
        now = self._now(at)

        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None or not grant.is_active(now):
                return False

            usage = self._usage.setdefault(grant_id, _GrantUsage())
            if (
                grant.constraints.max_operations is not None
                and usage.operations + operations > grant.constraints.max_operations
            ):
                return False
            if (
                grant.constraints.max_bytes is not None
                and usage.bytes + bytes_used > grant.constraints.max_bytes
            ):
                return False

            usage.operations += operations
            usage.bytes += bytes_used
            return True

    def _first_matching_deny(self, request: CapabilityRequest) -> PolicyRule | None:
        for rule in self._rules.values():
            if rule.effect is PolicyEffect.DENY and rule.matches_scope(request):
                return rule
        return None

    def _matching_allow_rule(
        self, request: CapabilityRequest
    ) -> tuple[PolicyRule | None, PolicyRule | None]:
        scope_only: PolicyRule | None = None
        for rule in self._rules.values():
            if rule.effect is not PolicyEffect.ALLOW or not rule.matches_scope(request):
                continue
            if rule.allows(request):
                return rule, scope_only
            scope_only = scope_only or rule
        return None, scope_only

    def _matching_grant(self, request: CapabilityRequest, now: datetime) -> Grant | None:
        for grant in self._grants.values():
            if grant.covers(request, now):
                return grant
        return None

    def _has_capacity(self, grant: Grant, request: CapabilityRequest) -> bool:
        usage = self._usage.setdefault(grant.grant_id, _GrantUsage())
        if (
            grant.constraints.max_operations is not None
            and usage.operations >= grant.constraints.max_operations
        ):
            return False
        return not (
            grant.constraints.max_bytes is not None
            and usage.bytes + request.bytes_requested > grant.constraints.max_bytes
        )

    def _grant_for_rule(
        self, request: CapabilityRequest, rule: PolicyRule, now: datetime
    ) -> Grant:
        key = (request.task_id, rule.rule_id)
        existing_id = self._rule_grants.get(key)
        if existing_id is not None:
            existing = self._grants.get(existing_id)
            if existing is not None and existing.is_active(now):
                return existing

        grant = Grant(
            grant_id=new_grant_id(),
            task_id=request.task_id,
            operations=rule.operations,
            selector=rule.selector,
            constraints=rule.constraints,
            issued_by=f"policy:{rule.rule_id}",
            issued_at=now,
            expires_at=now + self._default_grant_ttl,
            rule_id=rule.rule_id,
        )
        self._grants[grant.grant_id] = grant
        self._usage[grant.grant_id] = _GrantUsage()
        self._rule_grants[key] = grant.grant_id
        return grant

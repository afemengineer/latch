from datetime import UTC, datetime, timedelta

from latch.core.capabilities import (
    CapabilityRequest,
    ConstraintSet,
    FilesystemResource,
    FilesystemResourceSelector,
    PolicyRule,
)
from latch.core.ids import TaskId, new_rule_id, new_task_id
from latch.core.policy import CapabilityBroker
from latch.core.types import DecisionOutcome, Operation, PathPlatform, PolicyEffect

NOW = datetime(2026, 10, 1, 19, 0, tzinfo=UTC)


def request_for(
    path: str,
    *,
    task_id: TaskId | None = None,
    operation: Operation = Operation.FILESYSTEM_READ,
    bytes_requested: int = 0,
    overwrite: bool = False,
) -> CapabilityRequest:
    return CapabilityRequest(
        task_id=task_id or new_task_id(),
        operation=operation,
        resource=FilesystemResource(path, PathPlatform.POSIX),
        bytes_requested=bytes_requested,
        overwrite=overwrite,
    )


def test_missing_authority_requires_approval() -> None:
    broker = CapabilityBroker()
    decision = broker.request(request_for("/home/demo/invoice.pdf"), at=NOW)

    assert decision.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert decision.reason == "missing_authority"


def test_allow_rule_mints_task_scoped_grant() -> None:
    task = new_task_id()
    rule = PolicyRule(
        rule_id=new_rule_id(),
        effect=PolicyEffect.ALLOW,
        operations=frozenset({Operation.FILESYSTEM_READ}),
        selector=FilesystemResourceSelector("/home/demo/Downloads", PathPlatform.POSIX),
    )
    broker = CapabilityBroker([rule])

    first = broker.request(request_for("/home/demo/Downloads/a.pdf", task_id=task), at=NOW)
    second = broker.request(request_for("/home/demo/Downloads/b.pdf", task_id=task), at=NOW)

    assert first.outcome is DecisionOutcome.ALLOW
    assert first.reason == "matched_allow_rule"
    assert first.grant_id is not None
    assert second.outcome is DecisionOutcome.ALLOW
    assert second.reason == "matched_grant"
    assert second.grant_id == first.grant_id


def test_grant_cannot_cross_task_boundary() -> None:
    broker = CapabilityBroker()
    first_task = new_task_id()
    second_task = new_task_id()
    approved_request = request_for("/home/demo/invoice.pdf", task_id=first_task)
    broker.approve(approved_request, approved_by="user", at=NOW)

    decision = broker.request(
        request_for("/home/demo/invoice.pdf", task_id=second_task),
        at=NOW,
    )

    assert decision.outcome is DecisionOutcome.NEEDS_APPROVAL


def test_deny_rule_overrides_broad_allow_rule() -> None:
    allow = PolicyRule(
        rule_id=new_rule_id(),
        effect=PolicyEffect.ALLOW,
        operations=frozenset({Operation.FILESYSTEM_READ}),
        selector=FilesystemResourceSelector("/home/demo", PathPlatform.POSIX),
    )
    deny = PolicyRule(
        rule_id=new_rule_id(),
        effect=PolicyEffect.DENY,
        operations=frozenset({Operation.FILESYSTEM_READ}),
        selector=FilesystemResourceSelector("/home/demo/.ssh", PathPlatform.POSIX),
    )
    broker = CapabilityBroker([allow, deny])

    decision = broker.request(request_for("/home/demo/.ssh/id_rsa"), at=NOW)

    assert decision.outcome is DecisionOutcome.DENY
    assert decision.reason == "matched_deny_rule"
    assert decision.rule_id == deny.rule_id


def test_policy_constraints_trigger_escalation_instead_of_silent_allow() -> None:
    rule = PolicyRule(
        rule_id=new_rule_id(),
        effect=PolicyEffect.ALLOW,
        operations=frozenset({Operation.FILESYSTEM_READ}),
        selector=FilesystemResourceSelector("/home/demo/Downloads", PathPlatform.POSIX),
        constraints=ConstraintSet(max_bytes=1024),
    )
    broker = CapabilityBroker([rule])

    decision = broker.request(
        request_for("/home/demo/Downloads/large.pdf", bytes_requested=2048),
        at=NOW,
    )

    assert decision.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert decision.reason == "policy_constraints_exceeded"


def test_operation_limit_is_enforced_atomically() -> None:
    request = request_for("/home/demo/invoice.pdf")
    broker = CapabilityBroker()
    grant = broker.approve(
        request,
        approved_by="user",
        constraints=ConstraintSet(max_operations=1),
        at=NOW,
    )

    assert broker.consume(grant.grant_id, at=NOW)
    assert not broker.consume(grant.grant_id, at=NOW)

    decision = broker.request(request, at=NOW)
    assert decision.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert decision.reason == "grant_constraints_exceeded"


def test_byte_limit_is_cumulative() -> None:
    request = request_for("/home/demo/invoice.pdf", bytes_requested=6)
    broker = CapabilityBroker()
    grant = broker.approve(
        request,
        approved_by="user",
        constraints=ConstraintSet(max_bytes=10),
        at=NOW,
    )

    assert broker.consume(grant.grant_id, bytes_used=6, at=NOW)
    assert not broker.consume(grant.grant_id, bytes_used=5, at=NOW)


def test_expired_grant_no_longer_authorizes() -> None:
    request = request_for("/home/demo/invoice.pdf")
    broker = CapabilityBroker()
    broker.approve(
        request,
        approved_by="user",
        ttl=timedelta(seconds=1),
        at=NOW,
    )

    decision = broker.request(request, at=NOW + timedelta(seconds=2))

    assert decision.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert decision.reason == "missing_authority"


def test_overwrite_constraint_is_enforced() -> None:
    rule = PolicyRule(
        rule_id=new_rule_id(),
        effect=PolicyEffect.ALLOW,
        operations=frozenset({Operation.FILESYSTEM_MOVE}),
        selector=FilesystemResourceSelector("/home/demo/Receipts", PathPlatform.POSIX),
        constraints=ConstraintSet(overwrite=False),
    )
    broker = CapabilityBroker([rule])

    decision = broker.request(
        request_for(
            "/home/demo/Receipts/invoice.pdf",
            operation=Operation.FILESYSTEM_MOVE,
            overwrite=True,
        ),
        at=NOW,
    )

    assert decision.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert decision.reason == "policy_constraints_exceeded"


def test_allow_rule_does_not_remint_grant_to_bypass_operation_limit() -> None:
    task = new_task_id()
    rule = PolicyRule(
        rule_id=new_rule_id(),
        effect=PolicyEffect.ALLOW,
        operations=frozenset({Operation.FILESYSTEM_READ}),
        selector=FilesystemResourceSelector("/home/demo/Downloads", PathPlatform.POSIX),
        constraints=ConstraintSet(max_operations=1),
    )
    broker = CapabilityBroker([rule])
    request = request_for("/home/demo/Downloads/a.pdf", task_id=task)

    first = broker.request(request, at=NOW)
    assert first.outcome is DecisionOutcome.ALLOW
    assert first.grant_id is not None
    assert broker.consume(first.grant_id, at=NOW)

    second = broker.request(request, at=NOW)
    assert second.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert second.reason == "grant_constraints_exceeded"
    assert second.grant_id == first.grant_id

from datetime import UTC, datetime

import pytest

from latch.core.capabilities import (
    CapabilityRequest,
    ConstraintSet,
    FilesystemResource,
    FilesystemResourceSelector,
)
from latch.core.evidence import EvidenceLedger
from latch.core.ids import SkillId, new_task_id
from latch.core.information_flow import (
    DataRef,
    FlowRequest,
    Sink,
    SinkKind,
)
from latch.core.permissions import (
    CapabilityCeilingRule,
    PermissionEnvelope,
    PermissionManager,
    PermissionProhibited,
    PermissionReason,
)
from latch.core.policy import CapabilityBroker
from latch.core.types import (
    DataLabel,
    DecisionOutcome,
    Operation,
    PathPlatform,
)

NOW = datetime(2026, 10, 1, 22, 0, tzinfo=UTC)
SKILL = SkillId("organize-receipts")


def request(
    path: str,
    *,
    operation: Operation = Operation.FILESYSTEM_READ,
) -> CapabilityRequest:
    return CapabilityRequest(
        task_id=new_task_id(),
        operation=operation,
        resource=FilesystemResource(path, PathPlatform.POSIX),
    )


def manager() -> tuple[PermissionManager, CapabilityBroker, EvidenceLedger]:
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    envelope = PermissionEnvelope(
        skill_id=SKILL,
        display_name="Organize Receipts",
        authority_ceiling=(
            CapabilityCeilingRule(
                operations=frozenset(
                    {
                        Operation.FILESYSTEM_INSPECT,
                        Operation.FILESYSTEM_READ,
                        Operation.FILESYSTEM_MOVE,
                    }
                ),
                selector=FilesystemResourceSelector(
                    "/home/demo",
                    PathPlatform.POSIX,
                ),
                constraints=ConstraintSet(overwrite=False),
            ),
        ),
    )
    return (
        PermissionManager(
            broker=broker,
            envelopes=(envelope,),
            evidence=evidence,
        ),
        broker,
        evidence,
    )


def test_missing_standing_permission_requests_approval() -> None:
    permissions, _, _ = manager()
    assessment = permissions.assess_capability(
        SKILL,
        request("/home/demo/Downloads/invoice.pdf"),
    )

    assert assessment.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert assessment.reason is PermissionReason.MISSING_STANDING_PERMISSION
    assert assessment.can_persist
    assert "read" in assessment.consequence.title.lower()


def test_outside_ceiling_is_prohibited_not_approvable() -> None:
    permissions, _, _ = manager()
    assessment = permissions.assess_capability(
        SKILL,
        request("/home/other/secret.txt"),
    )

    assert assessment.outcome is DecisionOutcome.DENY
    assert assessment.reason is PermissionReason.OUTSIDE_AUTHORITY_CEILING
    assert not assessment.can_persist


def test_operation_outside_ceiling_is_prohibited() -> None:
    permissions, _, _ = manager()
    assessment = permissions.assess_capability(
        SKILL,
        request(
            "/home/demo/invoice.pdf",
            operation=Operation.FILESYSTEM_RENAME,
        ),
    )

    assert assessment.outcome is DecisionOutcome.DENY


def test_persistent_permission_removes_repeat_prompt() -> None:
    permissions, _, evidence = manager()
    current = request("/home/demo/Downloads/invoice.pdf")

    standing = permissions.approve_capability_persistent(
        SKILL,
        current,
        approved_by="user",
        selector=FilesystemResourceSelector(
            "/home/demo/Downloads",
            PathPlatform.POSIX,
        ),
        at=NOW,
    )

    second = CapabilityRequest(
        task_id=new_task_id(),
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource(
            "/home/demo/Downloads/other.pdf",
            PathPlatform.POSIX,
        ),
    )
    assessment = permissions.assess_capability(SKILL, second)

    assert assessment.outcome is DecisionOutcome.ALLOW
    assert assessment.reason is PermissionReason.STANDING_PERMISSION
    assert assessment.permission_id == standing.permission_id
    assert evidence.verify().valid


def test_recursive_persistent_scope_cannot_exceed_ceiling() -> None:
    permissions, _, _ = manager()
    current = request("/home/demo/Downloads/invoice.pdf")

    with pytest.raises(PermissionProhibited):
        permissions.approve_capability_persistent(
            SKILL,
            current,
            approved_by="user",
            selector=FilesystemResourceSelector(
                "/home",
                PathPlatform.POSIX,
            ),
            at=NOW,
        )


def test_ceiling_exclusions_make_recursive_subscope_conservative() -> None:
    broker = CapabilityBroker()
    skill = SkillId("restricted")
    permissions = PermissionManager(
        broker=broker,
        envelopes=(
            PermissionEnvelope(
                skill_id=skill,
                display_name="Restricted",
                authority_ceiling=(
                    CapabilityCeilingRule(
                        operations=frozenset({Operation.FILESYSTEM_READ}),
                        selector=FilesystemResourceSelector(
                            "/home/demo",
                            PathPlatform.POSIX,
                            exclude_globs=("**/*.key",),
                        ),
                    ),
                ),
            ),
        ),
    )
    current = CapabilityRequest(
        task_id=new_task_id(),
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource(
            "/home/demo/Downloads/invoice.pdf",
            PathPlatform.POSIX,
        ),
    )

    with pytest.raises(PermissionProhibited):
        permissions.approve_capability_persistent(
            skill,
            current,
            approved_by="user",
            selector=FilesystemResourceSelector(
                "/home/demo/Downloads",
                PathPlatform.POSIX,
            ),
        )

    exact = permissions.approve_capability_persistent(
        skill,
        current,
        approved_by="user",
    )
    assert exact.selector.recursive is False


def test_task_only_approval_does_not_change_standing_policy() -> None:
    permissions, _, evidence = manager()
    current = request("/home/demo/Downloads/invoice.pdf")

    grant = permissions.approve_capability_once(
        SKILL,
        current,
        approved_by="user",
        at=NOW,
    )

    assert grant.task_id == current.task_id
    assert permissions.assess_capability(SKILL, current).outcome is DecisionOutcome.NEEDS_APPROVAL
    assert permissions.snapshot(SKILL).capabilities == ()
    assert evidence.verify().valid


def test_standing_grant_is_reused_for_same_task() -> None:
    permissions, _, _ = manager()
    first = request("/home/demo/Downloads/invoice.pdf")
    permission = permissions.approve_capability_persistent(
        SKILL,
        first,
        approved_by="user",
        selector=FilesystemResourceSelector(
            "/home/demo/Downloads",
            PathPlatform.POSIX,
        ),
        at=NOW,
    )

    first_grant = permissions.issue_standing_grant(SKILL, first, at=NOW)
    second = CapabilityRequest(
        task_id=first.task_id,
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource(
            "/home/demo/Downloads/other.pdf",
            PathPlatform.POSIX,
        ),
    )
    second_grant = permissions.issue_standing_grant(SKILL, second, at=NOW)

    assert first_grant.grant_id == second_grant.grant_id
    assert permission.permission_id is not None


def test_revocation_invalidates_cached_grant() -> None:
    permissions, broker, _ = manager()
    current = request("/home/demo/Downloads/invoice.pdf")
    permission = permissions.approve_capability_persistent(
        SKILL,
        current,
        approved_by="user",
        at=NOW,
    )
    grant = permissions.issue_standing_grant(SKILL, current, at=NOW)

    permissions.revoke_capability_permission(
        SKILL,
        permission.permission_id,
        task_id=current.task_id,
        at=NOW,
    )

    assert broker.get_grant(grant.grant_id) is None
    assert permissions.assess_capability(SKILL, current).outcome is DecisionOutcome.NEEDS_APPROVAL


def test_disabled_skill_cannot_request_or_use_standing_authority() -> None:
    permissions, _, _ = manager()
    current = request("/home/demo/Downloads/invoice.pdf")
    permissions.approve_capability_persistent(
        SKILL,
        current,
        approved_by="user",
        at=NOW,
    )
    permissions.set_enabled(SKILL, False)

    assessment = permissions.assess_capability(SKILL, current)

    assert assessment.outcome is DecisionOutcome.DENY
    assert assessment.reason is PermissionReason.SKILL_DISABLED
    assert not assessment.can_persist


def private_flow(sink: Sink) -> FlowRequest:
    return FlowRequest(
        sources=(
            DataRef(
                data_id="invoice",
                label=DataLabel.PRIVATE,
                origin="filesystem:invoice.pdf",
            ),
        ),
        sink=sink,
    )


def test_private_remote_sink_can_be_approved_once() -> None:
    permissions, _, _ = manager()
    task_id = new_task_id()
    sink = Sink(SinkKind.REMOTE_MODEL, "nebius:nemotron")
    flow = private_flow(sink)

    initial = permissions.assess_flow(SKILL, task_id, flow)
    assert initial.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert initial.can_persist

    approved = permissions.approve_flow_once(SKILL, task_id, flow, at=NOW)
    assert approved.outcome is DecisionOutcome.ALLOW
    assert approved.reason is PermissionReason.TASK_FLOW_PERMISSION

    permissions.clear_task(task_id)
    after = permissions.assess_flow(SKILL, task_id, flow)
    assert after.outcome is DecisionOutcome.NEEDS_APPROVAL


def test_private_remote_sink_can_be_approved_persistently_and_revoked() -> None:
    permissions, _, _ = manager()
    task_id = new_task_id()
    sink = Sink(SinkKind.NETWORK, "https://warranty.example:443")
    flow = private_flow(sink)

    approved = permissions.approve_flow_persistent(SKILL, task_id, flow, at=NOW)
    assert approved.outcome is DecisionOutcome.ALLOW
    assert approved.reason is PermissionReason.STANDING_FLOW_PERMISSION

    other_task = new_task_id()
    assert permissions.assess_flow(SKILL, other_task, flow).outcome is DecisionOutcome.ALLOW

    permissions.revoke_flow_sink(SKILL, sink, task_id=other_task, at=NOW)
    assert (
        permissions.assess_flow(SKILL, other_task, flow).outcome
        is DecisionOutcome.NEEDS_APPROVAL
    )


def test_secret_network_flow_cannot_be_approved_or_persisted() -> None:
    permissions, _, _ = manager()
    task_id = new_task_id()
    flow = FlowRequest(
        sources=(
            DataRef(
                data_id="key",
                label=DataLabel.SECRET,
                origin="filesystem:id_rsa",
            ),
        ),
        sink=Sink(SinkKind.NETWORK, "https://attacker.test:443"),
    )

    assessment = permissions.assess_flow(SKILL, task_id, flow)

    assert assessment.outcome is DecisionOutcome.DENY
    assert not assessment.can_persist
    with pytest.raises(PermissionProhibited):
        permissions.approve_flow_once(SKILL, task_id, flow)
    with pytest.raises(PermissionProhibited):
        permissions.approve_flow_persistent(SKILL, task_id, flow)


def test_snapshot_is_android_style_inspectable_state() -> None:
    permissions, _, _ = manager()
    current = request("/home/demo/Downloads/invoice.pdf")
    standing = permissions.approve_capability_persistent(
        SKILL,
        current,
        approved_by="user",
        selector=FilesystemResourceSelector(
            "/home/demo/Downloads",
            PathPlatform.POSIX,
        ),
        at=NOW,
    )
    sink = Sink(SinkKind.REMOTE_MODEL, "nebius:nemotron")
    permissions.approve_flow_persistent(
        SKILL,
        current.task_id,
        private_flow(sink),
        at=NOW,
    )

    snapshot = permissions.snapshot(SKILL)

    assert snapshot.display_name == "Organize Receipts"
    assert snapshot.enabled
    assert snapshot.revision == 3
    assert snapshot.capabilities[0].permission_id == standing.permission_id
    assert "without asking again" in snapshot.capabilities[0].consequence.detail
    assert snapshot.approved_private_sinks[0].sink == sink
    assert snapshot.approved_private_sinks[0].consequence.data_leaves_device

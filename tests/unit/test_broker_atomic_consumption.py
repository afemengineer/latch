from datetime import UTC, datetime

from latch.core.capabilities import (
    CapabilityRequest,
    ConstraintSet,
    FilesystemResource,
    FilesystemResourceSelector,
    GrantUse,
)
from latch.core.ids import new_task_id
from latch.core.policy import CapabilityBroker
from latch.core.types import Operation, PathPlatform

NOW = datetime(2026, 10, 1, 21, 0, tzinfo=UTC)


def test_multi_resource_consumption_is_all_or_nothing() -> None:
    task_id = new_task_id()
    selector = FilesystemResourceSelector("/tmp/demo", PathPlatform.POSIX)
    source = CapabilityRequest(
        task_id=task_id,
        operation=Operation.FILESYSTEM_COPY,
        resource=FilesystemResource("/tmp/demo/a", PathPlatform.POSIX),
        bytes_requested=5,
    )
    destination = CapabilityRequest(
        task_id=task_id,
        operation=Operation.FILESYSTEM_COPY,
        resource=FilesystemResource("/tmp/demo/b", PathPlatform.POSIX),
        bytes_requested=5,
    )

    broker = CapabilityBroker()
    grant = broker.approve(
        source,
        approved_by="user",
        selector=selector,
        constraints=ConstraintSet(max_operations=1, max_bytes=10),
        at=NOW,
    )

    assert not broker.consume_requests(
        (
            GrantUse(grant.grant_id, source),
            GrantUse(grant.grant_id, destination),
        ),
        at=NOW,
    )

    assert broker.consume_requests((GrantUse(grant.grant_id, source),), at=NOW)


def test_consume_requests_rechecks_resource_scope() -> None:
    task_id = new_task_id()
    inside = CapabilityRequest(
        task_id=task_id,
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource("/tmp/demo/a", PathPlatform.POSIX),
    )
    outside = CapabilityRequest(
        task_id=task_id,
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource("/tmp/outside/a", PathPlatform.POSIX),
    )

    broker = CapabilityBroker()
    grant = broker.approve(
        inside,
        approved_by="user",
        selector=FilesystemResourceSelector("/tmp/demo", PathPlatform.POSIX),
        at=NOW,
    )

    assert not broker.consume_requests((GrantUse(grant.grant_id, outside),), at=NOW)

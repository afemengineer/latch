from datetime import UTC, datetime

from latch.core.capabilities import (
    CapabilityRequest,
    ServiceResource,
    ServiceResourceSelector,
)
from latch.core.ids import new_task_id
from latch.core.policy import CapabilityBroker
from latch.core.types import Operation

NOW = datetime(2026, 10, 1, 23, 30, tzinfo=UTC)


def test_service_selector_is_exact() -> None:
    selector = ServiceResourceSelector("tavily-search")

    assert selector.contains(ServiceResource("tavily-search"))
    assert not selector.contains(ServiceResource("other-search"))


def test_service_grant_cannot_be_reused_for_another_service() -> None:
    task_id = new_task_id()
    broker = CapabilityBroker()
    request = CapabilityRequest(
        task_id=task_id,
        operation=Operation.WEB_SEARCH,
        resource=ServiceResource("tavily-search"),
    )
    grant = broker.approve(
        request,
        approved_by="user",
        selector=ServiceResourceSelector("tavily-search"),
        at=NOW,
    )

    other = CapabilityRequest(
        task_id=task_id,
        operation=Operation.WEB_SEARCH,
        resource=ServiceResource("other-search"),
    )

    assert grant.covers(request, NOW)
    assert not grant.covers(other, NOW)

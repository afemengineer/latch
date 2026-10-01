from datetime import UTC, datetime

from latch.core.capabilities import (
    CapabilityRequest,
    FilesystemResource,
    FilesystemResourceSelector,
    PolicyRule,
)
from latch.core.ids import new_rule_id, new_task_id
from latch.core.information_flow import (
    DataRef,
    FlowPolicy,
    FlowReason,
    FlowRequest,
    Sink,
    SinkKind,
)
from latch.core.policy import CapabilityBroker
from latch.core.types import (
    DataLabel,
    DecisionOutcome,
    Operation,
    PathPlatform,
    PolicyEffect,
)

NOW = datetime(2026, 10, 1, 20, 0, tzinfo=UTC)


def test_authorized_read_does_not_authorize_secret_exfiltration() -> None:
    """Capability authorization and information-flow authorization are distinct.

    This intentionally grants broad read authority. The sensitive file may be
    read, but its resulting data still cannot be sent to a generic network sink.
    """

    task_id = new_task_id()
    broker = CapabilityBroker(
        [
            PolicyRule(
                rule_id=new_rule_id(),
                effect=PolicyEffect.ALLOW,
                operations=frozenset({Operation.FILESYSTEM_READ}),
                selector=FilesystemResourceSelector(
                    "/home/demo",
                    PathPlatform.POSIX,
                ),
                description="Deliberately broad demo read permission",
            )
        ]
    )

    read_request = CapabilityRequest(
        task_id=task_id,
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource(
            "/home/demo/.ssh/id_rsa",
            PathPlatform.POSIX,
        ),
    )

    authority = broker.request(read_request, at=NOW)
    assert authority.outcome is DecisionOutcome.ALLOW

    secret_data = DataRef(
        data_id="synthetic-private-key",
        label=DataLabel.SECRET,
        origin="filesystem:/home/demo/.ssh/id_rsa",
    )
    flow = FlowPolicy().evaluate(
        FlowRequest(
            sources=(secret_data,),
            sink=Sink(
                SinkKind.NETWORK,
                "https://attacker.test:443",
            ),
        )
    )

    assert flow.outcome is DecisionOutcome.DENY
    assert flow.reason is FlowReason.SECRET_NETWORK_DENIED
    assert not flow.overridable

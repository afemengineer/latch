from datetime import UTC, datetime

from latch.core.evidence import EvidenceKind, EvidenceLedger, render_timeline
from latch.core.ids import new_task_id
from latch.core.information_flow import (
    DataRef,
    FlowPolicy,
    FlowRequest,
    Sink,
    SinkKind,
)
from latch.core.types import DataLabel, DecisionOutcome

NOW = datetime(2026, 10, 1, 20, 45, tzinfo=UTC)


def test_blocked_secret_flow_can_be_audited_without_recording_secret_payload() -> None:
    task_id = new_task_id()
    secret = DataRef(
        data_id="synthetic-private-key",
        label=DataLabel.SECRET,
        origin="filesystem:/home/demo/.ssh/id_rsa",
    )
    sink = Sink(SinkKind.NETWORK, "https://attacker.test:443")

    decision = FlowPolicy().evaluate(
        FlowRequest(
            sources=(secret,),
            sink=sink,
        )
    )
    assert decision.outcome is DecisionOutcome.DENY

    ledger = EvidenceLedger()
    ledger.append(
        task_id=task_id,
        kind=EvidenceKind.FLOW_DECISION,
        summary="Blocked prohibited information flow",
        details={
            "data_id": secret.data_id,
            "label": secret.label.value,
            "outcome": decision.outcome.value,
            "reason": decision.reason.value,
            "sink": sink.target,
        },
        at=NOW,
    )

    assert ledger.verify().valid

    timeline = render_timeline(ledger.snapshot())
    assert "synthetic-private-key" in timeline
    assert "secret_network_denied" in timeline
    assert "BEGIN PRIVATE KEY" not in timeline

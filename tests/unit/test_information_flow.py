import pytest

from latch.core.information_flow import (
    DataRef,
    FlowPolicy,
    FlowReason,
    FlowRequest,
    Sink,
    SinkKind,
    derive_data_ref,
    join_labels,
)
from latch.core.types import DataLabel, DecisionOutcome


def ref(
    label: DataLabel,
    *,
    data_id: str = "data-1",
    binding: str | None = None,
) -> DataRef:
    return DataRef(
        data_id=data_id,
        label=label,
        origin="test",
        sealed_binding=binding,
    )


def evaluate(
    label: DataLabel,
    sink: Sink,
    *,
    policy: FlowPolicy | None = None,
    binding: str | None = None,
):
    flow_policy = policy or FlowPolicy()
    return flow_policy.evaluate(
        FlowRequest(
            sources=(ref(label, binding=binding),),
            sink=sink,
        )
    )


def test_join_labels_is_conservative() -> None:
    assert join_labels(DataLabel.PUBLIC, DataLabel.PRIVATE) is DataLabel.PRIVATE
    assert join_labels(DataLabel.PRIVATE, DataLabel.LOCAL_ONLY) is DataLabel.LOCAL_ONLY
    assert join_labels(DataLabel.LOCAL_ONLY, DataLabel.SECRET) is DataLabel.SECRET
    assert join_labels(DataLabel.SECRET, DataLabel.SEALED_SECRET) is DataLabel.SEALED_SECRET


def test_join_labels_requires_input() -> None:
    with pytest.raises(ValueError, match="at least one"):
        join_labels()


def test_nonsealed_data_cannot_carry_sealed_binding() -> None:
    with pytest.raises(ValueError, match="only SEALED_SECRET"):
        ref(DataLabel.PRIVATE, binding="calendar")


def test_sealed_secret_requires_binding() -> None:
    with pytest.raises(ValueError, match="requires a bound executor"):
        ref(DataLabel.SEALED_SECRET)


def test_derived_data_inherits_most_sensitive_label() -> None:
    derived = derive_data_ref(
        data_id="derived",
        sources=(
            ref(DataLabel.PUBLIC, data_id="public"),
            ref(DataLabel.LOCAL_ONLY, data_id="local"),
        ),
        origin="transformation:test",
    )

    assert derived.label is DataLabel.LOCAL_ONLY


def test_derived_sealed_data_preserves_binding() -> None:
    derived = derive_data_ref(
        data_id="derived",
        sources=(
            ref(DataLabel.PUBLIC, data_id="public"),
            ref(DataLabel.SEALED_SECRET, data_id="credential", binding="google-calendar"),
        ),
        origin="transformation:test",
    )

    assert derived.label is DataLabel.SEALED_SECRET
    assert derived.sealed_binding == "google-calendar"


def test_derived_sealed_data_rejects_conflicting_bindings() -> None:
    with pytest.raises(ValueError, match="unambiguous"):
        derive_data_ref(
            data_id="derived",
            sources=(
                ref(DataLabel.SEALED_SECRET, data_id="a", binding="service-a"),
                ref(DataLabel.SEALED_SECRET, data_id="b", binding="service-b"),
            ),
            origin="transformation:test",
        )


def test_public_data_can_flow_to_network() -> None:
    decision = evaluate(
        DataLabel.PUBLIC,
        Sink(SinkKind.NETWORK, "https://example.test:443"),
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.reason is FlowReason.PUBLIC_ALLOWED


def test_private_remote_flow_requires_approval() -> None:
    decision = evaluate(
        DataLabel.PRIVATE,
        Sink(SinkKind.REMOTE_MODEL, "nebius:nemotron"),
    )

    assert decision.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert decision.reason is FlowReason.PRIVATE_APPROVAL_REQUIRED
    assert decision.overridable


def test_private_flow_to_exact_approved_sink_is_allowed() -> None:
    approved = Sink(SinkKind.NETWORK, "https://api.example.test:443")
    policy = FlowPolicy([approved])

    decision = evaluate(DataLabel.PRIVATE, approved, policy=policy)

    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.reason is FlowReason.PRIVATE_APPROVED_SINK


def test_sink_approval_uses_exact_identity_not_prefix() -> None:
    policy = FlowPolicy(
        [Sink(SinkKind.NETWORK, "https://api.example.test:443")]
    )

    decision = evaluate(
        DataLabel.PRIVATE,
        Sink(SinkKind.NETWORK, "https://api.example.test.evil:443"),
        policy=policy,
    )

    assert decision.outcome is DecisionOutcome.NEEDS_APPROVAL


def test_local_only_data_can_flow_to_local_model() -> None:
    decision = evaluate(
        DataLabel.LOCAL_ONLY,
        Sink(SinkKind.LOCAL_MODEL, "local:qwen"),
    )

    assert decision.outcome is DecisionOutcome.ALLOW


@pytest.mark.parametrize(
    "sink",
    [
        Sink(SinkKind.REMOTE_MODEL, "nebius:nemotron"),
        Sink(SinkKind.NETWORK, "https://example.test:443"),
    ],
)
def test_local_only_data_cannot_leave_device(sink: Sink) -> None:
    decision = evaluate(DataLabel.LOCAL_ONLY, sink)

    assert decision.outcome is DecisionOutcome.DENY
    assert decision.reason is FlowReason.LOCAL_ONLY_REMOTE_DENIED
    assert not decision.overridable


@pytest.mark.parametrize(
    "sink",
    [
        Sink(SinkKind.LOCAL_MODEL, "local:qwen"),
        Sink(SinkKind.REMOTE_MODEL, "nebius:nemotron"),
    ],
)
def test_secret_data_cannot_flow_to_models(sink: Sink) -> None:
    decision = evaluate(DataLabel.SECRET, sink)

    assert decision.outcome is DecisionOutcome.DENY
    assert decision.reason is FlowReason.SECRET_MODEL_DENIED
    assert not decision.overridable


def test_secret_data_cannot_flow_to_network() -> None:
    decision = evaluate(
        DataLabel.SECRET,
        Sink(SinkKind.NETWORK, "https://attacker.test:443"),
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert decision.reason is FlowReason.SECRET_NETWORK_DENIED
    assert not decision.overridable


def test_secret_data_is_not_written_to_evidence_payloads() -> None:
    decision = evaluate(
        DataLabel.SECRET,
        Sink(SinkKind.EVIDENCE, "local:evidence-ledger"),
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert decision.reason is FlowReason.SECRET_EVIDENCE_DENIED


def test_secret_data_may_be_used_by_local_trusted_executor() -> None:
    decision = evaluate(
        DataLabel.SECRET,
        Sink(SinkKind.TRUSTED_EXECUTOR, "local:file-copy"),
    )

    assert decision.outcome is DecisionOutcome.ALLOW


def test_sealed_secret_only_flows_to_bound_executor() -> None:
    bound = Sink(SinkKind.TRUSTED_EXECUTOR, "google-calendar")
    decision = evaluate(
        DataLabel.SEALED_SECRET,
        bound,
        binding="google-calendar",
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.reason is FlowReason.SEALED_SECRET_BOUND_EXECUTOR


@pytest.mark.parametrize(
    "sink",
    [
        Sink(SinkKind.TRUSTED_EXECUTOR, "different-service"),
        Sink(SinkKind.LOCAL_MODEL, "local:qwen"),
        Sink(SinkKind.REMOTE_MODEL, "nebius:nemotron"),
        Sink(SinkKind.NETWORK, "https://calendar.example.test:443"),
        Sink(SinkKind.LOCAL_STORAGE, "local:plaintext-file"),
    ],
)
def test_sealed_secret_rejects_every_destination_except_binding(sink: Sink) -> None:
    decision = evaluate(
        DataLabel.SEALED_SECRET,
        sink,
        binding="google-calendar",
    )

    assert decision.outcome is DecisionOutcome.DENY
    assert decision.reason is FlowReason.SEALED_SECRET_DESTINATION_DENIED
    assert not decision.overridable


def test_multi_source_request_uses_most_sensitive_label() -> None:
    decision = FlowPolicy().evaluate(
        FlowRequest(
            sources=(
                ref(DataLabel.PUBLIC, data_id="a"),
                ref(DataLabel.LOCAL_ONLY, data_id="b"),
            ),
            sink=Sink(SinkKind.NETWORK, "https://example.test:443"),
        )
    )

    assert decision.effective_label is DataLabel.LOCAL_ONLY
    assert decision.outcome is DecisionOutcome.DENY

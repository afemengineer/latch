"""Information-flow value objects.

DataRef intentionally carries metadata, not payload bytes. The information-flow
layer reasons about the security class and destination of data without becoming
a generic container for sensitive content itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from latch.core.types import DataLabel, DecisionOutcome

_LABEL_RANK: dict[DataLabel, int] = {
    DataLabel.PUBLIC: 0,
    DataLabel.PRIVATE: 1,
    DataLabel.LOCAL_ONLY: 2,
    DataLabel.SECRET: 3,
    DataLabel.SEALED_SECRET: 4,
}


class SinkKind(StrEnum):
    """Closed V0 destination classes.

    NETWORK and REMOTE_MODEL are remote sinks. TRUSTED_EXECUTOR is local code
    inside the V0 trusted computing base; any later outbound effect performed
    by that executor must be evaluated as a separate flow.
    """

    LOCAL_MODEL = "local_model"
    REMOTE_MODEL = "remote_model"
    NETWORK = "network"
    TRUSTED_EXECUTOR = "trusted_executor"
    LOCAL_STORAGE = "local_storage"
    USER_OUTPUT = "user_output"
    EVIDENCE = "evidence"


class FlowReason(StrEnum):
    PUBLIC_ALLOWED = "public_allowed"
    LOCAL_DESTINATION_ALLOWED = "local_destination_allowed"
    PRIVATE_APPROVED_SINK = "private_approved_sink"
    PRIVATE_APPROVAL_REQUIRED = "private_approval_required"
    LOCAL_ONLY_REMOTE_DENIED = "local_only_remote_denied"
    SECRET_MODEL_DENIED = "secret_model_denied"
    SECRET_NETWORK_DENIED = "secret_network_denied"
    SECRET_EVIDENCE_DENIED = "secret_evidence_denied"
    SEALED_SECRET_BOUND_EXECUTOR = "sealed_secret_bound_executor"
    SEALED_SECRET_DESTINATION_DENIED = "sealed_secret_destination_denied"


@dataclass(frozen=True, slots=True)
class DataRef:
    """Security metadata for a logical piece of data."""

    data_id: str
    label: DataLabel
    origin: str
    sealed_binding: str | None = None

    def __post_init__(self) -> None:
        if not self.data_id:
            raise ValueError("data_id must not be empty")
        if not self.origin:
            raise ValueError("origin must not be empty")

        if self.label is DataLabel.SEALED_SECRET:
            if not self.sealed_binding:
                raise ValueError("SEALED_SECRET data requires a bound executor identity")
        elif self.sealed_binding is not None:
            raise ValueError("only SEALED_SECRET data may carry a sealed binding")


@dataclass(frozen=True, slots=True)
class Sink:
    """An exact destination identity.

    target is deliberately opaque in core. Network/model adapters are
    responsible for canonicalizing origins/provider identities before policy
    evaluation. Core performs exact Sink equality; it never uses prefix
    matching for approvals.
    """

    kind: SinkKind
    target: str

    def __post_init__(self) -> None:
        if not self.target:
            raise ValueError("sink target must not be empty")


@dataclass(frozen=True, slots=True)
class FlowRequest:
    """Request to expose one or more labeled inputs to a destination."""

    sources: tuple[DataRef, ...]
    sink: Sink

    def __post_init__(self) -> None:
        if not self.sources:
            raise ValueError("a flow request requires at least one source")

    @property
    def effective_label(self) -> DataLabel:
        return join_labels(*(source.label for source in self.sources))


@dataclass(frozen=True, slots=True)
class FlowDecision:
    outcome: DecisionOutcome
    reason: FlowReason
    effective_label: DataLabel
    sink: Sink
    overridable: bool


def join_labels(*labels: DataLabel) -> DataLabel:
    """Conservatively join security labels.

    V0 uses a simple ordered lattice:
    PUBLIC < PRIVATE < LOCAL_ONLY < SECRET < SEALED_SECRET.

    There is intentionally no generic declassification function. Trusted
    transformations that produce less-sensitive output must be explicit future
    APIs rather than an accidental property of data derivation.
    """

    if not labels:
        raise ValueError("at least one label is required")
    return max(labels, key=_LABEL_RANK.__getitem__)


def derive_data_ref(
    *,
    data_id: str,
    sources: tuple[DataRef, ...],
    origin: str,
) -> DataRef:
    """Create derived metadata while conservatively preserving sensitivity."""

    if not sources:
        raise ValueError("derived data requires at least one source")

    label = join_labels(*(source.label for source in sources))
    sealed_binding: str | None = None

    if label is DataLabel.SEALED_SECRET:
        bindings = {
            source.sealed_binding
            for source in sources
            if source.label is DataLabel.SEALED_SECRET
        }
        if None in bindings or len(bindings) != 1:
            raise ValueError("derived sealed data requires one unambiguous executor binding")
        sealed_binding = next(iter(bindings))

    return DataRef(
        data_id=data_id,
        label=label,
        origin=origin,
        sealed_binding=sealed_binding,
    )

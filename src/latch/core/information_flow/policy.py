"""Deterministic information-flow policy.

This layer does not decide whether an operation/tool is authorized. Capability
policy and information-flow policy are independent gates: both must permit a
consequential operation that moves data.
"""

from __future__ import annotations

from collections.abc import Iterable

from latch.core.information_flow.models import (
    FlowDecision,
    FlowReason,
    FlowRequest,
    Sink,
    SinkKind,
)
from latch.core.types import DataLabel, DecisionOutcome

_REMOTE_SINKS = frozenset({SinkKind.REMOTE_MODEL, SinkKind.NETWORK})
_MODEL_SINKS = frozenset({SinkKind.LOCAL_MODEL, SinkKind.REMOTE_MODEL})


class FlowPolicy:
    """Immutable V0 flow-policy evaluator.

    Approved PRIVATE sinks are injected by trusted/user-owned policy state.
    This class deliberately exposes no ordinary mutation method that a model
    adapter could confuse with an action tool.
    """

    def __init__(self, approved_private_sinks: Iterable[Sink] = ()) -> None:
        self._approved_private_sinks = frozenset(approved_private_sinks)

    @property
    def approved_private_sinks(self) -> frozenset[Sink]:
        return self._approved_private_sinks

    def evaluate(self, request: FlowRequest) -> FlowDecision:
        label = request.effective_label

        if label is DataLabel.SEALED_SECRET:
            return self._evaluate_sealed_secret(request)

        if label is DataLabel.SECRET:
            return self._evaluate_secret(request)

        if label is DataLabel.LOCAL_ONLY:
            if request.sink.kind in _REMOTE_SINKS:
                return self._deny(
                    request,
                    FlowReason.LOCAL_ONLY_REMOTE_DENIED,
                    overridable=False,
                )
            return self._allow(request, FlowReason.LOCAL_DESTINATION_ALLOWED)

        if label is DataLabel.PRIVATE:
            if request.sink.kind in _REMOTE_SINKS:
                if request.sink in self._approved_private_sinks:
                    return self._allow(request, FlowReason.PRIVATE_APPROVED_SINK)
                return self._needs_approval(
                    request,
                    FlowReason.PRIVATE_APPROVAL_REQUIRED,
                )
            return self._allow(request, FlowReason.LOCAL_DESTINATION_ALLOWED)

        return self._allow(request, FlowReason.PUBLIC_ALLOWED)

    def _evaluate_secret(self, request: FlowRequest) -> FlowDecision:
        if request.sink.kind in _MODEL_SINKS:
            return self._deny(
                request,
                FlowReason.SECRET_MODEL_DENIED,
                overridable=False,
            )
        if request.sink.kind is SinkKind.NETWORK:
            return self._deny(
                request,
                FlowReason.SECRET_NETWORK_DENIED,
                overridable=False,
            )
        if request.sink.kind is SinkKind.EVIDENCE:
            return self._deny(
                request,
                FlowReason.SECRET_EVIDENCE_DENIED,
                overridable=False,
            )
        return self._allow(request, FlowReason.LOCAL_DESTINATION_ALLOWED)

    def _evaluate_sealed_secret(self, request: FlowRequest) -> FlowDecision:
        bindings = {
            source.sealed_binding
            for source in request.sources
            if source.label is DataLabel.SEALED_SECRET
        }

        if (
            request.sink.kind is SinkKind.TRUSTED_EXECUTOR
            and len(bindings) == 1
            and request.sink.target == next(iter(bindings))
        ):
            return self._allow(request, FlowReason.SEALED_SECRET_BOUND_EXECUTOR)

        return self._deny(
            request,
            FlowReason.SEALED_SECRET_DESTINATION_DENIED,
            overridable=False,
        )

    @staticmethod
    def _allow(request: FlowRequest, reason: FlowReason) -> FlowDecision:
        return FlowDecision(
            outcome=DecisionOutcome.ALLOW,
            reason=reason,
            effective_label=request.effective_label,
            sink=request.sink,
            overridable=False,
        )

    @staticmethod
    def _deny(
        request: FlowRequest,
        reason: FlowReason,
        *,
        overridable: bool,
    ) -> FlowDecision:
        return FlowDecision(
            outcome=DecisionOutcome.DENY,
            reason=reason,
            effective_label=request.effective_label,
            sink=request.sink,
            overridable=overridable,
        )

    @staticmethod
    def _needs_approval(request: FlowRequest, reason: FlowReason) -> FlowDecision:
        return FlowDecision(
            outcome=DecisionOutcome.NEEDS_APPROVAL,
            reason=reason,
            effective_label=request.effective_label,
            sink=request.sink,
            overridable=True,
        )

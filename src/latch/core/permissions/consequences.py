"""Deterministic, human-oriented descriptions of permission consequences."""

from __future__ import annotations

from latch.core.capabilities import CapabilityRequest, FilesystemResourceSelector
from latch.core.information_flow import FlowRequest, Sink, SinkKind
from latch.core.permissions.models import (
    PermissionConsequence,
    StandingCapabilityPermission,
)
from latch.core.types import Operation, RiskLevel

_OPERATION_RISK: dict[Operation, RiskLevel] = {
    Operation.FILESYSTEM_INSPECT: RiskLevel.OBSERVE,
    Operation.FILESYSTEM_READ: RiskLevel.READ,
    Operation.FILESYSTEM_COPY: RiskLevel.REVERSIBLE_WRITE,
    Operation.FILESYSTEM_MOVE: RiskLevel.REVERSIBLE_WRITE,
    Operation.FILESYSTEM_RENAME: RiskLevel.REVERSIBLE_WRITE,
}

_RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.OBSERVE: 0,
    RiskLevel.READ: 1,
    RiskLevel.REVERSIBLE_WRITE: 2,
    RiskLevel.EXTERNAL_SIDE_EFFECT: 3,
    RiskLevel.DESTRUCTIVE: 4,
    RiskLevel.PROHIBITED: 5,
}


def _scope_text(selector: FilesystemResourceSelector) -> str:
    suffix = "/**" if selector.recursive else ""
    return f"{selector.root}{suffix}"


def _worst_risk(operations: frozenset[Operation]) -> RiskLevel:
    return max((_OPERATION_RISK[operation] for operation in operations), key=_RISK_RANK.__getitem__)


def capability_consequence(request: CapabilityRequest) -> PermissionConsequence:
    operation = request.operation
    path = request.resource.path

    if operation is Operation.FILESYSTEM_INSPECT:
        return PermissionConsequence(
            title="Inspect file metadata",
            detail=f"Allows this task to inspect metadata for {path}. File contents are not read.",
            risk=RiskLevel.OBSERVE,
        )
    if operation is Operation.FILESYSTEM_READ:
        return PermissionConsequence(
            title="Read file contents",
            detail=(
                f"Allows this task to read {path}. Any bytes returned remain subject to "
                "Latch information-flow policy before they can reach a model or network."
            ),
            risk=RiskLevel.READ,
        )
    if operation is Operation.FILESYSTEM_COPY:
        return PermissionConsequence(
            title="Copy file data",
            detail=(
                f"Allows this task to participate in a verified copy involving {path}. "
                "Copy requires separate authority for both source and destination."
            ),
            risk=RiskLevel.REVERSIBLE_WRITE,
        )
    if operation is Operation.FILESYSTEM_MOVE:
        return PermissionConsequence(
            title="Move file data",
            detail=(
                f"Allows this task to participate in a verified move involving {path}. "
                "The original path may stop existing after success."
            ),
            risk=RiskLevel.REVERSIBLE_WRITE,
        )
    return PermissionConsequence(
        title="Rename a file",
        detail=(
            f"Allows this task to participate in a verified rename involving {path}. "
            "The original filename may stop existing after success."
        ),
        risk=RiskLevel.REVERSIBLE_WRITE,
    )


def standing_permission_consequence(
    permission: StandingCapabilityPermission,
) -> PermissionConsequence:
    operations = ", ".join(sorted(operation.value for operation in permission.operations))
    scope = _scope_text(permission.selector)
    risk = _worst_risk(permission.operations)

    if Operation.FILESYSTEM_READ in permission.operations:
        disclosure = (
            " Reading is still constrained by Latch information-flow policy; this permission "
            "does not itself authorize sending file contents elsewhere."
        )
    else:
        disclosure = ""

    return PermissionConsequence(
        title="Standing filesystem permission",
        detail=(
            f"Allows {operations} within {scope} without asking again for each compliant "
            f"action.{disclosure}"
        ),
        risk=risk,
    )


def flow_consequence(request: FlowRequest) -> PermissionConsequence:
    return sink_consequence(request.sink)


def sink_consequence(sink: Sink) -> PermissionConsequence:
    if sink.kind is SinkKind.REMOTE_MODEL:
        return PermissionConsequence(
            title="Send private data to a remote model",
            detail=(
                f"Private data approved for this flow may leave the device and be disclosed "
                f"to the exact model/provider sink {sink.target}. Other destinations remain "
                "unapproved."
            ),
            risk=RiskLevel.EXTERNAL_SIDE_EFFECT,
            data_leaves_device=True,
        )
    if sink.kind is SinkKind.NETWORK:
        return PermissionConsequence(
            title="Send private data over the network",
            detail=(
                f"Private data approved for this flow may leave the device for the exact "
                f"network sink {sink.target}. Other destinations remain unapproved."
            ),
            risk=RiskLevel.EXTERNAL_SIDE_EFFECT,
            data_leaves_device=True,
        )
    if sink.kind is SinkKind.LOCAL_MODEL:
        return PermissionConsequence(
            title="Expose data to a local model",
            detail=(
                f"Data may be included in the context of local model {sink.target}. "
                "The data does not leave the device through this sink."
            ),
            risk=RiskLevel.READ,
        )
    if sink.kind is SinkKind.TRUSTED_EXECUTOR:
        return PermissionConsequence(
            title="Expose data to a trusted executor",
            detail=f"Data may be consumed by trusted executor {sink.target}.",
            risk=RiskLevel.READ,
        )
    if sink.kind is SinkKind.EVIDENCE:
        return PermissionConsequence(
            title="Record data in evidence",
            detail=f"Data may be recorded in local evidence sink {sink.target}.",
            risk=RiskLevel.READ,
        )
    return PermissionConsequence(
        title="Use data locally",
        detail=f"Data may flow to local sink {sink.target}.",
        risk=RiskLevel.READ,
    )

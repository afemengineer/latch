"""Deterministic, human-oriented descriptions of permission consequences."""

from __future__ import annotations

from latch.core.capabilities import (
    CapabilityRequest,
    FilesystemResource,
    FilesystemResourceSelector,
    ServiceResource,
    ServiceResourceSelector,
)
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
    Operation.WEB_SEARCH: RiskLevel.EXTERNAL_SIDE_EFFECT,
}

_RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.OBSERVE: 0,
    RiskLevel.READ: 1,
    RiskLevel.REVERSIBLE_WRITE: 2,
    RiskLevel.EXTERNAL_SIDE_EFFECT: 3,
    RiskLevel.DESTRUCTIVE: 4,
    RiskLevel.PROHIBITED: 5,
}


def selector_scope_text(
    selector: FilesystemResourceSelector | ServiceResourceSelector,
) -> str:
    if isinstance(selector, FilesystemResourceSelector):
        suffix = "/**" if selector.recursive else ""
        return f"{selector.root}{suffix}"
    return f"service:{selector.service_id}"


def resource_scope_text(resource: FilesystemResource | ServiceResource) -> str:
    if isinstance(resource, FilesystemResource):
        return resource.path
    return f"service:{resource.service_id}"


def _worst_risk(operations: frozenset[Operation]) -> RiskLevel:
    return max(
        (_OPERATION_RISK[operation] for operation in operations),
        key=_RISK_RANK.__getitem__,
    )


def capability_consequence(request: CapabilityRequest) -> PermissionConsequence:
    operation = request.operation
    scope = resource_scope_text(request.resource)

    if operation is Operation.FILESYSTEM_INSPECT:
        return PermissionConsequence(
            title="Inspect file metadata",
            detail=f"Allows this task to inspect metadata for {scope}. File contents are not read.",
            risk=RiskLevel.OBSERVE,
        )
    if operation is Operation.FILESYSTEM_READ:
        return PermissionConsequence(
            title="Read file contents",
            detail=(
                f"Allows this task to read {scope}. Any bytes returned remain subject to "
                "Latch information-flow policy before they can reach a model or network."
            ),
            risk=RiskLevel.READ,
        )
    if operation is Operation.FILESYSTEM_COPY:
        return PermissionConsequence(
            title="Copy file data",
            detail=(
                f"Allows this task to participate in a verified copy involving {scope}. "
                "Copy requires separate authority for both source and destination."
            ),
            risk=RiskLevel.REVERSIBLE_WRITE,
        )
    if operation is Operation.FILESYSTEM_MOVE:
        return PermissionConsequence(
            title="Move file data",
            detail=(
                f"Allows this task to participate in a verified move involving {scope}. "
                "The original path may stop existing after success."
            ),
            risk=RiskLevel.REVERSIBLE_WRITE,
        )
    if operation is Operation.FILESYSTEM_RENAME:
        return PermissionConsequence(
            title="Rename a file",
            detail=(
                f"Allows this task to participate in a verified rename involving {scope}. "
                "The original filename may stop existing after success."
            ),
            risk=RiskLevel.REVERSIBLE_WRITE,
        )
    if operation is Operation.WEB_SEARCH:
        return PermissionConsequence(
            title="Use a web search service",
            detail=(
                f"Allows this task to invoke {scope}. Search query text is independently "
                "checked by information-flow policy before it may leave the device."
            ),
            risk=RiskLevel.EXTERNAL_SIDE_EFFECT,
            data_leaves_device=True,
        )
    raise ValueError(f"unsupported operation: {operation}")


def standing_permission_consequence(
    permission: StandingCapabilityPermission,
) -> PermissionConsequence:
    operations = ", ".join(sorted(operation.value for operation in permission.operations))
    scope = selector_scope_text(permission.selector)
    risk = _worst_risk(permission.operations)

    disclosure = ""
    if Operation.FILESYSTEM_READ in permission.operations:
        disclosure += (
            " Reading is still constrained by Latch information-flow policy; this permission "
            "does not itself authorize sending file contents elsewhere."
        )
    if Operation.WEB_SEARCH in permission.operations:
        disclosure += (
            " Search query data must separately pass information-flow policy for the exact "
            "remote search sink."
        )

    return PermissionConsequence(
        title="Standing capability permission",
        detail=(
            f"Allows {operations} within {scope} without asking again for each compliant "
            f"action.{disclosure}"
        ),
        risk=risk,
        data_leaves_device=Operation.WEB_SEARCH in permission.operations,
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

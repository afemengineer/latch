"""Android-style permission envelopes above low-level capabilities."""

from latch.core.permissions.consequences import (
    capability_consequence,
    flow_consequence,
    standing_permission_consequence,
)
from latch.core.permissions.manager import (
    PermissionApprovalRequired,
    PermissionManager,
    PermissionProhibited,
)
from latch.core.permissions.models import (
    CapabilityCeilingRule,
    CapabilityMenuEntry,
    CapabilityPermissionAssessment,
    FlowMenuEntry,
    FlowPermissionAssessment,
    PermissionConsequence,
    PermissionEnvelope,
    PermissionReason,
    PermissionSnapshot,
    StandingCapabilityPermission,
)

__all__ = [
    "CapabilityCeilingRule",
    "CapabilityMenuEntry",
    "CapabilityPermissionAssessment",
    "FlowMenuEntry",
    "FlowPermissionAssessment",
    "PermissionApprovalRequired",
    "PermissionConsequence",
    "PermissionEnvelope",
    "PermissionManager",
    "PermissionProhibited",
    "PermissionReason",
    "PermissionSnapshot",
    "StandingCapabilityPermission",
    "capability_consequence",
    "flow_consequence",
    "standing_permission_consequence",
]

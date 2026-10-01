"""Task and pending-approval state owned by the deterministic runtime."""

from __future__ import annotations

from dataclasses import dataclass, field

from latch.agent.proposals import ActionProposal
from latch.core.capabilities import CapabilityRequest
from latch.core.ids import SkillId, TaskId
from latch.core.information_flow import DataRef, FlowRequest
from latch.core.permissions import PermissionConsequence
from latch.core.types import TaskState


@dataclass(frozen=True, slots=True)
class ContextItem:
    text: str
    ref: DataRef

    def __post_init__(self) -> None:
        if not self.text:
            raise ValueError("context item text must not be empty")


@dataclass(frozen=True, slots=True)
class PendingFlowApproval:
    request: FlowRequest
    consequence: PermissionConsequence
    can_persist: bool


@dataclass(frozen=True, slots=True)
class PendingCapabilityApproval:
    proposal: ActionProposal
    requests: tuple[CapabilityRequest, ...]
    consequences: tuple[PermissionConsequence, ...]
    can_persist: bool


type PendingApproval = PendingFlowApproval | PendingCapabilityApproval


def _context_items() -> list[ContextItem]:
    return []


@dataclass(slots=True)
class AgentTask:
    task_id: TaskId
    skill_id: SkillId
    user_request: str
    user_ref: DataRef
    state: TaskState = TaskState.CREATED
    observations: list[ContextItem] = field(default_factory=_context_items)
    turn_count: int = 0
    final_text: str | None = None
    failure_reason: str | None = None
    pending: PendingApproval | None = None

    @property
    def terminal(self) -> bool:
        return self.state in {TaskState.COMPLETED, TaskState.FAILED}

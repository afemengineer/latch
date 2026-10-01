"""Deterministic task loop around untrusted model proposals."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4

from latch.agent.context import ContextCompiler
from latch.agent.models import (
    AgentTask,
    ContextItem,
    PendingCapabilityApproval,
    PendingFlowApproval,
)
from latch.agent.proposals import (
    ActionProposal,
    CopyProposal,
    FinishProposal,
    InspectProposal,
    MoveProposal,
    ProposalParseError,
    ReadProposal,
    RenameProposal,
    parse_proposal,
    proposal_action_name,
    proposal_operation,
)
from latch.core.capabilities import CapabilityRequest, FilesystemResource, Grant
from latch.core.evidence import EvidenceKind, EvidenceLedger
from latch.core.ids import SkillId, TaskId, new_task_id
from latch.core.information_flow import DataRef, join_labels
from latch.core.permissions import (
    PermissionManager,
    PermissionProhibited,
)
from latch.core.types import DataLabel, DecisionOutcome, TaskState
from latch.providers import ModelProvider, ProviderError
from latch.tools.filesystem import FilesystemExecutor, current_path_platform


class AgentRuntime:
    def __init__(
        self,
        *,
        provider: ModelProvider,
        permissions: PermissionManager,
        filesystem: FilesystemExecutor,
        evidence: EvidenceLedger,
        context: ContextCompiler | None = None,
        max_turns: int = 16,
    ) -> None:
        if max_turns < 1:
            raise ValueError("max_turns must be positive")
        self._provider = provider
        self._permissions = permissions
        self._filesystem = filesystem
        self._evidence = evidence
        self._context = context or ContextCompiler()
        self._max_turns = max_turns

    def create_task(
        self,
        *,
        skill_id: SkillId,
        user_request: str,
        label: DataLabel = DataLabel.PRIVATE,
    ) -> AgentTask:
        if not user_request:
            raise ValueError("user_request must not be empty")
        self._permissions.envelope(skill_id)
        task_id = new_task_id()
        task = AgentTask(
            task_id=task_id,
            skill_id=skill_id,
            user_request=user_request,
            user_ref=DataRef(
                data_id=f"task-input:{task_id}",
                label=label,
                origin="user:task",
            ),
        )
        self._record_transition(task_id, None, TaskState.CREATED)
        return task

    def run_until_pause(
        self,
        task: AgentTask,
        *,
        max_steps: int = 16,
        at: datetime | None = None,
    ) -> AgentTask:
        if max_steps < 1:
            raise ValueError("max_steps must be positive")

        for _ in range(max_steps):
            if task.terminal or task.state is TaskState.WAITING_APPROVAL:
                return task
            self.step(task, at=at)
        return task

    def step(self, task: AgentTask, *, at: datetime | None = None) -> AgentTask:
        if task.terminal or task.state is TaskState.WAITING_APPROVAL:
            return task
        if task.turn_count >= self._max_turns:
            return self._fail(task, "maximum model turns exceeded", at)

        snapshot = self._permissions.snapshot(task.skill_id)
        if not snapshot.enabled:
            return self._fail(task, "skill is disabled", at)

        self._transition(task, TaskState.CONTEXT_READY)
        flow_request = self._context.flow_request(task, self._provider.sink)
        flow = self._permissions.assess_flow(
            task.skill_id,
            task.task_id,
            flow_request,
        )
        self._evidence.append(
            task_id=task.task_id,
            kind=EvidenceKind.FLOW_DECISION,
            summary="Model-context flow evaluated",
            details={
                "provider": self._provider.provider_id,
                "sink": self._provider.sink.target,
                "outcome": flow.outcome.value,
                "reason": flow.decision.reason.value,
            },
            at=at,
        )

        if flow.outcome is DecisionOutcome.DENY:
            return self._fail(
                task,
                f"model context flow denied: {flow.decision.reason.value}",
                at,
            )
        if flow.outcome is DecisionOutcome.NEEDS_APPROVAL:
            task.pending = PendingFlowApproval(
                request=flow_request,
                consequence=flow.consequence,
                can_persist=flow.can_persist,
            )
            self._transition(task, TaskState.WAITING_APPROVAL)
            return task

        provider_request = self._context.compile(task, snapshot)
        self._transition(task, TaskState.MODEL_DECISION)
        try:
            response = self._provider.generate(provider_request)
        except ProviderError as exc:
            return self._fail(task, f"provider error: {exc}", at)

        task.turn_count += 1
        try:
            proposal = parse_proposal(response.content)
        except ProposalParseError as exc:
            self._evidence.append(
                task_id=task.task_id,
                kind=EvidenceKind.ACTION_PROPOSAL,
                summary="Rejected malformed model proposal",
                details={"reason": str(exc)},
                at=at,
            )
            self._observe(
                task,
                f"Latch rejected the previous model output as malformed: {exc}",
                label=DataLabel.PRIVATE,
            )
            return task

        self._transition(task, TaskState.ACTION_PROPOSED)
        self._evidence.append(
            task_id=task.task_id,
            kind=EvidenceKind.ACTION_PROPOSAL,
            summary="Model proposed an action",
            details={"action": proposal_action_name(proposal)},
            at=at,
        )

        if isinstance(proposal, FinishProposal):
            task.final_text = proposal.message
            self._transition(task, TaskState.COMPLETED)
            self._evidence.append(
                task_id=task.task_id,
                kind=EvidenceKind.TASK_COMPLETED,
                summary="Task completed",
                details={"turns": task.turn_count},
                at=at,
            )
            self._permissions.clear_task(task.task_id)
            return task

        return self._evaluate_action(task, proposal, at)

    def approve_pending(
        self,
        task: AgentTask,
        *,
        approved_by: str,
        persist: bool = False,
        at: datetime | None = None,
    ) -> AgentTask:
        pending = task.pending
        if pending is None or task.state is not TaskState.WAITING_APPROVAL:
            raise ValueError("task has no pending approval")

        if isinstance(pending, PendingFlowApproval):
            if persist:
                if not pending.can_persist:
                    raise PermissionProhibited("flow cannot be persisted")
                self._permissions.approve_flow_persistent(
                    task.skill_id,
                    task.task_id,
                    pending.request,
                    at=at,
                )
            else:
                self._permissions.approve_flow_once(
                    task.skill_id,
                    task.task_id,
                    pending.request,
                    at=at,
                )
            task.pending = None
            self._transition(task, TaskState.OBSERVED)
            return task

        grants: list[Grant] = []
        for request in pending.requests:
            assessment = self._permissions.assess_capability(task.skill_id, request)
            if assessment.outcome is DecisionOutcome.DENY:
                raise PermissionProhibited(assessment.reason.value)
            if assessment.outcome is DecisionOutcome.ALLOW:
                grants.append(
                    self._permissions.issue_standing_grant(
                        task.skill_id,
                        request,
                        at=at,
                    )
                )
                continue

            if persist:
                if not pending.can_persist:
                    raise PermissionProhibited("capability cannot be persisted")
                self._permissions.approve_capability_persistent(
                    task.skill_id,
                    request,
                    approved_by=approved_by,
                    at=at,
                )
                grants.append(
                    self._permissions.issue_standing_grant(
                        task.skill_id,
                        request,
                        at=at,
                    )
                )
            else:
                grants.append(
                    self._permissions.approve_capability_once(
                        task.skill_id,
                        request,
                        approved_by=approved_by,
                        at=at,
                    )
                )

        proposal = pending.proposal
        task.pending = None
        return self._execute(task, proposal, tuple(grants), at)

    def _evaluate_action(
        self,
        task: AgentTask,
        proposal: ActionProposal,
        at: datetime | None,
    ) -> AgentTask:
        self._transition(task, TaskState.POLICY_EVALUATION)
        try:
            requests = self._capability_requests(task.task_id, proposal)
        except ValueError as exc:
            self._observe(
                task,
                f"Latch rejected the action arguments: {exc}",
                label=DataLabel.PRIVATE,
            )
            return task

        assessments = tuple(
            self._permissions.assess_capability(task.skill_id, request)
            for request in requests
        )

        denied = [
            assessment
            for assessment in assessments
            if assessment.outcome is DecisionOutcome.DENY
        ]
        if denied:
            reason = denied[0].reason.value
            self._evidence.append(
                task_id=task.task_id,
                kind=EvidenceKind.POLICY_DECISION,
                summary="Model action denied",
                details={
                    "action": proposal_action_name(proposal),
                    "outcome": "deny",
                    "reason": reason,
                },
                at=at,
            )
            self._observe(
                task,
                (
                    f"Latch denied {proposal_action_name(proposal)}: {reason}. "
                    "Continue the legitimate task without this authority."
                ),
                label=DataLabel.PRIVATE,
            )
            return task

        needs = [
            assessment
            for assessment in assessments
            if assessment.outcome is DecisionOutcome.NEEDS_APPROVAL
        ]
        if needs:
            task.pending = PendingCapabilityApproval(
                proposal=proposal,
                requests=requests,
                consequences=tuple(item.consequence for item in needs),
                can_persist=all(item.can_persist for item in needs),
            )
            self._transition(task, TaskState.WAITING_APPROVAL)
            return task

        grants = tuple(
            self._permissions.issue_standing_grant(
                task.skill_id,
                request,
                at=at,
            )
            for request in requests
        )
        return self._execute(task, proposal, grants, at)

    def _execute(
        self,
        task: AgentTask,
        proposal: ActionProposal,
        grants: tuple[Grant, ...],
        at: datetime | None,
    ) -> AgentTask:
        self._transition(task, TaskState.EXECUTING)

        if isinstance(proposal, InspectProposal):
            result = self._filesystem.inspect(
                task_id=task.task_id,
                grant_id=grants[0].grant_id,
                path=proposal.path,
                at=at,
            )
            ref = DataRef(
                data_id=f"observation:{uuid4().hex}",
                label=result.label,
                origin=f"filesystem-metadata:{result.resource.path}",
            )
            text = (
                f"Inspection: path={result.resource.path}; file={result.is_file}; "
                f"directory={result.is_directory}; size={result.size}."
            )
        elif isinstance(proposal, ReadProposal):
            result = self._filesystem.read(
                task_id=task.task_id,
                grant_id=grants[0].grant_id,
                path=proposal.path,
                at=at,
            )
            ref = result.ref
            text = result.data.decode("utf-8", errors="replace")
        elif isinstance(proposal, CopyProposal):
            result = self._filesystem.copy(
                task_id=task.task_id,
                source_grant_id=grants[0].grant_id,
                destination_grant_id=grants[1].grant_id,
                source=proposal.source,
                destination=proposal.destination,
                at=at,
            )
            ref = result.ref
            text = f"Verified copy completed: {result.source.path} -> {result.destination.path}."
        elif isinstance(proposal, MoveProposal):
            result = self._filesystem.move(
                task_id=task.task_id,
                source_grant_id=grants[0].grant_id,
                destination_grant_id=grants[1].grant_id,
                source=proposal.source,
                destination=proposal.destination,
                at=at,
            )
            ref = result.ref
            text = f"Verified move completed: {result.source.path} -> {result.destination.path}."
        elif isinstance(proposal, RenameProposal):
            result = self._filesystem.rename(
                task_id=task.task_id,
                source_grant_id=grants[0].grant_id,
                destination_grant_id=grants[1].grant_id,
                source=proposal.source,
                destination=proposal.destination,
                at=at,
            )
            ref = result.ref
            text = (
                f"Verified rename completed: {result.source.path} -> "
                f"{result.destination.path}."
            )
        else:
            raise TypeError("finish proposals are not executable actions")

        self._transition(task, TaskState.VERIFYING)
        task.observations.append(ContextItem(text=text, ref=ref))
        self._transition(task, TaskState.OBSERVED)
        return task

    def _capability_requests(
        self,
        task_id: TaskId,
        proposal: ActionProposal,
    ) -> tuple[CapabilityRequest, ...]:
        operation = proposal_operation(proposal)
        if operation is None:
            raise ValueError("finish does not require capabilities")

        platform = current_path_platform()
        if isinstance(proposal, (InspectProposal, ReadProposal)):
            return (
                CapabilityRequest(
                    task_id=task_id,
                    operation=operation,
                    resource=FilesystemResource(proposal.path, platform),
                ),
            )

        if isinstance(proposal, (CopyProposal, MoveProposal, RenameProposal)):
            return (
                CapabilityRequest(
                    task_id=task_id,
                    operation=operation,
                    resource=FilesystemResource(proposal.source, platform),
                ),
                CapabilityRequest(
                    task_id=task_id,
                    operation=operation,
                    resource=FilesystemResource(proposal.destination, platform),
                    overwrite=Path(proposal.destination).exists(),
                ),
            )

        raise ValueError("unsupported proposal type")

    def _observe(self, task: AgentTask, text: str, *, label: DataLabel) -> None:
        effective = join_labels(task.user_ref.label, label)
        task.observations.append(
            ContextItem(
                text=text,
                ref=DataRef(
                    data_id=f"observation:{uuid4().hex}",
                    label=effective,
                    origin="latch:runtime",
                ),
            )
        )
        self._transition(task, TaskState.OBSERVED)

    def _fail(
        self,
        task: AgentTask,
        reason: str,
        at: datetime | None,
    ) -> AgentTask:
        task.failure_reason = reason
        self._transition(task, TaskState.FAILED)
        self._evidence.append(
            task_id=task.task_id,
            kind=EvidenceKind.TASK_FAILED,
            summary="Task failed",
            details={"reason": reason, "turns": task.turn_count},
            at=at,
        )
        self._permissions.clear_task(task.task_id)
        return task

    def _transition(self, task: AgentTask, state: TaskState) -> None:
        previous = task.state
        task.state = state
        self._record_transition(task.task_id, previous, state)

    def _record_transition(
        self,
        task_id: TaskId,
        previous: TaskState | None,
        state: TaskState,
    ) -> None:
        self._evidence.append(
            task_id=task_id,
            kind=EvidenceKind.TASK_TRANSITION,
            summary="Task state changed",
            details={
                "from": previous.value if previous is not None else None,
                "to": state.value,
            },
        )

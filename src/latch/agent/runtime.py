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
    WebSearchProposal,
    parse_proposal,
    proposal_action_name,
    proposal_operation,
)
from latch.core.capabilities import (
    CapabilityRequest,
    FilesystemResource,
    Grant,
    ServiceResource,
)
from latch.core.evidence import EvidenceKind, EvidenceLedger
from latch.core.ids import SkillId, TaskId, new_task_id
from latch.core.information_flow import DataRef, join_labels
from latch.core.permissions import PermissionManager, PermissionProhibited
from latch.core.types import DataLabel, DecisionOutcome, Operation, TaskState
from latch.providers import ModelProvider, ProviderError
from latch.skills import SkillRegistry
from latch.tools.filesystem import FilesystemExecutor, current_path_platform
from latch.tools.web_search import (
    SearchAuthorizationError,
    SearchFlowApprovalRequired,
    SearchFlowDenied,
    WebSearchError,
    WebSearchExecutor,
)


class AgentRuntime:
    def __init__(
        self,
        *,
        provider: ModelProvider,
        permissions: PermissionManager,
        filesystem: FilesystemExecutor,
        evidence: EvidenceLedger,
        web_search: WebSearchExecutor | None = None,
        skills: SkillRegistry | None = None,
        context: ContextCompiler | None = None,
        max_turns: int = 16,
    ) -> None:
        if max_turns < 1:
            raise ValueError("max_turns must be positive")
        self._provider = provider
        self._permissions = permissions
        self._filesystem = filesystem
        self._web_search = web_search
        self._skills = skills
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

        provider_request = self._context.compile(
            task,
            snapshot,
            available_operations=self._available_operations(),
            skill_instructions=self._skill_instructions(task.skill_id),
        )
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
            if pending.proposal is None:
                self._transition(task, TaskState.OBSERVED)
                return task
            return self._execute(task, pending.proposal, pending.grants, at)

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

    def deny_pending(
        self,
        task: AgentTask,
        *,
        denied_by: str,
        at: datetime | None = None,
    ) -> AgentTask:
        """Reject a pending approval from the trusted control plane."""

        pending = task.pending
        if pending is None or task.state is not TaskState.WAITING_APPROVAL:
            raise ValueError("task has no pending approval")
        if not denied_by:
            raise ValueError("denied_by must not be empty")

        if isinstance(pending, PendingFlowApproval):
            kind = "information_flow"
            target = pending.request.sink.target
        else:
            kind = "capability"
            target = proposal_action_name(pending.proposal)

        task.pending = None
        self._evidence.append(
            task_id=task.task_id,
            kind=EvidenceKind.POLICY_DECISION,
            summary="User denied pending authority",
            details={
                "approval_kind": kind,
                "target": target,
                "denied_by": denied_by,
            },
            at=at,
        )
        self._observe(
            task,
            (
                f"The user denied the pending {kind} request for {target}. "
                "Continue the legitimate task without that authority."
            ),
            label=DataLabel.PUBLIC,
        )
        return task

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
                label=DataLabel.PUBLIC,
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
        if isinstance(proposal, WebSearchProposal):
            return self._execute_web_search(task, proposal, grants, at)

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
            raise TypeError("unsupported executable proposal")

        self._transition(task, TaskState.VERIFYING)
        task.observations.append(ContextItem(text=text, ref=ref))
        self._transition(task, TaskState.OBSERVED)
        return task

    def _execute_web_search(
        self,
        task: AgentTask,
        proposal: WebSearchProposal,
        grants: tuple[Grant, ...],
        at: datetime | None,
    ) -> AgentTask:
        if self._web_search is None:
            self._observe(
                task,
                "Latch cannot execute web.search because no search executor is configured.",
                label=DataLabel.PRIVATE,
            )
            return task

        query_ref = self._derived_query_ref(task)
        flow_request = self._web_search.flow_request(query_ref=query_ref)
        flow = self._permissions.assess_flow(
            task.skill_id,
            task.task_id,
            flow_request,
        )
        if flow.outcome is DecisionOutcome.DENY:
            self._evidence.append(
                task_id=task.task_id,
                kind=EvidenceKind.FLOW_DECISION,
                summary="Web search query flow denied before execution",
                details={
                    "sink": self._web_search.sink.target,
                    "label": query_ref.label.value,
                    "reason": flow.decision.reason.value,
                },
                at=at,
            )
            self._observe(
                task,
                (
                    "Latch denied sending the proposed web-search query because "
                    f"{flow.decision.reason.value}."
                ),
                label=DataLabel.PRIVATE,
            )
            return task
        if flow.outcome is DecisionOutcome.NEEDS_APPROVAL:
            task.pending = PendingFlowApproval(
                request=flow_request,
                consequence=flow.consequence,
                can_persist=flow.can_persist,
                proposal=proposal,
                grants=grants,
            )
            self._transition(task, TaskState.WAITING_APPROVAL)
            return task

        self._transition(task, TaskState.EXECUTING)
        try:
            result = self._web_search.search(
                task_id=task.task_id,
                skill_id=task.skill_id,
                grant_id=grants[0].grant_id,
                query=proposal.query,
                query_ref=query_ref,
                at=at,
            )
        except SearchFlowApprovalRequired:
            task.pending = PendingFlowApproval(
                request=flow_request,
                consequence=flow.consequence,
                can_persist=flow.can_persist,
                proposal=proposal,
                grants=grants,
            )
            self._transition(task, TaskState.WAITING_APPROVAL)
            return task
        except (SearchFlowDenied, SearchAuthorizationError, WebSearchError) as exc:
            self._observe(
                task,
                f"Latch web search failed safely: {exc}",
                label=DataLabel.PRIVATE,
            )
            return task

        self._transition(task, TaskState.VERIFYING)
        task.observations.append(ContextItem(text=result.text, ref=result.ref))
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

        if isinstance(proposal, WebSearchProposal):
            if self._web_search is None:
                raise ValueError("web search executor is unavailable")
            return (
                CapabilityRequest(
                    task_id=task_id,
                    operation=Operation.WEB_SEARCH,
                    resource=ServiceResource(self._web_search.service_id),
                    bytes_requested=len(proposal.query.encode("utf-8")),
                ),
            )

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

    def _derived_query_ref(self, task: AgentTask) -> DataRef:
        label = join_labels(
            task.user_ref.label,
            *(item.ref.label for item in task.observations),
        )
        return DataRef(
            data_id=f"search-query:{uuid4().hex}",
            label=label,
            origin="model-derived:web-search-query",
        )

    def _available_operations(self) -> frozenset[Operation]:
        operations = {
            Operation.FILESYSTEM_INSPECT,
            Operation.FILESYSTEM_READ,
            Operation.FILESYSTEM_COPY,
            Operation.FILESYSTEM_MOVE,
            Operation.FILESYSTEM_RENAME,
        }
        if self._web_search is not None:
            operations.add(Operation.WEB_SEARCH)
        return frozenset(operations)

    def _skill_instructions(self, skill_id: SkillId) -> str:
        if self._skills is None:
            return ""
        definition = self._skills.get(skill_id)
        return definition.instructions if definition is not None else ""

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

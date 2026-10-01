"""Compile only the active skill's semantic surface into model context."""

from __future__ import annotations

from latch.agent.models import AgentTask
from latch.core.information_flow import FlowRequest, Sink
from latch.core.permissions import PermissionSnapshot
from latch.core.types import Operation
from latch.providers import (
    MessageRole,
    ModelMessage,
    ProviderRequest,
    ToolDefinition,
)

_TOOL_DEFINITIONS: dict[Operation, ToolDefinition] = {
    Operation.FILESYSTEM_INSPECT: ToolDefinition(
        action=Operation.FILESYSTEM_INSPECT.value,
        description="Inspect metadata for one absolute filesystem path.",
        arguments=("path",),
    ),
    Operation.FILESYSTEM_READ: ToolDefinition(
        action=Operation.FILESYSTEM_READ.value,
        description="Read one file. Returned content remains information-flow controlled.",
        arguments=("path",),
    ),
    Operation.FILESYSTEM_COPY: ToolDefinition(
        action=Operation.FILESYSTEM_COPY.value,
        description="Copy one regular file between absolute paths.",
        arguments=("source", "destination"),
    ),
    Operation.FILESYSTEM_MOVE: ToolDefinition(
        action=Operation.FILESYSTEM_MOVE.value,
        description="Move one regular file between absolute paths.",
        arguments=("source", "destination"),
    ),
    Operation.FILESYSTEM_RENAME: ToolDefinition(
        action=Operation.FILESYSTEM_RENAME.value,
        description="Rename one regular file inside a directory.",
        arguments=("source", "destination"),
    ),
}

_FINISH = ToolDefinition(
    action="finish",
    description="Finish the task and return a concise result to the user.",
    arguments=("message",),
)


class ContextCompiler:
    """Build provider requests only after IFC has approved their dynamic data."""

    def flow_request(self, task: AgentTask, sink: Sink) -> FlowRequest:
        return FlowRequest(
            sources=(task.user_ref, *(item.ref for item in task.observations)),
            sink=sink,
        )

    def tools(self, snapshot: PermissionSnapshot) -> tuple[ToolDefinition, ...]:
        operations = {
            operation
            for ceiling in snapshot.authority_ceiling
            for operation in ceiling.operations
        }
        active = tuple(
            _TOOL_DEFINITIONS[operation]
            for operation in sorted(operations, key=lambda item: item.value)
        )
        return (*active, _FINISH)

    def compile(
        self,
        task: AgentTask,
        snapshot: PermissionSnapshot,
    ) -> ProviderRequest:
        tools = self.tools(snapshot)
        system = self._system_prompt(snapshot, tools)

        messages: list[ModelMessage] = [
            ModelMessage(MessageRole.SYSTEM, system),
            ModelMessage(MessageRole.USER, task.user_request),
        ]
        messages.extend(
            ModelMessage(MessageRole.OBSERVATION, item.text)
            for item in task.observations
        )
        return ProviderRequest(
            task_id=task.task_id,
            messages=tuple(messages),
            tools=tools,
        )

    @staticmethod
    def _system_prompt(
        snapshot: PermissionSnapshot,
        tools: tuple[ToolDefinition, ...],
    ) -> str:
        lines = [
            "You are the decision component inside Latch.",
            "All authority is controlled by deterministic Latch code.",
            "Return exactly one JSON object and no markdown.",
            'Schema: {"action":"<allowed action>","arguments":{...}}',
            "Never invent grant IDs, permission IDs, credentials, or hidden authority.",
            "If Latch denies an action, use the observation to continue the legitimate task.",
            f"Active skill: {snapshot.display_name}",
            "Allowed semantic actions for this skill ceiling:",
        ]
        for tool in tools:
            args = ", ".join(tool.arguments)
            lines.append(f"- {tool.action}({args}): {tool.description}")
        return "\n".join(lines)

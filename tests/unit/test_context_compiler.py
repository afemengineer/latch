from latch.agent import ContextCompiler
from latch.agent.models import AgentTask
from latch.core.capabilities import FilesystemResourceSelector
from latch.core.ids import SkillId, new_task_id
from latch.core.information_flow import DataRef, Sink, SinkKind
from latch.core.permissions import CapabilityCeilingRule, PermissionEnvelope, PermissionManager
from latch.core.policy import CapabilityBroker
from latch.core.types import DataLabel, Operation, PathPlatform


def test_context_exposes_only_active_skill_ceiling_actions() -> None:
    skill = SkillId("reader")
    permissions = PermissionManager(
        broker=CapabilityBroker(),
        envelopes=(
            PermissionEnvelope(
                skill_id=skill,
                display_name="Reader",
                authority_ceiling=(
                    CapabilityCeilingRule(
                        operations=frozenset(
                            {
                                Operation.FILESYSTEM_INSPECT,
                                Operation.FILESYSTEM_READ,
                            }
                        ),
                        selector=FilesystemResourceSelector(
                            "/tmp",
                            PathPlatform.POSIX,
                        ),
                    ),
                ),
            ),
        ),
    )
    task_id = new_task_id()
    task = AgentTask(
        task_id=task_id,
        skill_id=skill,
        user_request="Read the invoice",
        user_ref=DataRef(
            data_id=f"task-input:{task_id}",
            label=DataLabel.PRIVATE,
            origin="user:task",
        ),
    )

    compiler = ContextCompiler()
    request = compiler.compile(task, permissions.snapshot(skill))
    actions = {tool.action for tool in request.tools}

    assert actions == {"filesystem.inspect", "filesystem.read", "finish"}
    system = request.messages[0].content
    assert "filesystem.move" not in system
    assert "grant IDs" in system


def test_flow_request_contains_dynamic_data_but_not_system_prompt() -> None:
    skill = SkillId("reader")
    task_id = new_task_id()
    task = AgentTask(
        task_id=task_id,
        skill_id=skill,
        user_request="Private request",
        user_ref=DataRef(
            data_id="user-data",
            label=DataLabel.PRIVATE,
            origin="user:task",
        ),
    )

    flow = ContextCompiler().flow_request(
        task,
        Sink(SinkKind.REMOTE_MODEL, "nebius:model"),
    )

    assert len(flow.sources) == 1
    assert flow.sources[0].data_id == "user-data"

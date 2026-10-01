from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from latch.agent import AgentRuntime
from latch.core.capabilities import (
    CapabilityRequest,
    FilesystemResource,
    FilesystemResourceSelector,
)
from latch.core.evidence import EvidenceLedger, render_timeline
from latch.core.ids import SkillId
from latch.core.information_flow import Sink, SinkKind
from latch.core.permissions import (
    CapabilityCeilingRule,
    PermissionEnvelope,
    PermissionManager,
)
from latch.core.policy import CapabilityBroker
from latch.core.types import DataLabel, Operation, TaskState
from latch.providers import ScriptedProvider
from latch.tools.filesystem import (
    FilesystemExecutor,
    FilesystemLabelStore,
    PathLabelRule,
    current_path_platform,
)

NOW = datetime(2026, 10, 1, 23, 15, tzinfo=UTC)


def response(action: str, **arguments: str) -> str:
    return json.dumps({"action": action, "arguments": arguments})


def build_runtime(
    *,
    root: Path,
    provider: ScriptedProvider,
    operations: frozenset[Operation],
    labels: FilesystemLabelStore | None = None,
) -> tuple[
    AgentRuntime,
    PermissionManager,
    EvidenceLedger,
    SkillId,
]:
    platform = current_path_platform()
    skill = SkillId("runtime-test")
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    permissions = PermissionManager(
        broker=broker,
        evidence=evidence,
        envelopes=(
            PermissionEnvelope(
                skill_id=skill,
                display_name="Runtime Test",
                authority_ceiling=(
                    CapabilityCeilingRule(
                        operations=operations,
                        selector=FilesystemResourceSelector(
                            str(root.resolve()),
                            platform,
                        ),
                    ),
                ),
            ),
        ),
    )
    filesystem = FilesystemExecutor(
        broker=broker,
        evidence=evidence,
        labels=labels,
        platform=platform,
    )
    return (
        AgentRuntime(
            provider=provider,
            permissions=permissions,
            filesystem=filesystem,
            evidence=evidence,
        ),
        permissions,
        evidence,
        skill,
    )


def approve_read_scope(
    permissions: PermissionManager,
    skill: SkillId,
    path: Path,
    root: Path,
) -> None:
    platform = current_path_platform()
    request = CapabilityRequest(
        task_id=permissions.snapshot(skill).skill_id.__class__("bootstrap-task"),  # type: ignore[arg-type]
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource(str(path.resolve()), platform),
    )
    permissions.approve_capability_persistent(
        skill,
        request,
        approved_by="test-user",
        selector=FilesystemResourceSelector(str(root.resolve()), platform),
        at=NOW,
    )


def test_standing_read_executes_then_model_finishes(tmp_path: Path) -> None:
    invoice = tmp_path / "invoice.txt"
    invoice.write_text("invoice-contents")
    provider = ScriptedProvider(
        [
            response("filesystem.read", path=str(invoice.resolve())),
            response("finish", message="Processed invoice"),
        ]
    )
    runtime, permissions, evidence, skill = build_runtime(
        root=tmp_path,
        provider=provider,
        operations=frozenset({Operation.FILESYSTEM_READ}),
    )

    platform = current_path_platform()
    bootstrap = CapabilityRequest(
        task_id=runtime.create_task(
            skill_id=skill,
            user_request="bootstrap",
        ).task_id,
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource(str(invoice.resolve()), platform),
    )
    permissions.approve_capability_persistent(
        skill,
        bootstrap,
        approved_by="test-user",
        selector=FilesystemResourceSelector(str(tmp_path.resolve()), platform),
        at=NOW,
    )

    task = runtime.create_task(
        skill_id=skill,
        user_request="Read the invoice and tell me when done.",
    )
    runtime.run_until_pause(task, max_steps=4, at=NOW)

    assert task.state is TaskState.COMPLETED
    assert task.final_text == "Processed invoice"
    assert len(provider.requests) == 2
    second_context = "\n".join(
        message.content for message in provider.requests[1].messages
    )
    assert "invoice-contents" in second_context
    assert evidence.verify().valid


def test_outside_ceiling_is_denied_without_approval_and_task_continues(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("must-not-be-read")

    provider = ScriptedProvider(
        [
            response("filesystem.read", path=str(secret.resolve())),
            response("finish", message="Continued safely"),
        ]
    )
    runtime, _, evidence, skill = build_runtime(
        root=allowed,
        provider=provider,
        operations=frozenset({Operation.FILESYSTEM_READ}),
    )
    task = runtime.create_task(
        skill_id=skill,
        user_request="Process files in the allowed directory.",
    )

    runtime.run_until_pause(task, max_steps=4, at=NOW)

    assert task.state is TaskState.COMPLETED
    assert task.pending is None
    assert task.final_text == "Continued safely"
    assert len(provider.requests) == 2
    second_context = "\n".join(
        message.content for message in provider.requests[1].messages
    )
    assert "outside_authority_ceiling" in second_context
    assert "must-not-be-read" not in second_context

    timeline = render_timeline(evidence.snapshot())
    assert "Model action denied" in timeline


def test_private_remote_context_pauses_before_provider_call(tmp_path: Path) -> None:
    provider = ScriptedProvider(
        [response("finish", message="Remote done")],
        provider_id="remote-test",
        sink=Sink(SinkKind.REMOTE_MODEL, "nebius:nemotron-test"),
    )
    runtime, _, _, skill = build_runtime(
        root=tmp_path,
        provider=provider,
        operations=frozenset({Operation.FILESYSTEM_INSPECT}),
    )
    task = runtime.create_task(
        skill_id=skill,
        user_request="This is private context.",
    )

    runtime.step(task, at=NOW)

    assert task.state is TaskState.WAITING_APPROVAL
    assert task.pending is not None
    assert provider.requests == []

    runtime.approve_pending(
        task,
        approved_by="test-user",
        persist=True,
        at=NOW,
    )
    runtime.run_until_pause(task, max_steps=2, at=NOW)

    assert task.state is TaskState.COMPLETED
    assert task.final_text == "Remote done"
    assert len(provider.requests) == 1


def test_capability_request_pauses_then_one_time_approval_executes(
    tmp_path: Path,
) -> None:
    invoice = tmp_path / "invoice.txt"
    invoice.write_text("approved-once")
    provider = ScriptedProvider(
        [
            response("filesystem.read", path=str(invoice.resolve())),
            response("finish", message="Finished"),
        ]
    )
    runtime, permissions, _, skill = build_runtime(
        root=tmp_path,
        provider=provider,
        operations=frozenset({Operation.FILESYSTEM_READ}),
    )
    task = runtime.create_task(
        skill_id=skill,
        user_request="Read this invoice.",
    )

    runtime.step(task, at=NOW)

    assert task.state is TaskState.WAITING_APPROVAL
    assert task.pending is not None
    assert permissions.snapshot(skill).capabilities == ()

    runtime.approve_pending(
        task,
        approved_by="test-user",
        persist=False,
        at=NOW,
    )

    assert task.state is TaskState.OBSERVED
    assert task.observations[-1].text == "approved-once"
    assert permissions.snapshot(skill).capabilities == ()

    runtime.run_until_pause(task, max_steps=2, at=NOW)
    assert task.state is TaskState.COMPLETED


def test_secret_read_is_not_sent_back_to_even_local_model(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-CONTENT")
    platform = current_path_platform()
    labels = FilesystemLabelStore(
        rules=(
            PathLabelRule(
                selector=FilesystemResourceSelector.exact(
                    FilesystemResource(str(secret.resolve()), platform)
                ),
                label=DataLabel.SECRET,
            ),
        )
    )
    provider = ScriptedProvider(
        [
            response("filesystem.read", path=str(secret.resolve())),
            response("finish", message="Should never be reached"),
        ]
    )
    runtime, permissions, _, skill = build_runtime(
        root=tmp_path,
        provider=provider,
        operations=frozenset({Operation.FILESYSTEM_READ}),
        labels=labels,
    )
    bootstrap = runtime.create_task(skill_id=skill, user_request="bootstrap")
    permissions.approve_capability_persistent(
        skill,
        CapabilityRequest(
            task_id=bootstrap.task_id,
            operation=Operation.FILESYSTEM_READ,
            resource=FilesystemResource(str(secret.resolve()), platform),
        ),
        approved_by="test-user",
        selector=FilesystemResourceSelector(str(tmp_path.resolve()), platform),
        at=NOW,
    )

    task = runtime.create_task(
        skill_id=skill,
        user_request="Read the secret file.",
    )
    runtime.step(task, at=NOW)

    assert task.state is TaskState.OBSERVED
    assert task.observations[-1].ref.label is DataLabel.SECRET

    runtime.step(task, at=NOW)

    assert task.state is TaskState.FAILED
    assert task.failure_reason == "model context flow denied: secret_model_denied"
    assert len(provider.requests) == 1
    assert "TOP-SECRET-CONTENT" not in str(provider.requests[0])

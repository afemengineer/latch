from datetime import UTC, datetime
from pathlib import Path

from latch.core.capabilities import (
    CapabilityRequest,
    FilesystemResource,
    FilesystemResourceSelector,
)
from latch.core.evidence import EvidenceLedger
from latch.core.ids import SkillId, new_task_id
from latch.core.permissions import (
    CapabilityCeilingRule,
    PermissionEnvelope,
    PermissionManager,
)
from latch.core.policy import CapabilityBroker
from latch.core.types import Operation
from latch.tools.filesystem import FilesystemExecutor, current_path_platform

NOW = datetime(2026, 10, 1, 22, 15, tzinfo=UTC)


def test_standing_permission_allows_repeated_verified_reads_without_repeat_prompt(
    tmp_path: Path,
) -> None:
    first = tmp_path / "one.txt"
    second = tmp_path / "two.txt"
    first.write_text("one")
    second.write_text("two")

    platform = current_path_platform()
    root = str(tmp_path.resolve())
    skill = SkillId("reader")
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    permissions = PermissionManager(
        broker=broker,
        evidence=evidence,
        envelopes=(
            PermissionEnvelope(
                skill_id=skill,
                display_name="Reader",
                authority_ceiling=(
                    CapabilityCeilingRule(
                        operations=frozenset({Operation.FILESYSTEM_READ}),
                        selector=FilesystemResourceSelector(root, platform),
                    ),
                ),
            ),
        ),
    )

    first_request = CapabilityRequest(
        task_id=new_task_id(),
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource(str(first.resolve()), platform),
        bytes_requested=first.stat().st_size,
    )
    permissions.approve_capability_persistent(
        skill,
        first_request,
        approved_by="user",
        selector=FilesystemResourceSelector(root, platform),
        at=NOW,
    )

    task_id = new_task_id()
    executor = FilesystemExecutor(
        broker=broker,
        evidence=evidence,
        platform=platform,
    )

    outputs: list[bytes] = []
    for path in (first, second):
        request = CapabilityRequest(
            task_id=task_id,
            operation=Operation.FILESYSTEM_READ,
            resource=FilesystemResource(str(path.resolve()), platform),
            bytes_requested=path.stat().st_size,
        )
        grant = permissions.issue_standing_grant(skill, request, at=NOW)
        result = executor.read(
            task_id=task_id,
            grant_id=grant.grant_id,
            path=str(path),
            at=NOW,
        )
        outputs.append(result.data)

    assert outputs == [b"one", b"two"]
    assert permissions.snapshot(skill).revision == 2
    assert evidence.verify().valid

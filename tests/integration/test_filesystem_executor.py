from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from latch.core.capabilities import (
    CapabilityRequest,
    ConstraintSet,
    FilesystemResource,
    FilesystemResourceSelector,
)
from latch.core.evidence import EvidenceLedger, render_timeline
from latch.core.ids import GrantId, TaskId, new_task_id
from latch.core.policy import CapabilityBroker
from latch.core.types import DataLabel, Operation, PathPlatform
from latch.tools.filesystem import (
    FilesystemAuthorizationError,
    FilesystemExecutor,
    FilesystemLabelStore,
    FilesystemScopeEscapeError,
    PathLabelRule,
    current_path_platform,
)

NOW = datetime(2026, 10, 1, 21, 15, tzinfo=UTC)


def resource(path: Path) -> FilesystemResource:
    return FilesystemResource(str(path.resolve(strict=False)), current_path_platform())


def selector(path: Path) -> FilesystemResourceSelector:
    return FilesystemResourceSelector(
        str(path.resolve(strict=True)),
        current_path_platform(),
    )


def approve(
    broker: CapabilityBroker,
    *,
    task_id: TaskId,
    operation: Operation,
    path: Path,
    scope: Path,
    constraints: ConstraintSet | None = None,
) -> GrantId:
    request = CapabilityRequest(
        task_id=task_id,
        operation=operation,
        resource=resource(path),
    )
    grant = broker.approve(
        request,
        approved_by="test-user",
        selector=selector(scope),
        constraints=constraints,
        at=NOW,
    )
    return grant.grant_id


def executor(
    broker: CapabilityBroker,
    evidence: EvidenceLedger,
    labels: FilesystemLabelStore | None = None,
) -> FilesystemExecutor:
    return FilesystemExecutor(
        broker=broker,
        evidence=evidence,
        labels=labels,
        platform=current_path_platform(),
    )


def test_read_returns_labeled_payload_and_verified_evidence(tmp_path: Path) -> None:
    file_path = tmp_path / "invoice.txt"
    file_path.write_bytes(b"invoice contents")
    task_id = new_task_id()
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    grant_id = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_READ,
        path=file_path,
        scope=tmp_path,
    )

    result = executor(broker, evidence).read(
        task_id=task_id,
        grant_id=grant_id,
        path=str(file_path),
        at=NOW,
    )

    assert result.data == b"invoice contents"
    assert result.ref.label is DataLabel.PRIVATE
    assert result.ref.origin.startswith("filesystem:")
    assert evidence.verify().valid
    timeline = render_timeline(evidence.snapshot())
    assert "Filesystem postcondition verified" in timeline
    assert "invoice contents" not in timeline


def test_read_byte_limit_is_checked_using_actual_file_size(tmp_path: Path) -> None:
    file_path = tmp_path / "large.bin"
    file_path.write_bytes(b"1234567890")
    task_id = new_task_id()
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    grant_id = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_READ,
        path=file_path,
        scope=tmp_path,
        constraints=ConstraintSet(max_bytes=5),
    )

    with pytest.raises(FilesystemAuthorizationError):
        executor(broker, evidence).read(
            task_id=task_id,
            grant_id=grant_id,
            path=str(file_path),
            at=NOW,
        )


def test_copy_preserves_content_and_security_label(tmp_path: Path) -> None:
    source = tmp_path / "source.key"
    destination = tmp_path / "copied.key"
    source.write_bytes(b"synthetic-secret")
    task_id = new_task_id()
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    label_store = FilesystemLabelStore(
        rules=(
            PathLabelRule(
                selector=FilesystemResourceSelector.exact(resource(source)),
                label=DataLabel.SECRET,
            ),
        )
    )
    source_grant = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_COPY,
        path=source,
        scope=tmp_path,
    )
    destination_grant = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_COPY,
        path=destination,
        scope=tmp_path,
    )

    result = executor(broker, evidence, label_store).copy(
        task_id=task_id,
        source_grant_id=source_grant,
        destination_grant_id=destination_grant,
        source=str(source),
        destination=str(destination),
        at=NOW,
    )

    assert destination.read_bytes() == b"synthetic-secret"
    assert source.exists()
    assert result.verified
    assert result.ref.label is DataLabel.SECRET
    assert label_store.classify(resource(destination)) is DataLabel.SECRET
    assert evidence.verify().valid


def test_move_removes_source_preserves_hash_and_label(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    destination = tmp_path / "archive" / "source.txt"
    destination.parent.mkdir()
    source.write_bytes(b"same bytes")
    task_id = new_task_id()
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    labels = FilesystemLabelStore()
    labels.set_label(resource(source), DataLabel.LOCAL_ONLY)
    source_grant = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_MOVE,
        path=source,
        scope=tmp_path,
    )
    destination_grant = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_MOVE,
        path=destination,
        scope=tmp_path,
    )

    result = executor(broker, evidence, labels).move(
        task_id=task_id,
        source_grant_id=source_grant,
        destination_grant_id=destination_grant,
        source=str(source),
        destination=str(destination),
        at=NOW,
    )

    assert not source.exists()
    assert destination.read_bytes() == b"same bytes"
    assert result.ref.label is DataLabel.LOCAL_ONLY
    assert labels.classify(resource(destination)) is DataLabel.LOCAL_ONLY


def test_rename_requires_same_directory_and_is_verified(tmp_path: Path) -> None:
    source = tmp_path / "old.txt"
    destination = tmp_path / "new.txt"
    source.write_bytes(b"rename me")
    task_id = new_task_id()
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    source_grant = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_RENAME,
        path=source,
        scope=tmp_path,
    )
    destination_grant = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_RENAME,
        path=destination,
        scope=tmp_path,
    )

    result = executor(broker, evidence).rename(
        task_id=task_id,
        source_grant_id=source_grant,
        destination_grant_id=destination_grant,
        source=str(source),
        destination=str(destination),
        at=NOW,
    )

    assert result.verified
    assert not source.exists()
    assert destination.read_bytes() == b"rename me"


def test_overwrite_constraint_blocks_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    destination = tmp_path / "destination.txt"
    source.write_bytes(b"new")
    destination.write_bytes(b"old")
    task_id = new_task_id()
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    source_grant = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_COPY,
        path=source,
        scope=tmp_path,
    )
    destination_grant = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_COPY,
        path=destination,
        scope=tmp_path,
        constraints=ConstraintSet(overwrite=False),
    )

    with pytest.raises(FilesystemAuthorizationError):
        executor(broker, evidence).copy(
            task_id=task_id,
            source_grant_id=source_grant,
            destination_grant_id=destination_grant,
            source=str(source),
            destination=str(destination),
            at=NOW,
        )

    assert destination.read_bytes() == b"old"


def test_symlink_source_escape_is_blocked_after_resolution(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("outside")
    link = allowed / "linked-secret.txt"

    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symlink creation is unavailable on this runner")

    task_id = new_task_id()
    broker = CapabilityBroker()
    evidence = EvidenceLedger()

    lexical_request = CapabilityRequest(
        task_id=task_id,
        operation=Operation.FILESYSTEM_READ,
        resource=FilesystemResource(str(link.absolute()), current_path_platform()),
    )
    grant = broker.approve(
        lexical_request,
        approved_by="test-user",
        selector=FilesystemResourceSelector(
            str(allowed.resolve()),
            current_path_platform(),
        ),
        at=NOW,
    )

    with pytest.raises(FilesystemScopeEscapeError):
        executor(broker, evidence).read(
            task_id=task_id,
            grant_id=grant.grant_id,
            path=str(link.absolute()),
            at=NOW,
        )

    assert secret.read_text() == "outside"
    timeline = render_timeline(evidence.snapshot())
    assert "resolved_scope_escape" in timeline


def test_symlink_destination_parent_escape_is_blocked(tmp_path: Path) -> None:
    link_is_directory = os.name == "nt"

    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    source = allowed / "source.txt"
    source.write_text("payload")
    link_dir = allowed / "escape"

    try:
        link_dir.symlink_to(outside, target_is_directory=link_is_directory)
    except OSError:
        pytest.skip("symlink creation is unavailable on this runner")

    destination = link_dir / "copied.txt"
    task_id = new_task_id()
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    source_grant = approve(
        broker,
        task_id=task_id,
        operation=Operation.FILESYSTEM_COPY,
        path=source,
        scope=allowed,
    )

    lexical_destination_request = CapabilityRequest(
        task_id=task_id,
        operation=Operation.FILESYSTEM_COPY,
        resource=FilesystemResource(str(destination.absolute()), current_path_platform()),
    )
    destination_grant = broker.approve(
        lexical_destination_request,
        approved_by="test-user",
        selector=FilesystemResourceSelector(
            str(allowed.resolve()),
            current_path_platform(),
        ),
        at=NOW,
    )

    with pytest.raises(FilesystemScopeEscapeError):
        executor(broker, evidence).copy(
            task_id=task_id,
            source_grant_id=source_grant,
            destination_grant_id=destination_grant.grant_id,
            source=str(source),
            destination=str(destination.absolute()),
            at=NOW,
        )

    assert not (outside / "copied.txt").exists()


def test_grant_bound_to_another_task_cannot_execute(tmp_path: Path) -> None:
    file_path = tmp_path / "invoice.txt"
    file_path.write_text("payload")
    first_task = new_task_id()
    second_task = new_task_id()
    broker = CapabilityBroker()
    evidence = EvidenceLedger()
    grant_id = approve(
        broker,
        task_id=first_task,
        operation=Operation.FILESYSTEM_READ,
        path=file_path,
        scope=tmp_path,
    )

    with pytest.raises(FilesystemAuthorizationError):
        executor(broker, evidence).read(
            task_id=second_task,
            grant_id=grant_id,
            path=str(file_path),
            at=NOW,
        )


def test_executor_uses_host_path_semantics() -> None:
    platform = current_path_platform()
    if os.name == "nt":
        assert platform is PathPlatform.WINDOWS
    else:
        assert platform is PathPlatform.POSIX

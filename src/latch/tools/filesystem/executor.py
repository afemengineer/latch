"""Trusted filesystem executor.

The executor resolves filesystem objects authoritatively, re-checks the resolved
resources against concrete grants, atomically reserves grant usage, performs the
operation, and invokes an independent verifier before reporting success.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from latch.core.capabilities import (
    CapabilityRequest,
    FilesystemResource,
    GrantUse,
)
from latch.core.evidence import EvidenceKind, EvidenceLedger
from latch.core.ids import GrantId, TaskId
from latch.core.information_flow import DataRef, join_labels
from latch.core.policy import CapabilityBroker
from latch.core.types import DataLabel, Operation, PathPlatform
from latch.tools.filesystem.labels import FilesystemLabelStore
from latch.tools.filesystem.models import (
    FileInspection,
    FilesystemAuthorizationError,
    FilesystemOperationError,
    FilesystemScopeEscapeError,
    FilesystemVerificationError,
    LabeledBytes,
    MutationResult,
)
from latch.tools.filesystem.resolution import (
    current_path_platform,
    resolve_destination,
    resolve_existing,
)
from latch.tools.filesystem.verification import (
    FileSnapshot,
    FilesystemVerifier,
    VerificationResult,
)


class FilesystemExecutor:
    def __init__(
        self,
        *,
        broker: CapabilityBroker,
        evidence: EvidenceLedger,
        labels: FilesystemLabelStore | None = None,
        verifier: FilesystemVerifier | None = None,
        platform: PathPlatform | None = None,
    ) -> None:
        chosen_platform = platform or current_path_platform()
        if chosen_platform is not current_path_platform():
            raise ValueError("filesystem executor platform must match the host OS")

        self._broker = broker
        self._evidence = evidence
        self._labels = labels or FilesystemLabelStore()
        self._verifier = verifier or FilesystemVerifier()
        self._platform = chosen_platform

    def inspect(
        self,
        *,
        task_id: TaskId,
        grant_id: GrantId,
        path: str,
        at: datetime | None = None,
    ) -> FileInspection:
        resolved_path, resource = resolve_existing(path, platform=self._platform)
        stat = resolved_path.stat()
        request = CapabilityRequest(
            task_id=task_id,
            operation=Operation.FILESYSTEM_INSPECT,
            resource=resource,
        )
        self._authorize(
            task_id=task_id,
            uses=(GrantUse(grant_id=grant_id, request=request),),
            operation=Operation.FILESYSTEM_INSPECT,
            resources=(resource,),
            at=at,
        )

        label = self._labels.classify(resource)
        result = FileInspection(
            resource=resource,
            label=label,
            is_file=resolved_path.is_file(),
            is_directory=resolved_path.is_dir(),
            size=stat.st_size if resolved_path.is_file() else None,
            modified_ns=stat.st_mtime_ns,
        )
        self._evidence.append(
            task_id=task_id,
            kind=EvidenceKind.EXECUTION_RESULT,
            summary="Filesystem inspection completed",
            details={
                "operation": Operation.FILESYSTEM_INSPECT.value,
                "resource": resource.path,
                "label": label.value,
            },
            at=at,
        )
        return result

    def read(
        self,
        *,
        task_id: TaskId,
        grant_id: GrantId,
        path: str,
        at: datetime | None = None,
    ) -> LabeledBytes:
        resolved_path, resource = resolve_existing(path, platform=self._platform)
        before = self._require_regular_file(resolved_path)
        request = CapabilityRequest(
            task_id=task_id,
            operation=Operation.FILESYSTEM_READ,
            resource=resource,
            bytes_requested=before.size,
        )
        self._authorize(
            task_id=task_id,
            uses=(GrantUse(grant_id=grant_id, request=request),),
            operation=Operation.FILESYSTEM_READ,
            resources=(resource,),
            at=at,
        )

        self._execution_started(task_id, Operation.FILESYSTEM_READ, resource, at)
        payload = resolved_path.read_bytes()
        verification = self._verifier.verify_read(before, payload)
        self._record_verification(
            task_id=task_id,
            operation=Operation.FILESYSTEM_READ,
            result=verification,
            resource=resource,
            at=at,
        )
        if verification is not VerificationResult.PASS:
            raise FilesystemVerificationError(
                f"read verification failed: {verification.value}"
            )

        label = self._labels.classify(resource)
        data_ref = DataRef(
            data_id=f"data_{uuid4().hex}",
            label=label,
            origin=f"filesystem:{resource.path}",
        )
        self._evidence.append(
            task_id=task_id,
            kind=EvidenceKind.EXECUTION_RESULT,
            summary="Filesystem read completed",
            details={
                "operation": Operation.FILESYSTEM_READ.value,
                "resource": resource.path,
                "bytes": len(payload),
                "label": label.value,
            },
            at=at,
        )
        return LabeledBytes(resource=resource, data=payload, ref=data_ref)

    def copy(
        self,
        *,
        task_id: TaskId,
        source_grant_id: GrantId,
        destination_grant_id: GrantId,
        source: str,
        destination: str,
        at: datetime | None = None,
    ) -> MutationResult:
        return self._transfer(
            task_id=task_id,
            source_grant_id=source_grant_id,
            destination_grant_id=destination_grant_id,
            source=source,
            destination=destination,
            operation=Operation.FILESYSTEM_COPY,
            at=at,
        )

    def move(
        self,
        *,
        task_id: TaskId,
        source_grant_id: GrantId,
        destination_grant_id: GrantId,
        source: str,
        destination: str,
        at: datetime | None = None,
    ) -> MutationResult:
        return self._transfer(
            task_id=task_id,
            source_grant_id=source_grant_id,
            destination_grant_id=destination_grant_id,
            source=source,
            destination=destination,
            operation=Operation.FILESYSTEM_MOVE,
            at=at,
        )

    def rename(
        self,
        *,
        task_id: TaskId,
        source_grant_id: GrantId,
        destination_grant_id: GrantId,
        source: str,
        destination: str,
        at: datetime | None = None,
    ) -> MutationResult:
        source_path, source_resource = resolve_existing(source, platform=self._platform)
        destination_path, destination_resource = resolve_destination(
            destination,
            platform=self._platform,
        )
        if source_path.parent != destination_path.parent:
            raise FilesystemOperationError("rename requires source and destination in one directory")

        return self._transfer_resolved(
            task_id=task_id,
            source_grant_id=source_grant_id,
            destination_grant_id=destination_grant_id,
            source_path=source_path,
            source_resource=source_resource,
            destination_path=destination_path,
            destination_resource=destination_resource,
            operation=Operation.FILESYSTEM_RENAME,
            at=at,
        )

    def _transfer(
        self,
        *,
        task_id: TaskId,
        source_grant_id: GrantId,
        destination_grant_id: GrantId,
        source: str,
        destination: str,
        operation: Operation,
        at: datetime | None,
    ) -> MutationResult:
        source_path, source_resource = resolve_existing(source, platform=self._platform)
        destination_path, destination_resource = resolve_destination(
            destination,
            platform=self._platform,
        )
        return self._transfer_resolved(
            task_id=task_id,
            source_grant_id=source_grant_id,
            destination_grant_id=destination_grant_id,
            source_path=source_path,
            source_resource=source_resource,
            destination_path=destination_path,
            destination_resource=destination_resource,
            operation=operation,
            at=at,
        )

    def _transfer_resolved(
        self,
        *,
        task_id: TaskId,
        source_grant_id: GrantId,
        destination_grant_id: GrantId,
        source_path: Path,
        source_resource: FilesystemResource,
        destination_path: Path,
        destination_resource: FilesystemResource,
        operation: Operation,
        at: datetime | None,
    ) -> MutationResult:
        if source_resource == destination_resource:
            raise FilesystemOperationError("source and destination resolve to the same resource")
        if destination_path.exists() and destination_path.is_dir():
            raise FilesystemOperationError("destination must be a file path")

        before = self._require_regular_file(source_path)
        overwrite = destination_path.exists()

        source_request = CapabilityRequest(
            task_id=task_id,
            operation=operation,
            resource=source_resource,
            bytes_requested=before.size,
        )
        destination_request = CapabilityRequest(
            task_id=task_id,
            operation=operation,
            resource=destination_resource,
            bytes_requested=before.size,
            overwrite=overwrite,
        )
        self._authorize(
            task_id=task_id,
            uses=(
                GrantUse(grant_id=source_grant_id, request=source_request),
                GrantUse(grant_id=destination_grant_id, request=destination_request),
            ),
            operation=operation,
            resources=(source_resource, destination_resource),
            at=at,
        )

        self._execution_started(task_id, operation, source_resource, at)
        try:
            if operation is Operation.FILESYSTEM_COPY:
                shutil.copy2(source_path, destination_path)
            elif operation is Operation.FILESYSTEM_MOVE:
                shutil.move(str(source_path), str(destination_path))
            elif operation is Operation.FILESYSTEM_RENAME:
                os.replace(source_path, destination_path)
            else:
                raise FilesystemOperationError(f"unsupported transfer operation: {operation}")
        except OSError as exc:
            self._evidence.append(
                task_id=task_id,
                kind=EvidenceKind.EXECUTION_RESULT,
                summary="Filesystem mutation failed",
                details={
                    "operation": operation.value,
                    "source": source_resource.path,
                    "destination": destination_resource.path,
                    "error_type": type(exc).__name__,
                },
                at=at,
            )
            raise FilesystemOperationError(
                f"filesystem mutation failed: {type(exc).__name__}"
            ) from exc

        if operation is Operation.FILESYSTEM_COPY:
            verification = self._verifier.verify_copy(
                before,
                source_path,
                destination_path,
            )
        else:
            verification = self._verifier.verify_move(
                before,
                source_path,
                destination_path,
            )

        self._record_verification(
            task_id=task_id,
            operation=operation,
            result=verification,
            resource=destination_resource,
            at=at,
        )
        if verification is not VerificationResult.PASS:
            raise FilesystemVerificationError(
                f"{operation.value} verification failed: {verification.value}"
            )

        if operation is Operation.FILESYSTEM_COPY:
            label = self._labels.record_copy(source_resource, destination_resource)
        else:
            label = self._labels.record_move(source_resource, destination_resource)

        data_ref = DataRef(
            data_id=f"data_{uuid4().hex}",
            label=label,
            origin=f"filesystem:{destination_resource.path}",
        )
        self._evidence.append(
            task_id=task_id,
            kind=EvidenceKind.EXECUTION_RESULT,
            summary="Filesystem mutation completed",
            details={
                "operation": operation.value,
                "source": source_resource.path,
                "destination": destination_resource.path,
                "bytes": before.size,
                "label": label.value,
            },
            at=at,
        )
        return MutationResult(
            source=source_resource,
            destination=destination_resource,
            ref=data_ref,
            verified=True,
        )

    def _authorize(
        self,
        *,
        task_id: TaskId,
        uses: tuple[GrantUse, ...],
        operation: Operation,
        resources: tuple[FilesystemResource, ...],
        at: datetime | None,
    ) -> None:
        for use in uses:
            grant = self._broker.get_grant(use.grant_id)
            if grant is None:
                self._authorization_denied(
                    task_id,
                    operation,
                    use.request.resource,
                    "grant_missing",
                    at,
                )
                raise FilesystemAuthorizationError("grant does not exist")

            if not grant.selector.contains(use.request.resource):
                self._authorization_denied(
                    task_id,
                    operation,
                    use.request.resource,
                    "resolved_scope_escape",
                    at,
                )
                raise FilesystemScopeEscapeError(
                    "resolved filesystem target is outside the grant scope"
                )

        if not self._broker.consume_requests(uses, at=at):
            self._authorization_denied(
                task_id,
                operation,
                resources[0],
                "grant_validation_or_constraints_failed",
                at,
            )
            raise FilesystemAuthorizationError(
                "grant validation, expiry, deny policy, or constraints rejected execution"
            )

        self._evidence.append(
            task_id=task_id,
            kind=EvidenceKind.POLICY_DECISION,
            summary="Filesystem authority accepted",
            details={
                "operation": operation.value,
                "resources": len(resources),
                "outcome": "allow",
            },
            at=at,
        )

    def _authorization_denied(
        self,
        task_id: TaskId,
        operation: Operation,
        resource: FilesystemResource,
        reason: str,
        at: datetime | None,
    ) -> None:
        self._evidence.append(
            task_id=task_id,
            kind=EvidenceKind.POLICY_DECISION,
            summary="Filesystem authority denied",
            details={
                "operation": operation.value,
                "resource": resource.path,
                "outcome": "deny",
                "reason": reason,
            },
            at=at,
        )

    def _execution_started(
        self,
        task_id: TaskId,
        operation: Operation,
        resource: FilesystemResource,
        at: datetime | None,
    ) -> None:
        self._evidence.append(
            task_id=task_id,
            kind=EvidenceKind.EXECUTION_STARTED,
            summary="Filesystem execution started",
            details={
                "operation": operation.value,
                "resource": resource.path,
            },
            at=at,
        )

    def _record_verification(
        self,
        *,
        task_id: TaskId,
        operation: Operation,
        result: VerificationResult,
        resource: FilesystemResource,
        at: datetime | None,
    ) -> None:
        self._evidence.append(
            task_id=task_id,
            kind=EvidenceKind.VERIFICATION_RESULT,
            summary="Filesystem postcondition verified"
            if result is VerificationResult.PASS
            else "Filesystem postcondition failed",
            details={
                "operation": operation.value,
                "resource": resource.path,
                "result": result.value,
            },
            at=at,
        )

    def _require_regular_file(self, path: Path) -> FileSnapshot:
        if not path.is_file():
            raise FilesystemOperationError(f"operation requires a regular file: {path}")
        return self._verifier.snapshot(path)


def payload_digest(payload: bytes) -> str:
    """Diagnostic helper kept outside evidence; never logs payload bytes."""

    return sha256(payload).hexdigest()

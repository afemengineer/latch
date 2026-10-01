"""Independent filesystem postcondition verification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path


class VerificationResult(StrEnum):
    PASS = "pass"
    SOURCE_CHANGED = "source_changed"
    SOURCE_STILL_EXISTS = "source_still_exists"
    DESTINATION_MISSING = "destination_missing"
    DESTINATION_NOT_FILE = "destination_not_file"
    CONTENT_MISMATCH = "content_mismatch"


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    path: str
    size: int
    sha256: str
    modified_ns: int


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class FilesystemVerifier:
    """Re-read authoritative state rather than trusting executor return values."""

    def snapshot(self, path: Path) -> FileSnapshot:
        if not path.is_file():
            raise ValueError(f"not a regular file: {path}")
        stat = path.stat()
        return FileSnapshot(
            path=str(path),
            size=stat.st_size,
            sha256=_hash_file(path),
            modified_ns=stat.st_mtime_ns,
        )

    def verify_read(self, before: FileSnapshot, payload: bytes) -> VerificationResult:
        if sha256(payload).hexdigest() != before.sha256:
            return VerificationResult.SOURCE_CHANGED
        return VerificationResult.PASS

    def verify_copy(
        self,
        before: FileSnapshot,
        source: Path,
        destination: Path,
    ) -> VerificationResult:
        if not destination.exists():
            return VerificationResult.DESTINATION_MISSING
        if not destination.is_file():
            return VerificationResult.DESTINATION_NOT_FILE
        if not source.is_file():
            return VerificationResult.SOURCE_CHANGED

        source_after = self.snapshot(source)
        destination_after = self.snapshot(destination)
        if source_after.sha256 != before.sha256 or source_after.size != before.size:
            return VerificationResult.SOURCE_CHANGED
        if (
            destination_after.sha256 != before.sha256
            or destination_after.size != before.size
        ):
            return VerificationResult.CONTENT_MISMATCH
        return VerificationResult.PASS

    def verify_move(
        self,
        before: FileSnapshot,
        source: Path,
        destination: Path,
    ) -> VerificationResult:
        if source.exists():
            return VerificationResult.SOURCE_STILL_EXISTS
        if not destination.exists():
            return VerificationResult.DESTINATION_MISSING
        if not destination.is_file():
            return VerificationResult.DESTINATION_NOT_FILE

        destination_after = self.snapshot(destination)
        if (
            destination_after.sha256 != before.sha256
            or destination_after.size != before.size
        ):
            return VerificationResult.CONTENT_MISMATCH
        return VerificationResult.PASS

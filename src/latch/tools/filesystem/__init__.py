"""Trusted filesystem executor with scope re-resolution and verification."""

from latch.tools.filesystem.executor import FilesystemExecutor
from latch.tools.filesystem.labels import FilesystemLabelStore, PathLabelRule
from latch.tools.filesystem.models import (
    FileInspection,
    FilesystemAuthorizationError,
    FilesystemOperationError,
    FilesystemScopeEscapeError,
    FilesystemVerificationError,
    LabeledBytes,
    MutationResult,
)
from latch.tools.filesystem.resolution import current_path_platform
from latch.tools.filesystem.verification import (
    FileSnapshot,
    FilesystemVerifier,
    VerificationResult,
)

__all__ = [
    "FileInspection",
    "FileSnapshot",
    "FilesystemAuthorizationError",
    "FilesystemExecutor",
    "FilesystemLabelStore",
    "FilesystemOperationError",
    "FilesystemScopeEscapeError",
    "FilesystemVerificationError",
    "FilesystemVerifier",
    "LabeledBytes",
    "MutationResult",
    "PathLabelRule",
    "VerificationResult",
    "current_path_platform",
]

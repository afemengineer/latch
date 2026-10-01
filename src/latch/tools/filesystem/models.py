"""Result and error types for filesystem execution."""

from __future__ import annotations

from dataclasses import dataclass

from latch.core.capabilities import FilesystemResource
from latch.core.information_flow import DataRef
from latch.core.types import DataLabel


class FilesystemOperationError(RuntimeError):
    """Base class for filesystem execution failures."""


class FilesystemAuthorizationError(FilesystemOperationError):
    """The supplied grant(s) did not authorize the resolved operation."""


class FilesystemScopeEscapeError(FilesystemAuthorizationError):
    """Lexical path resolved to a resource outside the grant selector."""


class FilesystemVerificationError(FilesystemOperationError):
    """Independent postcondition verification failed."""


@dataclass(frozen=True, slots=True)
class FileInspection:
    resource: FilesystemResource
    label: DataLabel
    is_file: bool
    is_directory: bool
    size: int | None
    modified_ns: int


@dataclass(frozen=True, slots=True)
class LabeledBytes:
    """Payload plus mandatory IFC metadata at the tool boundary."""

    resource: FilesystemResource
    data: bytes
    ref: DataRef


@dataclass(frozen=True, slots=True)
class MutationResult:
    source: FilesystemResource
    destination: FilesystemResource
    ref: DataRef
    verified: bool

"""Authoritative path resolution for filesystem executors."""

from __future__ import annotations

import os
from pathlib import Path

from latch.core.capabilities import FilesystemResource
from latch.core.types import PathPlatform
from latch.tools.filesystem.models import FilesystemOperationError


def current_path_platform() -> PathPlatform:
    return PathPlatform.WINDOWS if os.name == "nt" else PathPlatform.POSIX


def resolve_existing(
    raw_path: str,
    *,
    platform: PathPlatform,
) -> tuple[Path, FilesystemResource]:
    """Resolve an existing path through symlinks/junctions/reparse targets."""

    lexical = FilesystemResource(raw_path, platform)
    path = Path(lexical.path)

    try:
        resolved_path = path.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise FilesystemOperationError(f"cannot resolve existing path: {raw_path}") from exc

    resolved = FilesystemResource(str(resolved_path), platform)
    return resolved_path, resolved


def resolve_destination(
    raw_path: str,
    *,
    platform: PathPlatform,
) -> tuple[Path, FilesystemResource]:
    """Resolve the authoritative destination target.

    Existing final symlinks/reparse points are followed. For a missing final
    component, the parent is resolved strictly and the requested basename is
    appended to that authoritative parent.
    """

    lexical = FilesystemResource(raw_path, platform)
    path = Path(lexical.path)

    try:
        if path.exists() or path.is_symlink():
            resolved_path = path.resolve(strict=True)
        else:
            resolved_parent = path.parent.resolve(strict=True)
            if not resolved_parent.is_dir():
                raise FilesystemOperationError(
                    f"destination parent is not a directory: {raw_path}"
                )
            resolved_path = resolved_parent / path.name
    except FilesystemOperationError:
        raise
    except (FileNotFoundError, OSError) as exc:
        raise FilesystemOperationError(f"cannot resolve destination path: {raw_path}") from exc

    resolved = FilesystemResource(str(resolved_path), platform)
    return resolved_path, resolved

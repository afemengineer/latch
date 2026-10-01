"""Filesystem resources and lexical selectors.

This module deliberately performs *lexical* containment only. A future filesystem
executor MUST resolve and re-check the authoritative on-disk target before access,
including symlink/reparse-point handling. Policy matching alone is not a filesystem
sandbox.
"""

from __future__ import annotations

import fnmatch
import ntpath
import posixpath
from dataclasses import dataclass

from latch.core.types import PathPlatform


def _normalize_windows(path: str) -> str:
    if "\x00" in path:
        raise ValueError("filesystem paths cannot contain NUL")

    path = path.replace("/", "\\")
    folded = path.casefold()
    if folded.startswith("\\\\?\\") or folded.startswith("\\\\.\\"):
        raise ValueError("Windows device/extended paths are not supported in V0")

    normalized = ntpath.normpath(path)
    drive, tail = ntpath.splitdrive(normalized)
    if not drive or not tail.startswith("\\"):
        raise ValueError("Windows filesystem resources must be absolute")

    return ntpath.normcase(normalized)


def _normalize_posix(path: str) -> str:
    if "\x00" in path:
        raise ValueError("filesystem paths cannot contain NUL")
    if path.startswith("//"):
        raise ValueError("implementation-defined POSIX // paths are not supported in V0")
    if not posixpath.isabs(path):
        raise ValueError("POSIX filesystem resources must be absolute")
    return posixpath.normpath(path)


def normalize_absolute_path(path: str, platform: PathPlatform) -> str:
    if platform is PathPlatform.WINDOWS:
        return _normalize_windows(path)
    return _normalize_posix(path)


def _normalized_pattern(pattern: str, platform: PathPlatform) -> str:
    normalized = pattern.replace("\\", "/")
    return normalized.casefold() if platform is PathPlatform.WINDOWS else normalized


def _matches_pattern(relative_path: str, pattern: str) -> bool:
    if fnmatch.fnmatchcase(relative_path, pattern):
        return True
    if pattern.startswith("**/"):
        return fnmatch.fnmatchcase(relative_path, pattern[3:])
    return False


@dataclass(frozen=True, slots=True)
class FilesystemResource:
    path: str
    platform: PathPlatform

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_absolute_path(self.path, self.platform))


@dataclass(frozen=True, slots=True)
class FilesystemResourceSelector:
    root: str
    platform: PathPlatform
    recursive: bool = True
    exclude_globs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", normalize_absolute_path(self.root, self.platform))
        object.__setattr__(
            self,
            "exclude_globs",
            tuple(_normalized_pattern(pattern, self.platform) for pattern in self.exclude_globs),
        )

    @classmethod
    def exact(cls, resource: FilesystemResource) -> FilesystemResourceSelector:
        return cls(root=resource.path, platform=resource.platform, recursive=False)

    def contains(self, resource: FilesystemResource) -> bool:
        if resource.platform is not self.platform:
            return False

        path_module = ntpath if self.platform is PathPlatform.WINDOWS else posixpath

        if self.recursive:
            try:
                common = path_module.commonpath((self.root, resource.path))
            except ValueError:
                return False
            if common != self.root:
                return False
        elif resource.path != self.root:
            return False

        relative = (
            ""
            if resource.path == self.root
            else path_module.relpath(resource.path, self.root)
        )
        relative = relative.replace("\\", "/")
        if self.platform is PathPlatform.WINDOWS:
            relative = relative.casefold()

        return not any(_matches_pattern(relative, pattern) for pattern in self.exclude_globs)

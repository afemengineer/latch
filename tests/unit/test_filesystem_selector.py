import pytest

from latch.core.capabilities import FilesystemResource, FilesystemResourceSelector
from latch.core.types import PathPlatform


def test_windows_scope_is_case_insensitive() -> None:
    selector = FilesystemResourceSelector(
        root=r"C:\Users\Demo\Downloads",
        platform=PathPlatform.WINDOWS,
    )
    resource = FilesystemResource(
        path=r"c:\users\demo\DOWNLOADS\Invoice.pdf",
        platform=PathPlatform.WINDOWS,
    )

    assert selector.contains(resource)


def test_windows_parent_traversal_cannot_escape_scope() -> None:
    selector = FilesystemResourceSelector(
        root=r"C:\Users\demo\Downloads",
        platform=PathPlatform.WINDOWS,
    )
    escaped = FilesystemResource(
        path=r"C:\Users\demo\Downloads\..\..\.ssh\id_rsa",
        platform=PathPlatform.WINDOWS,
    )

    assert not selector.contains(escaped)


def test_windows_other_drive_is_denied() -> None:
    selector = FilesystemResourceSelector(
        root=r"C:\Users\demo\Downloads",
        platform=PathPlatform.WINDOWS,
    )
    resource = FilesystemResource(
        path=r"D:\Downloads\invoice.pdf",
        platform=PathPlatform.WINDOWS,
    )

    assert not selector.contains(resource)


def test_exclusion_globs_apply_at_root_and_nested_paths() -> None:
    selector = FilesystemResourceSelector(
        root="/home/demo/project",
        platform=PathPlatform.POSIX,
        exclude_globs=("**/.env", "**/*.key"),
    )

    assert not selector.contains(
        FilesystemResource("/home/demo/project/.env", PathPlatform.POSIX)
    )
    assert not selector.contains(
        FilesystemResource("/home/demo/project/keys/service.key", PathPlatform.POSIX)
    )
    assert selector.contains(
        FilesystemResource("/home/demo/project/readme.txt", PathPlatform.POSIX)
    )


def test_exact_selector_does_not_authorize_children() -> None:
    resource = FilesystemResource("/tmp/invoice.pdf", PathPlatform.POSIX)
    selector = FilesystemResourceSelector.exact(resource)

    assert selector.contains(resource)
    assert not selector.contains(
        FilesystemResource("/tmp/invoice.pdf/child", PathPlatform.POSIX)
    )


def test_relative_paths_are_rejected() -> None:
    with pytest.raises(ValueError, match="absolute"):
        FilesystemResource("relative/file.txt", PathPlatform.POSIX)


def test_windows_device_paths_are_rejected() -> None:
    with pytest.raises(ValueError, match="device/extended"):
        FilesystemResource(r"\\?\C:\Users\demo\file.txt", PathPlatform.WINDOWS)


def test_sibling_with_shared_prefix_is_not_inside_scope() -> None:
    selector = FilesystemResourceSelector(
        root=r"C:\Users\demo\Downloads",
        platform=PathPlatform.WINDOWS,
    )
    resource = FilesystemResource(
        path=r"C:\Users\demo\Downloads_evil\payload.txt",
        platform=PathPlatform.WINDOWS,
    )

    assert not selector.contains(resource)


def test_windows_drive_relative_path_is_rejected() -> None:
    with pytest.raises(ValueError, match="absolute"):
        FilesystemResource(r"C:relative\file.txt", PathPlatform.WINDOWS)

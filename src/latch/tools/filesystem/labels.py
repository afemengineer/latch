"""Deterministic path-label state for filesystem data."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from latch.core.capabilities import FilesystemResource, FilesystemResourceSelector
from latch.core.information_flow import join_labels
from latch.core.types import DataLabel


@dataclass(frozen=True, slots=True)
class PathLabelRule:
    selector: FilesystemResourceSelector
    label: DataLabel


class FilesystemLabelStore:
    """In-memory V0 label state.

    Exact labels preserve sensitivity across Latch-mediated copy/move/rename.
    Persistence is deferred, but lowering is never implicit.
    """

    def __init__(
        self,
        rules: tuple[PathLabelRule, ...] = (),
        *,
        default_label: DataLabel = DataLabel.PRIVATE,
    ) -> None:
        self._rules = rules
        self._default_label = default_label
        self._exact: dict[FilesystemResource, DataLabel] = {}
        self._lock = RLock()

    def classify(self, resource: FilesystemResource) -> DataLabel:
        labels = [self._default_label]
        with self._lock:
            exact = self._exact.get(resource)
            if exact is not None:
                labels.append(exact)
            for rule in self._rules:
                if rule.selector.contains(resource):
                    labels.append(rule.label)
        return join_labels(*labels)

    def set_label(self, resource: FilesystemResource, label: DataLabel) -> DataLabel:
        """Set an exact label without allowing an implicit downgrade."""

        with self._lock:
            current = self.classify(resource)
            effective = join_labels(current, label)
            self._exact[resource] = effective
            return effective

    def record_copy(
        self,
        source: FilesystemResource,
        destination: FilesystemResource,
    ) -> DataLabel:
        source_label = self.classify(source)
        destination_label = self.classify(destination)
        effective = join_labels(source_label, destination_label)
        with self._lock:
            self._exact[destination] = effective
        return effective

    def record_move(
        self,
        source: FilesystemResource,
        destination: FilesystemResource,
    ) -> DataLabel:
        source_label = self.classify(source)
        destination_label = self.classify(destination)
        effective = join_labels(source_label, destination_label)
        with self._lock:
            self._exact.pop(source, None)
            self._exact[destination] = effective
        return effective

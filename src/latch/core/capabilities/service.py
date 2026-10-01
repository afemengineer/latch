"""Exact semantic-service capability resources.

A ServiceResource names a narrow trusted integration such as tavily-search.
It is deliberately not a generic URL/network resource. Data leaving the device
is controlled independently by information-flow policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_SERVICE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class ServiceResource:
    service_id: str

    def __post_init__(self) -> None:
        normalized = self.service_id.strip().casefold()
        if not _SERVICE_ID.fullmatch(normalized):
            raise ValueError("service_id must be a lowercase slug")
        object.__setattr__(self, "service_id", normalized)


@dataclass(frozen=True, slots=True)
class ServiceResourceSelector:
    service_id: str

    def __post_init__(self) -> None:
        normalized = ServiceResource(self.service_id).service_id
        object.__setattr__(self, "service_id", normalized)

    @classmethod
    def exact(cls, resource: ServiceResource) -> ServiceResourceSelector:
        return cls(resource.service_id)

    def contains(self, resource: object) -> bool:
        return (
            isinstance(resource, ServiceResource)
            and resource.service_id == self.service_id
        )

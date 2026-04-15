from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from ..models import Finding, HostResult, build_finding


class BaseCheck(ABC):
    name = "base"

    @staticmethod
    def finding(**kwargs) -> Finding:
        """Provide a single construction path for all emitted findings."""

        return build_finding(**kwargs)

    @abstractmethod
    def run(self, hosts: list[HostResult], target: str) -> Iterable[Finding]:
        raise NotImplementedError

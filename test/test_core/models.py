from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RunSpec:
    case_name: str
    machine_name: str
    scheduler_name: str
    machine: dict[str, Any]
    scheduler: dict[str, Any]
    libvirt: dict[str, Any]
    workload: dict[str, Any]
    config_path: Path
    benchmark: dict[str, Any]


@dataclass(frozen=True)
class CheckResult:
    failures: tuple[str, ...]
    infos: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.failures

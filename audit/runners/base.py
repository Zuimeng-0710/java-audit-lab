from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from ..findings import Finding


@dataclass(slots=True)
class RunnerResult:
    name: str
    available: bool
    success: bool
    findings: list[Finding]
    message: str
    command: list[str] | None = None

    def summary(self) -> dict[str, object]:
        data = asdict(self)
        data.pop("findings")
        data["finding_count"] = len(self.findings)
        return data


class Runner(Protocol):
    name: str

    def run(self, root: Path, work_dir: Path) -> RunnerResult: ...

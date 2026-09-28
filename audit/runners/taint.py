"""taint runner：把框架模型 + 方法内污点追踪包装成扫描器。"""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from ..taint import run_taint
from .base import RunnerResult


class TaintRunner:
    """方法内污点分析。纯静态实现，无需外部工具，永远可用。"""

    name = "taint"

    def __init__(self, progress: bool = False, workers: int | None = None) -> None:
        self._progress = progress
        self._workers = workers

    def run(self, root: Path, work_dir: Path) -> RunnerResult:
        try:
            findings: list[Finding] = run_taint(root, progress=self._progress, workers=self._workers)
        except Exception as exc:  # 分析失败不能让整次扫描崩掉
            return RunnerResult(self.name, True, False, [], f"污点分析失败：{exc}")
        return RunnerResult(
            self.name, True, True, findings,
            f"框架模型污点分析完成，共匹配 {len(findings)} 条待复核发现。",
        )

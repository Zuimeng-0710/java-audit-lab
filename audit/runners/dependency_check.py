from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..importers import parse_dependency_check_json
from .base import RunnerResult


class DependencyCheckRunner:
    name = "dependency-check"

    def run(self, root: Path, work_dir: Path) -> RunnerResult:
        executable = shutil.which("dependency-check") or shutil.which("dependency-check.bat")
        if not executable:
            return RunnerResult(self.name, False, False, [], "未找到 OWASP Dependency-Check；已跳过依赖漏洞检查。")
        output_dir = work_dir / "dependency-check"
        output_dir.mkdir(parents=True, exist_ok=True)
        command = [executable, "--project", root.name, "--scan", str(root), "--format", "JSON", "--out", str(output_dir)]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=1800, check=False)
            report = output_dir / "dependency-check-report.json"
            if completed.returncode not in (0, 1) or not report.exists():
                return RunnerResult(self.name, True, False, [], (completed.stderr or completed.stdout or "Dependency-Check 执行失败")[-1000:], command)
            findings = parse_dependency_check_json(report, root)
            return RunnerResult(self.name, True, True, findings, f"Dependency-Check 完成，共 {len(findings)} 条。", command)
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            return RunnerResult(self.name, True, False, [], f"Dependency-Check 失败：{exc}", command)

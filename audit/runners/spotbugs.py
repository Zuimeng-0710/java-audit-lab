from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..importers import parse_spotbugs_xml
from .base import RunnerResult


class SpotBugsRunner:
    name = "spotbugs"

    def run(self, root: Path, work_dir: Path) -> RunnerResult:
        executable = shutil.which("spotbugs") or shutil.which("spotbugs.bat")
        if not executable:
            return RunnerResult(
                self.name, False, False, [],
                "未找到 SpotBugs CLI；已跳过。可安装 SpotBugs + Find Security Bugs 后接入 XML/SARIF 结果。",
            )
        inputs = [path for path in (root / "target/classes", root / "build/classes/java/main") if path.exists()]
        inputs.extend(root.glob("target/*.jar"))
        inputs.extend(root.glob("build/libs/*.jar"))
        if not inputs:
            return RunnerResult(self.name, True, False, [], "已找到 SpotBugs，但没有已编译 class/JAR；请先构建项目后重试。")
        output = work_dir / "spotbugs.xml"
        command = [executable, "-textui", "-xml:withMessages", "-output", str(output), *map(str, inputs)]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
            if completed.returncode not in (0, 1) or not output.exists():
                return RunnerResult(self.name, True, False, [], (completed.stderr or completed.stdout or "SpotBugs 执行失败")[-1000:], command)
            findings = parse_spotbugs_xml(output, root)
            return RunnerResult(self.name, True, True, findings, f"SpotBugs 完成，共 {len(findings)} 条。", command)
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            return RunnerResult(self.name, True, False, [], f"SpotBugs 失败：{exc}", command)

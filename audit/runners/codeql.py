from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..importers import parse_sarif
from .base import RunnerResult


class CodeQLRunner:
    name = "codeql"

    def run(self, root: Path, work_dir: Path) -> RunnerResult:
        executable = shutil.which("codeql") or shutil.which("codeql.exe")
        if not executable:
            return RunnerResult(self.name, False, False, [], "未找到 CodeQL CLI；已跳过跨文件数据流分析。")
        database = work_dir / "codeql-db"
        sarif = work_dir / "codeql.sarif"
        create = [executable, "database", "create", str(database), "--language=java-kotlin", "--build-mode=none", f"--source-root={root}"]
        analyze = [executable, "database", "analyze", str(database), "java-security-extended.qls", "--format=sarif-latest", f"--output={sarif}", "--threads=0"]
        try:
            first = subprocess.run(create, capture_output=True, text=True, timeout=1800, check=False)
            if first.returncode != 0:
                return RunnerResult(self.name, True, False, [], (first.stderr or first.stdout)[-1200:], create)
            second = subprocess.run(analyze, capture_output=True, text=True, timeout=1800, check=False)
            if second.returncode != 0 or not sarif.exists():
                return RunnerResult(self.name, True, False, [], (second.stderr or second.stdout)[-1200:], analyze)
            findings = parse_sarif(sarif, root)
            return RunnerResult(self.name, True, True, findings, f"CodeQL 完成，共 {len(findings)} 条并保留数据流路径。", analyze)
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            return RunnerResult(self.name, True, False, [], f"CodeQL 失败：{exc}", create)

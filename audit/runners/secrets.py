from __future__ import annotations

import hashlib
import re
from pathlib import Path

from ..findings import Finding, Location
from ..project import iter_config_files
from .base import RunnerResult


_ASSIGNMENT = re.compile(
    r"^\s*[\"']?(?P<key>[A-Za-z0-9_.-]+)[\"']?\s*(?:=|:)\s*[\"']?(?P<value>[^\"'#\s][^#\r\n]*?)[\"']?\s*,?\s*$"
)
_SENSITIVE_KEY = re.compile(
    r"(?:^|[_.-])(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|token)(?:$|[_.-])",
    re.I,
)
_PLACEHOLDER = re.compile(r"^(?:\$\{|\{\{|<|env:|vault:)|(?:example|sample|dummy|changeme|replace[_-]?me|your[_-])", re.I)


def _looks_literal(value: str) -> bool:
    cleaned = value.strip().strip("'\"").rstrip(",").strip()
    if len(cleaned) < 4 or cleaned.lower() in {"null", "none", "true", "false"}:
        return False
    if _PLACEHOLDER.search(cleaned) or "${" in cleaned or "#{" in cleaned:
        return False
    return True


def _scan_config(path: Path, root: Path) -> list[Finding]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    relative = path.relative_to(root).as_posix()
    findings: list[Finding] = []
    for number, line in enumerate(lines, 1):
        match = _ASSIGNMENT.match(line)
        if not match or not _SENSITIVE_KEY.search(match.group("key")) or not _looks_literal(match.group("value")):
            continue
        key = match.group("key")
        identity = f"JAL-CONFIG-SECRET-001:{relative}:{number}:{key.lower()}"
        findings.append(Finding(
            rule_id="JAL-CONFIG-SECRET-001",
            title="配置文件中疑似明文凭据",
            severity="high",
            confidence="medium",
            cwe="CWE-798",
            scanner="secrets",
            location=Location(relative, number, match.start("key") + 1),
            evidence=f"{key}: <redacted>",
            description="敏感配置键使用了字面量。报告已遮盖值，仍需确认它是否为有效凭据。",
            review_steps=["确认该配置是否进入生产环境。", "检查版本历史与构建产物中是否仍有同一凭据。", "若凭据有效，先轮换再清理历史。"],
            remediation="改为环境变量或秘密管理服务，并确保日志、报告和异常不会回显原值。",
            fingerprint=hashlib.sha256(identity.encode()).hexdigest()[:16],
            metadata={"redacted": True, "config_key": key},
        ))
    return findings


class SecretsRunner:
    name = "secrets"

    def __init__(self, progress: bool = False, workers: int | None = None) -> None:
        self._progress = progress
        self._workers = workers

    def run(self, root: Path, work_dir: Path) -> RunnerResult:
        files = list(iter_config_files(root))
        findings = [finding for path in files for finding in _scan_config(path, root)]
        return RunnerResult(self.name, True, True, findings, f"配置凭据扫描完成，共匹配 {len(findings)} 条已脱敏线索。")

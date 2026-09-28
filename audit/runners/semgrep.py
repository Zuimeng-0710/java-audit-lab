from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from ..findings import Finding, Location, normalize_path
from .base import RunnerResult


class SemgrepRunner:
    name = "semgrep"

    def run(self, root: Path, work_dir: Path) -> RunnerResult:
        executable = shutil.which("semgrep")
        if not executable:
            return RunnerResult(self.name, False, False, [], "未找到 semgrep；已跳过。")
        output = work_dir / "semgrep.json"
        local_rules = Path(__file__).resolve().parents[1] / "rules" / "java.yml"
        config = str(local_rules) if local_rules.exists() else "p/java"
        command = [executable, "scan", "--config", config, "--json", "--output", str(output), str(root)]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
            if completed.returncode not in (0, 1) or not output.exists():
                message = (completed.stderr or completed.stdout or "Semgrep 执行失败")[-1000:]
                return RunnerResult(self.name, True, False, [], message, command)
            payload = json.loads(output.read_text(encoding="utf-8"))
            findings = [self._convert(item, root) for item in payload.get("results", [])]
            return RunnerResult(self.name, True, True, findings, f"Semgrep 完成，共 {len(findings)} 条。", command)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            return RunnerResult(self.name, True, False, [], f"Semgrep 解析失败：{exc}", command)

    def _convert(self, item: dict, root: Path) -> Finding:
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
        cwe_value = metadata.get("cwe", "CWE-Unknown")
        if isinstance(cwe_value, list):
            cwe_value = cwe_value[0] if cwe_value else "CWE-Unknown"
        location = item.get("start", {})
        rule_id = item.get("check_id", "semgrep-unknown")
        path = normalize_path(item.get("path", "unknown"), root)
        line = int(location.get("line", 1))
        identity = f"{rule_id}:{path}:{line}"
        message = extra.get("message", "Semgrep 规则匹配")
        import re as _re
        cwe_match = _re.search(r"CWE[-/ ]?(\d+)", str(cwe_value), _re.I)
        cwe = f"CWE-{int(cwe_match.group(1))}" if cwe_match else "CWE-Unknown"
        trace = self._dataflow_trace(extra.get("dataflow_trace"), path, root)
        return Finding(
            rule_id=rule_id,
            title=metadata.get("shortlink") or rule_id,
            severity=severity_map.get(extra.get("severity"), "medium"),
            confidence=str(metadata.get("confidence", "medium")).lower(),
            cwe=cwe,
            scanner=self.name,
            location=Location(path, line, int(location.get("col", 1))),
            evidence=(extra.get("lines") or "").strip()[:500],
            description=message,
            review_steps=["追踪命中表达式使用的数据来源。", "确认危险操作是否在实际运行路径上可达。", "检查现有校验或净化逻辑。"],
            remediation="根据确认的数据流和框架语义选择修复方式；修复后重新扫描。",
            fingerprint=hashlib.sha256(identity.encode()).hexdigest()[:16],
            trace=trace,
            metadata={"semgrep": metadata, "engine_evidence": "semgrep-pro" if trace else "semgrep-oss"},
        )

    def _dataflow_trace(self, dataflow: dict | None, default_path: str, root: Path) -> list[dict]:
        """Semgrep Pro 引擎的污点路径 → 已证明的数据流步骤；OSS 无此字段时返回空。"""
        if not dataflow:
            return []
        trace: list[dict] = []

        def _loc(part: dict, label: str) -> dict:
            start = part.get("location", {}).get("start", {})
            return {
                "kind": "flow",
                "path": normalize_path(part.get("location", {}).get("path", default_path), root),
                "line": int(start.get("line", 1)),
                "label": f"{label}：{str(part.get('content', ''))[:120]}".rstrip("："),
            }

        source = dataflow.get("taint_source")
        if source:
            trace.append(_loc(source, "污点源"))
        for intermediate in dataflow.get("intermediate_vars") or []:
            start = intermediate.get("location", {}).get("start", {})
            trace.append({
                "kind": "flow",
                "path": normalize_path(intermediate.get("location", {}).get("path", default_path), root),
                "line": int(start.get("line", 1)),
                "label": f"传播：{str(intermediate.get('content', ''))[:120]}".rstrip("："),
            })
        sink = dataflow.get("taint_sink")
        if sink:
            step = _loc(sink, "污点终点")
            step["kind"] = "sink"
            trace.append(step)
        return trace

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from . import __version__
from .findings import Finding, Location, normalize_path


SEVERITY_MAP = {
    "critical": "critical", "error": "high", "high": "high",
    "warning": "medium", "medium": "medium", "moderate": "medium",
    "note": "low", "low": "low", "info": "info", "none": "info",
}


def _fingerprint(scanner: str, rule: str, path: str, line: int) -> str:
    return hashlib.sha256(f"{scanner}:{rule}:{path}:{line}".encode()).hexdigest()[:16]


def _severity(value: Any, default: str = "medium") -> str:
    return SEVERITY_MAP.get(str(value or "").lower(), default)


def _interpolate(text: str, arguments: list[Any]) -> str:
    """SARIF 消息用 {0} {1} 占位符引用 arguments，还原完整句子。"""
    for index, value in enumerate(arguments):
        text = text.replace("{" + str(index) + "}", str(value))
    return text


def _cwe_from_rule(rule: dict, result: dict) -> str:
    """按 CodeQL/Semgrep 常见格式提取 CWE：relationships 分类、tags、properties。"""
    for properties in (rule.get("properties", {}), result.get("properties", {})):
        cwe = properties.get("cwe")
        if isinstance(cwe, list) and cwe:
            cwe = cwe[0]
        if cwe:
            match = re.search(r"CWE[-/ ]?(\d+)", str(cwe), re.I)
            if match:
                return f"CWE-{int(match.group(1))}"
    for properties in (rule.get("properties", {}), result.get("properties", {})):
        for tag in properties.get("tags") or []:
            match = re.search(r"cwe[-/]?(\d+)", str(tag), re.I)
            if match:
                return f"CWE-{int(match.group(1))}"
    for relationship in rule.get("relationships") or []:
        target_id = str((relationship.get("target") or {}).get("id", ""))
        match = re.search(r"cwe[-/]?(\d+)", target_id, re.I)
        if match:
            return f"CWE-{int(match.group(1))}"
    return "CWE-Unknown"


def _severity_from_result(result: dict, rule: dict) -> str:
    """CodeQL 用 security-severity（CVSS 分值）表达风险，优先于 level。"""
    security_severity = (result.get("properties") or {}).get("security-severity") or (rule.get("properties") or {}).get("security-severity")
    if security_severity is not None:
        try:
            score = float(security_severity)
        except (TypeError, ValueError):
            score = -1.0
        if score >= 0:
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score >= 1.0:
                return "low"
            return "info"
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return _severity(level)


def parse_sarif(path: Path, root: Path) -> list[Finding]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    findings: list[Finding] = []
    for run in payload.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        scanner = driver.get("name", "sarif")
        rules = {rule.get("id"): rule for rule in driver.get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            properties = rule.get("properties", {}) | result.get("properties", {})
            location_data = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            artifact = location_data.get("artifactLocation", {}).get("uri", "unknown")
            region = location_data.get("region", {})
            line = int(region.get("startLine", 1))
            relative = normalize_path(artifact, root)
            raw_message = result.get("message", {})
            message = _interpolate(
                raw_message.get("text", rule.get("shortDescription", {}).get("text", rule_id)),
                raw_message.get("arguments") or [],
            )
            cwe = _cwe_from_rule(rule, result)
            flows: list[dict[str, Any]] = []
            for code_flow in result.get("codeFlows", []):
                for thread_flow in code_flow.get("threadFlows", []):
                    for step in thread_flow.get("locations", []):
                        loc = step.get("location", {})
                        physical = loc.get("physicalLocation", {})
                        step_region = physical.get("region", {})
                        flows.append({
                            "kind": "flow",
                            "path": normalize_path(physical.get("artifactLocation", {}).get("uri", artifact), root),
                            "line": int(step_region.get("startLine", 1)),
                            "label": _interpolate(loc.get("message", {}).get("text", "数据流步骤"), loc.get("message", {}).get("arguments") or []),
                        })
            for related in result.get("relatedLocations", []):
                physical = related.get("physicalLocation", {})
                step_region = physical.get("region", {})
                flows.append({
                    "kind": "related",
                    "path": normalize_path(physical.get("artifactLocation", {}).get("uri", artifact), root),
                    "line": int(step_region.get("startLine", 1)),
                    "label": _interpolate(related.get("message", {}).get("text", "相关位置"), related.get("message", {}).get("arguments") or []),
                })
            suppressions = result.get("suppressions") or []
            evidence_against = [
                f"引擎报告抑制（{item.get('kind', 'unknown')}）"
                + (f"：{item.get('justification')}" if item.get("justification") else "")
                for item in suppressions
            ]
            findings.append(Finding(
                rule_id=rule_id,
                title=rule.get("shortDescription", {}).get("text", rule_id),
                severity=_severity_from_result(result, rule),
                confidence=str(properties.get("precision", "medium")).lower(),
                cwe=cwe, scanner=scanner,
                location=Location(relative, line, int(region.get("startColumn", 1)), region.get("endLine")),
                evidence=message, description=message,
                review_steps=["沿 SARIF 数据流逐步确认输入来源。", "检查路径中的净化与权限控制。", "确认危险操作在真实配置下可达。"],
                remediation="依据规则说明修复，并对同一数据流重新扫描。",
                fingerprint=(result.get("partialFingerprints") or {}).get("primaryLocationLineHash") or _fingerprint(scanner, rule_id, relative, line),
                trace=flows, evidence_against=evidence_against,
                metadata={
                    "source_format": "sarif",
                    "properties": properties,
                    "suppressions": suppressions,
                    "help_uri": rule.get("helpUri"),
                },
            ))
    return findings


def parse_spotbugs_xml(path: Path, root: Path) -> list[Finding]:
    raw = path.read_bytes()
    declaration = re.match(br"\s*<\?xml[^>]*encoding=[\"']([^\"']+)", raw, re.I)
    encoding = declaration.group(1).decode("ascii", errors="replace") if declaration else "utf-8"
    document = ET.fromstring(raw.decode(encoding, errors="replace"))
    findings: list[Finding] = []
    cwe_map = {"SQL_INJECTION": "CWE-89", "COMMAND_INJECTION": "CWE-78", "PATH_TRAVERSAL": "CWE-22", "XXE": "CWE-611", "HARD_CODE_PASSWORD": "CWE-798"}
    for bug in document.findall(".//BugInstance"):
        rule_id = bug.get("type", "spotbugs-unknown")
        source = bug.find(".//SourceLine[@primary='true']")
        if source is None:
            source = bug.find(".//SourceLine")
        raw_path = source.get("sourcepath", "unknown") if source is not None else "unknown"
        line = int(source.get("start", "1")) if source is not None else 1
        candidates = (root / raw_path, root / "src/main/java" / raw_path, root / "src/test/java" / raw_path)
        resolved_source = next((candidate for candidate in candidates if candidate.exists()), Path(raw_path))
        relative = normalize_path(resolved_source, root)
        long_message = bug.findtext("LongMessage") or bug.findtext("ShortMessage") or rule_id
        rank = int(bug.get("rank", "15"))
        severity = "critical" if rank <= 4 else "high" if rank <= 9 else "medium" if rank <= 14 else "low"
        cwe = f"CWE-{bug.get('cweid')}" if bug.get("cweid") else next((value for key, value in cwe_map.items() if key in rule_id.upper()), "CWE-Unknown")
        findings.append(Finding(
            rule_id=rule_id, title=bug.findtext("ShortMessage") or rule_id, severity=severity,
            confidence="medium", cwe=cwe, scanner="spotbugs", location=Location(relative, line),
            evidence=long_message, description=long_message,
            review_steps=["打开字节码对应的源码位置。", "确认报告描述的执行条件是否成立。", "检查框架或调用方是否已有保护。"],
            remediation="参考 Find Security Bugs 对该类型的修复建议，并添加回归测试。",
            fingerprint=_fingerprint("spotbugs", rule_id, relative, line), metadata={"rank": rank, "category": bug.get("category")},
        ))
    return findings


def parse_dependency_check_json(path: Path, root: Path) -> list[Finding]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    findings: list[Finding] = []
    for dependency in payload.get("dependencies", []):
        dep_name = dependency.get("fileName") or dependency.get("filePath", "dependency")
        for vuln in dependency.get("vulnerabilities", []) or []:
            rule_id = vuln.get("name", "CVE-Unknown")
            cwes = vuln.get("cwes") or []
            cwe = cwes[0] if cwes else "CWE-1104"
            evidence = f"{dep_name} · {rule_id} · CVSS {vuln.get('cvssv3', {}).get('baseScore', vuln.get('cvssv2', {}).get('score', '未知'))}"
            findings.append(Finding(
                rule_id=rule_id, title=f"依赖漏洞：{rule_id}", severity=_severity(vuln.get("severity"), "high"),
                confidence="high", cwe=cwe, scanner="dependency-check", location=Location(dep_name, 1),
                evidence=evidence, description=vuln.get("description", "依赖包含公开披露的安全漏洞。")[:1200],
                review_steps=["确认实际解析到的依赖版本。", "检查漏洞影响的类或方法是否被调用。", "核对厂商公告、修复版本和缓解措施。"],
                remediation="升级到已修复版本；无法升级时评估可达性并记录临时缓解措施。",
                fingerprint=_fingerprint("dependency-check", rule_id, dep_name, 1), metadata={"dependency": dep_name, "references": vuln.get("references", [])[:10]},
            ))
    return findings


def write_sarif(path: Path, findings: list[Finding]) -> Path:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    for finding in findings:
        rules.setdefault(finding.rule_id, {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "properties": {"tags": [finding.cwe, "security"], "precision": finding.confidence},
        })
        result: dict[str, Any] = {
            "ruleId": finding.rule_id, "level": level_map.get(finding.severity, "warning"),
            "message": {"text": finding.description},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.location.path}, "region": {"startLine": finding.location.line, "startColumn": finding.location.column}}}],
            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
            "properties": {
                "scanner": finding.scanner,
                "cwe": finding.cwe,
                "reviewPriority": finding.review_priority,
                "priorityFactors": finding.priority_factors,
                "corroboratingScanners": finding.metadata.get("scanners", [finding.scanner]),
            },
        }
        if finding.trace:
            result["codeFlows"] = [{"threadFlows": [{"locations": [{"location": {"physicalLocation": {"artifactLocation": {"uri": step.get("path", finding.location.path)}, "region": {"startLine": step.get("line", 1)}}, "message": {"text": step.get("label", "数据流步骤")}}} for step in finding.trace]}]}]
        results.append(result)
    payload = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Java Audit Lab", "version": __version__, "rules": list(rules.values())}}, "results": results}]}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path

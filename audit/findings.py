from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(slots=True)
class Location:
    path: str
    line: int = 1
    column: int = 1
    end_line: int | None = None


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    scanner: str
    location: Location
    evidence: str
    description: str
    review_steps: list[str]
    remediation: str
    status: str = "unreviewed"
    fingerprint: str = ""
    trace: list[dict[str, Any]] = field(default_factory=list)
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    review_priority: int = 0
    priority_factors: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


TRACE_PROVEN_KINDS = {"flow"}
TRACE_INFERRED_KINDS = {"source-candidate", "parameter-candidate", "propagation-candidate"}
DYNAMIC_CALL_HINT = "dynamic"


def assess_path(finding: Finding) -> None:
    """Classify the call-chain evidence of a finding without inventing steps.

    Conclusion levels:
    - proven:   scanner-grade data flow (e.g. CodeQL/SARIF codeFlows) reaches the sink
    - inferred: only conservative same-file candidates connect source to sink
    - missing:  no usable path evidence at all
    - unresolved: dynamic dispatch/reflection sits on the only available path
    """
    proven = sum(1 for step in finding.trace if step.get("kind") in TRACE_PROVEN_KINDS)
    inferred = sum(1 for step in finding.trace if step.get("kind") in TRACE_INFERRED_KINDS)
    has_sink = any(step.get("kind") == "sink" for step in finding.trace)
    if finding.metadata.get("dynamic_call_on_path"):
        conclusion = "unresolved"
    elif proven > 0:
        conclusion = "proven"
    elif inferred > 0 and has_sink:
        conclusion = "inferred"
    else:
        conclusion = "missing"
    finding.metadata["path_assessment"] = {
        "conclusion": conclusion,
        "proven_steps": proven,
        "inferred_steps": inferred,
        "sink_present": has_sink,
        "dynamic_hint": bool(finding.metadata.get("dynamic_call_on_path")),
    }


def generalize_findings(findings: list[Finding]) -> None:
    """Stage 4 pattern generalization: attach sibling locations to every finding.

    Siblings are the same rule family elsewhere in the codebase. Confirming one
    finding should prompt reviewing its siblings first.
    """
    by_rule: dict[str, list[Finding]] = {}
    by_cwe: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)
        by_cwe.setdefault(finding.cwe, []).append(finding)
    for finding in findings:
        same_rule = [
            {"path": other.location.path, "line": other.location.line, "fingerprint": other.fingerprint}
            for other in by_rule.get(finding.rule_id, [])
            if other.fingerprint != finding.fingerprint
        ][:20]
        same_cwe_count = sum(
            1 for other in by_cwe.get(finding.cwe, [])
            if other.fingerprint != finding.fingerprint and other.rule_id != finding.rule_id
        )
        nearby = [
            {"path": other.location.path, "line": other.location.line, "fingerprint": other.fingerprint}
            for other in by_rule.get(finding.rule_id, [])
            if other.fingerprint != finding.fingerprint
            and other.location.path == finding.location.path
            and abs(other.location.line - finding.location.line) <= 15
        ][:10]
        finding.metadata["generalization"] = {
            "same_rule": same_rule,
            "same_rule_count": len(same_rule),
            "same_cwe_other_rule_count": same_cwe_count,
            "nearby_same_file": nearby,
            "note": "确认本条后，优先复核同规则兄弟位置与同文件邻近写法",
        }


def normalize_path(path: str | Path, root: Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return candidate.as_posix()


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Keep the strongest finding for the same rule and source location."""
    unique: dict[tuple[str, str, int], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.location.path, finding.location.line)
        current = unique.get(key)
        if current is None or SEVERITY_ORDER.get(finding.severity, 99) < SEVERITY_ORDER.get(current.severity, 99):
            unique[key] = finding
    return sorted(
        unique.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 99),
            item.location.path,
            item.location.line,
        ),
    )


def consolidate_findings(findings: list[Finding]) -> list[Finding]:
    """Merge reports that describe the same weakness and location, retaining every scanner as evidence."""
    exact = deduplicate(findings)
    clusters: list[list[Finding]] = []
    for finding in exact:
        match = next((cluster for cluster in clusters if _same_issue(cluster[0], finding)), None)
        if match is None:
            clusters.append([finding])
        else:
            match.append(finding)
    merged = [_merge_cluster(cluster) for cluster in clusters]
    for finding in merged:
        _assign_priority(finding)
    return sorted(merged, key=lambda item: (-item.review_priority, SEVERITY_ORDER.get(item.severity, 99), item.location.path, item.location.line))


def _same_issue(left: Finding, right: Finding) -> bool:
    if left.cwe == "CWE-Unknown" or right.cwe == "CWE-Unknown":
        return False
    return left.cwe == right.cwe and left.location.path == right.location.path and abs(left.location.line - right.location.line) <= 3


def _merge_cluster(cluster: list[Finding]) -> Finding:
    primary = min(cluster, key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), -len(item.trace)))
    scanners = sorted({item.scanner for item in cluster})
    if len(cluster) > 1:
        primary.fingerprint = hashlib.sha256(f"{primary.cwe}:{primary.location.path}:{primary.location.line // 4}".encode()).hexdigest()[:16]
    primary.metadata["corroboration"] = [
        {"scanner": item.scanner, "rule_id": item.rule_id, "line": item.location.line, "evidence": item.evidence[:300]}
        for item in cluster
    ]
    primary.metadata["scanners"] = scanners
    primary.metadata["occurrences"] = len(cluster)
    # 保留最强的路径证据：引擎已证明的数据流（如 CodeQL codeFlows）优先于推测级候选路径，
    # 避免跨引擎合并时把已证明路径降级为推测路径。
    proven_trace = next(
        (item.trace for item in cluster if any(step.get("kind") == "flow" for step in item.trace)),
        None,
    )
    if proven_trace is not None:
        primary.trace = proven_trace
    elif not primary.trace:
        primary.trace = next((item.trace for item in cluster if item.trace), [])
    return primary


def _assign_priority(finding: Finding) -> None:
    factors: list[dict[str, Any]] = []
    severity_points = {"critical": 42, "high": 32, "medium": 20, "low": 10, "info": 3}.get(finding.severity, 10)
    factors.append({"factor": "严重程度", "points": severity_points, "reason": finding.severity})
    confidence_points = {"high": 18, "medium": 11, "low": 4}.get(finding.confidence, 6)
    factors.append({"factor": "规则置信度", "points": confidence_points, "reason": finding.confidence})
    kinds = {step.get("kind") for step in finding.trace}
    reachability_points = 20 if "source-candidate" in kinds and "sink" in kinds else 12 if finding.trace else 0
    factors.append({"factor": "可达性证据", "points": reachability_points, "reason": "存在来源到终点候选路径" if reachability_points == 20 else ("存在局部路径" if reachability_points else "未提供路径")})
    scanner_count = len(finding.metadata.get("scanners", [finding.scanner]))
    corroboration_points = min(15, max(0, scanner_count - 1) * 8)
    factors.append({"factor": "交叉验证", "points": corroboration_points, "reason": f"{scanner_count} 个扫描器"})
    finding.review_priority = min(100, sum(int(item["points"]) for item in factors))
    finding.priority_factors = factors

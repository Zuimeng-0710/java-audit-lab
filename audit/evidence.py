"""统一证据记录：把单一 Finding 的所有证据归并为蓝图定义的统一模型。

结构（对应 Evidence Driven Audit Playbook 阶段 3/6 的证据编排）：
    entry            入口关联状态
    source           已识别的来源候选（输入起点）
    propagation      引擎或候选路径的传播步骤
    sanitizers       已观察到的净化/抑制证据（反证材料）
    sink             危险操作终点
    authorization    身份与权限证据（阶段 B 权限矩阵将填充）
    unresolved_steps 动态调用等无法解析的步骤
    engine_evidence  各引擎对该位置的独立佐证

原则：不发明任何证据。每一项都来自 trace、metadata 或 corroboration 中
已经存在的材料；缺失的部分如实标注为未采集。
"""

from __future__ import annotations

from typing import Any

SOURCE_KINDS = {"source-candidate", "parameter-candidate"}
PROPAGATION_KINDS = {"flow", "propagation-candidate"}
SINK_KINDS = {"sink"}
RELATED_KINDS = {"related"}

_CONCLUSION_LABELS = {
    "proven": "引擎已证明",
    "inferred": "候选推测",
    "missing": "路径缺失",
    "unresolved": "存在未解析调用",
}


def _step_brief(step: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": str(step.get("path", "")),
        "line": int(step.get("line", 1)),
        "label": str(step.get("label", ""))[:200],
        "kind": str(step.get("kind", "")),
    }


def build_evidence_record(finding: Any) -> dict[str, Any]:
    """把 Finding 的 trace / metadata / corroboration 归并为统一证据记录。"""
    metadata: dict[str, Any] = getattr(finding, "metadata", {}) or {}
    trace: list[dict[str, Any]] = list(getattr(finding, "trace", []) or [])
    location = getattr(finding, "location", None)

    source_steps = [s for s in trace if s.get("kind") in SOURCE_KINDS]
    propagation_steps = [s for s in trace if s.get("kind") in PROPAGATION_KINDS]
    sink_steps = [s for s in trace if s.get("kind") in SINK_KINDS]
    related_steps = [s for s in trace if s.get("kind") in RELATED_KINDS]

    entry: dict[str, Any]
    if metadata.get("entry_coverage"):
        entry = {
            "covered": True,
            "note": "位置位于已识别的入口文件（攻击面阶段）",
        }
    else:
        entry = {
            "covered": False,
            "note": "未关联到已识别入口；可能为内部方法或工具类",
        }

    if source_steps:
        source = _step_brief(source_steps[0])
    elif propagation_steps:
        first = _step_brief(propagation_steps[0])
        first["kind"] = "flow-start"
        first["label"] = f"路径首步（引擎数据流起点）：{first['label']}"
        source = first
    else:
        source = {"path": "", "line": 0, "label": "未采集：无来源候选步骤", "kind": "missing"}

    if sink_steps:
        sink = _step_brief(sink_steps[0])
    elif location is not None:
        sink = {
            "path": str(getattr(location, "path", "")),
            "line": int(getattr(location, "line", 1)),
            "label": "规则命中位置（未提供独立终点步骤）",
            "kind": "rule-hit",
        }
    else:
        sink = {"path": "", "line": 0, "label": "未采集", "kind": "missing"}

    sanitizers: list[dict[str, Any]] = []
    for item in metadata.get("sanitizers") or []:
        sanitizers.append({
            "origin": "engine",
            "detail": str(item.get("detail", item))[:200],
            "location": item.get("location"),
        })
    for suppression in metadata.get("suppressions") or []:
        sanitizers.append({
            "origin": "sarif-suppression",
            "detail": str(suppression.get("kind", "unknown"))
            + (f"：{suppression.get('justification')}" if suppression.get("justification") else ""),
            "location": None,
        })

    assessment = metadata.get("path_assessment") or {}
    conclusion = str(assessment.get("conclusion", "missing"))
    unresolved_steps = [
        _step_brief(step) for step in trace
        if str(step.get("kind", "")).startswith("dynamic")
    ]
    if conclusion == "unresolved" and not unresolved_steps:
        unresolved_steps.append({
            "path": str(getattr(location, "path", "") if location else ""),
            "line": int(getattr(location, "line", 1) if location else 0),
            "label": "路径上存在动态调用或反射，当前无法解析",
            "kind": "dynamic-unresolved",
        })

    engine_evidence: list[dict[str, Any]] = []
    for item in metadata.get("corroboration") or []:
        engine_evidence.append({
            "scanner": str(item.get("scanner", "")),
            "rule_id": str(item.get("rule_id", "")),
            "line": int(item.get("line", 1)),
            "path_conclusion": _CONCLUSION_LABELS.get(conclusion, conclusion),
        })

    return {
        "entry": entry,
        "source": source,
        "propagation": [_step_brief(s) for s in propagation_steps],
        "sanitizers": sanitizers,
        "sink": sink,
        "authorization": {
            "status": "未采集",
            "note": "权限矩阵分析尚未覆盖该位置（计划于阶段 B 填充）",
        },
        "unresolved_steps": unresolved_steps,
        "engine_evidence": engine_evidence,
        "related_locations": [_step_brief(s) for s in related_steps],
        "path_conclusion": _CONCLUSION_LABELS.get(conclusion, conclusion),
    }

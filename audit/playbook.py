"""Evidence driven audit playbook: a stage machine with explicit evidence gates.

The playbook answers one question honestly: *which audit stages actually have
evidence, and what is still missing?* Stages are never marked complete by
assertion — only by machine-checkable evidence counts or human review answers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .findings import Finding
from .project import ProjectInfo
from .runners.base import RunnerResult
from .surface import AttackSurface


STAGE_ORDER = ("profile", "surface", "model", "flow", "verify", "generalize", "refute", "conclude", "report")

STAGE_META: dict[str, dict[str, str]] = {
    "profile": {"name": "项目画像", "goal": "识别构建系统、框架、源码规模与依赖清单"},
    "surface": {"name": "入口与信任边界", "goal": "枚举路由、过滤器、消费者、定时任务等外部输入入口"},
    "model": {"name": "Source / Sink 建模", "goal": "为 Java 框架建立输入源与危险终点模型"},
    "flow": {"name": "数据流扫描", "goal": "运行扫描器并生成 Source → Sink 路径证据"},
    "verify": {"name": "成立条件验证", "goal": "对每条线索回答漏洞成立五问并核对证据门槛"},
    "generalize": {"name": "同类模式泛化", "goal": "对每条线索列出同规则、同 CWE 的兄弟位置"},
    "refute": {"name": "反证与绕过检查", "goal": "寻找能够推翻漏洞假设的安全控制与绕过条件"},
    "conclude": {"name": "人工结论", "goal": "复核者给出确认、误报或仍不确定的结论"},
    "report": {"name": "复测与报告", "goal": "与基线对比变化并导出多格式审计报告"},
}


@dataclass(slots=True)
class StageState:
    stage_id: str
    name: str
    goal: str
    status: str  # completed | partial | pending
    evidence: list[str]
    missing: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.stage_id, "name": self.name, "goal": self.goal,
            "status": self.status, "evidence": self.evidence, "missing": self.missing,
        }


def evaluate_playbook(
    project: ProjectInfo,
    surface: AttackSurface,
    runners: list[RunnerResult],
    findings: list[Finding],
    reviews: dict[str, dict[str, str]],
    baseline: dict[str, object],
    output_formats: list[str],
    authz: object | None = None,
) -> dict[str, Any]:
    stages = [
        _stage_profile(project),
        _stage_surface(project, surface, authz),
        _stage_model(runners),
        _stage_flow(runners, findings),
        _stage_verify(findings, reviews),
        _stage_generalize(findings),
        _stage_refute(surface, findings, reviews),
        _stage_conclude(findings, reviews),
        _stage_report(baseline, output_formats),
    ]
    completed = sum(1 for stage in stages if stage.status == "completed")
    partial = sum(1 for stage in stages if stage.status == "partial")
    return {
        "version": 1,
        "title": "Evidence Driven Audit Playbook",
        "stages": [stage.to_dict() for stage in stages],
        "progress": {"completed": completed, "partial": partial, "pending": len(stages) - completed - partial, "total": len(stages)},
        "guidance": "阶段状态只由可机器核验的证据或人工回答驱动；『部分完成』表示该阶段存在证据但仍有缺口，需要人工补齐。",
    }


def _stage_profile(project: ProjectInfo) -> StageState:
    evidence, missing = [], []
    if project.java_files > 0:
        evidence.append(f"{project.java_files} 个 Java 源文件")
    else:
        missing.append("未找到 Java 源文件，无法建立项目画像")
    if project.build_system != "plain-java":
        evidence.append(f"构建系统 {project.build_system}（{', '.join(project.manifests)}）")
    else:
        missing.append("未发现 pom.xml 或 build.gradle，依赖清单未知")
    if project.frameworks:
        evidence.append(f"识别框架：{', '.join(project.frameworks)}")
    else:
        missing.append("未从构建清单识别出常见框架，Source/Sink 模型覆盖度有限")
    return StageState("profile", STAGE_META["profile"]["name"], STAGE_META["profile"]["goal"],
                      "completed" if project.java_files > 0 and project.build_system != "plain-java" else "partial",
                      evidence, missing)


def _stage_surface(project: ProjectInfo, surface: AttackSurface, authz: object | None = None) -> StageState:
    evidence, missing = [], []
    grouped = surface.entries_by_kind()
    for kind, items in sorted(grouped.items()):
        evidence.append(f"{len(items)} 个 {kind} 入口")
    if surface.controls:
        evidence.append(f"{len(surface.controls)} 个安全控制信号（用于反证检查）")
    if project.java_files > 0 and not surface.entries:
        missing.append("有 Java 源文件但未发现任何入口：可能不是 Web/服务端项目，或入口写法不在模型内")
    if surface.dynamic_calls:
        missing.append(f"{len(surface.dynamic_calls)} 处反射/动态调用无法静态解析，需要人工确认调用目标")
    coverage = getattr(authz, "coverage", None) if authz is not None else None
    if isinstance(coverage, dict) and coverage.get("endpoints"):
        evidence.append(
            f"权限矩阵：{coverage.get('endpoints')} 个端点，权限已证明 {coverage.get('proven')} 个"
            f"（{coverage.get('confirmed_ratio')}%），配置规则 {coverage.get('rules')} 条"
        )
        if coverage.get("missing"):
            missing.append(f"{coverage.get('missing')} 个端点未找到权限声明，需要人工确认认证与授权状态")
        if coverage.get("anonymous"):
            missing.append(f"{coverage.get('anonymous')} 个端点显式允许匿名访问，需确认是否有意开放")
        if coverage.get("unprotected_high_risk"):
            missing.append(f"{coverage.get('unprotected_high_risk')} 个端点存在危险操作但身份要求为匿名或未知")
    status = "completed" if surface.entries else ("partial" if project.java_files > 0 else "pending")
    return StageState("surface", STAGE_META["surface"]["name"], STAGE_META["surface"]["goal"], status, evidence, missing)


def _stage_model(runners: list[RunnerResult]) -> StageState:
    evidence, missing = [], []
    builtin = next((item for item in runners if item.name == "builtin"), None)
    if builtin is not None and builtin.success:
        evidence.append("内置 Java 教学规则已加载（SQL/命令/路径/XXE/凭据/反序列化/SSRF/表达式/弱哈希）")
    if any(item.name == "semgrep" and item.success for item in runners):
        evidence.append("Semgrep Java 规则已加载")
    if any(item.name == "codeql" and item.success for item in runners):
        evidence.append("CodeQL Java 安全查询已加载")
    if builtin is None or not builtin.success:
        missing.append("内置规则未运行，Source/Sink 建模缺失")
    if not any(item.name == "codeql" and item.success for item in runners):
        missing.append("CodeQL 未运行：跨文件数据流建模较弱，路径多为推测级证据")
    return StageState("model", STAGE_META["model"]["name"], STAGE_META["model"]["goal"],
                      "completed" if builtin is not None and builtin.success else "partial", evidence, missing)


def _stage_flow(runners: list[RunnerResult], findings: list[Finding]) -> StageState:
    evidence, missing = [], []
    successful = [item for item in runners if item.success]
    for item in successful:
        evidence.append(f"{item.name} 完成，产生 {len(item.findings)} 条线索")
    failed = [item for item in runners if item.available and not item.success]
    for item in failed:
        missing.append(f"{item.name} 运行失败：{item.message}")
    if not successful:
        missing.append("没有任何扫描器成功运行，无数据流证据")
    with_traces = sum(1 for finding in findings if finding.trace)
    proven = sum(1 for finding in findings if finding.metadata.get("path_assessment", {}).get("proven_steps"))
    if findings:
        evidence.append(f"{with_traces}/{len(findings)} 条线索带有路径证据（其中 {proven} 条含扫描器级数据流）")
        if with_traces < len(findings):
            missing.append(f"{len(findings) - with_traces} 条线索缺少任何路径证据")
    status = "completed" if successful else "pending"
    if successful and with_traces < len(findings):
        status = "partial"
    return StageState("flow", STAGE_META["flow"]["name"], STAGE_META["flow"]["goal"], status, evidence, missing)


def _stage_verify(findings: list[Finding], reviews: dict[str, dict[str, str]]) -> StageState:
    evidence, missing = [], []
    if not findings:
        return StageState("verify", STAGE_META["verify"]["name"], STAGE_META["verify"]["goal"], "completed",
                          ["没有待验证线索"], [])
    answers = 0
    total_questions = 0
    for finding in findings:
        review = reviews.get(finding.fingerprint, {})
        answered = sum(1 for question in ("entry", "identity", "dataflow", "controls", "gap") if review.get("answers", {}).get(question))
        total_questions += 5
        answers += answered
    entries = _surface_entry_coverage(findings)
    if entries:
        evidence.append(f"{entries}/{len(findings)} 条线索在文件附近发现入口证据")
    else:
        missing.append("多数线索附近未发现入口（Controller/参数注解），入口与权限依赖人工确认")
    assessment_counts = {"proven": 0, "inferred": 0, "missing": 0}
    for finding in findings:
        assessment = finding.metadata.get("path_assessment", {})
        level = assessment.get("conclusion", "missing")
        assessment_counts[level if level in assessment_counts else "missing"] += 1
    evidence.append(f"路径证据等级：已证明 {assessment_counts['proven']} / 推测 {assessment_counts['inferred']} / 缺失 {assessment_counts['missing']}")
    if answers == 0:
        missing.append("五问尚未回答任何一条线索；所有结论都停留在『待复核』")
    else:
        evidence.append(f"五问已回答 {answers}/{total_questions} 项")
    status = "partial" if answers < total_questions else "completed"
    if answers == 0 and not entries:
        status = "partial"
    return StageState("verify", STAGE_META["verify"]["name"], STAGE_META["verify"]["goal"], status, evidence, missing)


def _surface_entry_coverage(findings: list[Finding]) -> int:
    coverage = 0
    for finding in findings:
        if finding.metadata.get("entry_coverage"):
            coverage += 1
    return coverage


def _stage_generalize(findings: list[Finding]) -> StageState:
    evidence, missing = [], []
    generalized = 0
    siblings = 0
    for finding in findings:
        generalization = finding.metadata.get("generalization")
        if generalization is not None:
            generalized += 1
            siblings += len(generalization.get("same_rule", []))
    if findings:
        evidence.append(f"{generalized}/{len(findings)} 条线索已生成同类模式清单")
        if siblings:
            evidence.append(f"共标记 {siblings} 处同规则兄弟位置，确认一条后应优先复核其余")
    else:
        evidence.append("无待泛化线索")
    if generalized < len(findings):
        missing.append("部分线索缺少同类模式泛化结果")
    return StageState("generalize", STAGE_META["generalize"]["name"], STAGE_META["generalize"]["goal"],
                      "completed" if findings and generalized == len(findings) else ("partial" if generalized else "completed"), evidence, missing)


def _stage_refute(surface: AttackSurface, findings: list[Finding], reviews: dict[str, dict[str, str]]) -> StageState:
    evidence, missing = [], []
    kinds = {control.kind for control in surface.controls}
    for kind in sorted(kinds):
        evidence.append(f"发现安全控制信号：{kind}")
    checked = sum(1 for finding in findings if reviews.get(finding.fingerprint, {}).get("answers", {}).get("controls"))
    if findings and checked:
        evidence.append(f"{checked}/{len(findings)} 条线索完成反证核对")
    else:
        missing.append("尚无线索完成反证核对；请逐条检查『能够推翻假设』清单")
    if surface.dynamic_calls:
        missing.append(f"{len(surface.dynamic_calls)} 处动态调用未解析，可能存在绕过路径")
    status = "completed" if checked == len(findings) and findings else ("partial" if surface.controls or checked else "partial")
    if not findings:
        status = "completed"
    return StageState("refute", STAGE_META["refute"]["name"], STAGE_META["refute"]["goal"], status, evidence, missing)


def _stage_conclude(findings: list[Finding], reviews: dict[str, dict[str, str]]) -> StageState:
    evidence, missing = [], []
    if not findings:
        return StageState("conclude", STAGE_META["conclude"]["name"], STAGE_META["conclude"]["goal"], "completed",
                          ["没有需要人工结论的线索"], [])
    reviewed = sum(1 for finding in findings if reviews.get(finding.fingerprint, {}).get("verdict"))
    confirmed = sum(1 for finding in findings if reviews.get(finding.fingerprint, {}).get("verdict") == "confirmed")
    evidence.append(f"已给出结论 {reviewed}/{len(findings)} 条（其中确认漏洞 {confirmed} 条）")
    if reviewed < len(findings):
        missing.append(f"{len(findings) - reviewed} 条线索尚未复核")
    return StageState("conclude", STAGE_META["conclude"]["name"], STAGE_META["conclude"]["goal"],
                      "completed" if reviewed == len(findings) else "partial", evidence, missing)


def _stage_report(baseline: dict[str, object], output_formats: list[str]) -> StageState:
    evidence, missing = [], []
    for fmt in output_formats:
        evidence.append(f"{fmt} 报告已生成")
    if baseline.get("enabled"):
        evidence.append(f"基线对比完成：新增 {len(baseline.get('new', []))}，已修复 {len(baseline.get('fixed', []))}")
    else:
        missing.append("没有基线报告，无法对比新增/已修复；建议保存本次报告作为下一轮基线")
    return StageState("report", STAGE_META["report"]["name"], STAGE_META["report"]["goal"],
                      "completed" if output_formats else "partial", evidence, missing)

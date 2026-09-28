from __future__ import annotations

import argparse
import atexit
import json
import platform
import shutil
import sys
import tempfile
from pathlib import Path

from . import __version__
from .ai import config_from_env, explain_with_ai
from .authz import collect_authorization, link_findings_to_endpoints
from .baseline import compare_with_baseline, load_reviews
from .benchmark import run_benchmark
from .cache import load_cached, project_digest, save_cached
from .config import discover_config, load_config
from .diff import (
    analyze_incremental,
    build_old_snapshot,
    build_revision_snapshot,
    collect_diff,
    compare_authorization,
    load_baseline_details,
    needs_revision_snapshot,
)
from .evidence import build_evidence_record
from .findings import SEVERITY_ORDER, assess_path, consolidate_findings, generalize_findings
from .importers import parse_dependency_check_json, parse_sarif, parse_spotbugs_xml
from .playbook import evaluate_playbook
from .project import detect_project, source_scope
from .report import write_reports
from .runners import BuiltinRunner, CodeQLRunner, DependencyCheckRunner, SecretsRunner, SemgrepRunner, SpotBugsRunner, TaintRunner
from .runners.base import RunnerResult
from .surface import collect_surface


RUNNERS = {"builtin": BuiltinRunner, "secrets": SecretsRunner, "taint": TaintRunner, "semgrep": SemgrepRunner, "spotbugs": SpotBugsRunner, "dependency-check": DependencyCheckRunner, "codeql": CodeQLRunner}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="java-audit", description="面向 Java 学习者的可复核代码审计练习工具")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="扫描 Java 项目并生成 JSON、SARIF 和学习报告")
    scan.add_argument("target", help="Java 项目目录")
    scan.add_argument("-o", "--output", default="audit-report", help="报告目录")
    scan.add_argument("--scanners", help="逗号分隔的扫描器列表；默认读取项目配置")
    scan.add_argument("--config", help=".java-audit.yml 或 JSON 配置路径")
    scan.add_argument("--no-cache", action="store_true", help="禁用增量扫描缓存")
    scan.add_argument("--sarif", action="append", default=[], help="额外导入 SARIF，可重复使用")
    scan.add_argument("--spotbugs-xml", action="append", default=[], help="导入已有 SpotBugs XML，可重复使用")
    scan.add_argument("--dependency-check-json", action="append", default=[], help="导入已有 Dependency-Check JSON，可重复使用")
    scan.add_argument("--baseline", help="上一份 report.json，用于识别新增、已有和已修复发现")
    scan.add_argument("--review-file", help="从浏览器导出的 review.json")
    scan.add_argument("--ai", action="store_true", help="使用环境变量配置的兼容 API 生成分层解释")
    scan.add_argument("--ai-level", choices=("beginner", "intermediate", "advanced"))
    scan.add_argument("--fail-on", choices=("none", "critical", "high", "medium", "low"), help="用于 CI 的退出阈值，只计算基线新增发现")
    scan.add_argument("--yes", action="store_true", help="跳过交互式扫描范围确认（CI/脚本环境）")
    scan.add_argument("--exclude", action="append", default=[], help="排除路径（glob 风格，如 'src/test/*'）；可重复使用，与 .java-audit.yml 中 exclude_paths 合并")
    scan.add_argument("--workers", type=int, help="并行扫描进程数；默认取 min(8, CPU 核心数)")
    scan.add_argument("--progress", action="store_true", default=None, help="强制开启进度日志（默认在 TTY 环境自动开启）")
    scan.add_argument("--no-progress", dest="progress", action="store_false", help="禁用进度日志")
    scan.add_argument("--rules", action="append", default=[], help="外部规则文件路径（YAML 或 JSON，可重复使用）；自动与内置规则合并")
    scan.add_argument("--diff", nargs="?", const="WORKING", default=None, metavar="REF",
                      help="Git 增量审计：不带参数比较工作区未提交变更，带参数与指定分支或提交比较（如 main）")
    scan.add_argument("--commit", metavar="REF", help="只分析某次提交引入的变更（如 HEAD~1）")
    scan.add_argument("--changed-only", action="store_true", help="增量模式下只分析变更文件，不纳入依赖闭包")
    subparsers.add_parser("doctor", help="检查本机扫描器与运行环境")
    rules = subparsers.add_parser("rules", help="列出内置教学规则")
    rules.add_argument("--json", action="store_true")
    benchmark = subparsers.add_parser("benchmark", help="运行内置规则回归基准")
    benchmark.add_argument("--manifest", help="基准清单 JSON")
    return parser


def _doctor() -> int:
    tools = {"python": sys.executable, "java": shutil.which("java"), "maven": shutil.which("mvn"), "gradle": shutil.which("gradle"), "semgrep": shutil.which("semgrep"), "spotbugs": shutil.which("spotbugs") or shutil.which("spotbugs.bat"), "dependency-check": shutil.which("dependency-check") or shutil.which("dependency-check.bat"), "codeql": shutil.which("codeql")}
    print(f"Java Audit Lab {__version__} · {platform.system()} {platform.release()}")
    for name, value in tools.items():
        print(f"{'[OK]' if value else '[--]'} {name:18} {value or '未找到（可选）'}")
    return 0


def _list_rules(as_json: bool) -> int:
    from .runners.builtin import RULES
    values = [{"id": r.rule_id, "title": r.title, "cwe": r.cwe, "severity": r.severity, "confidence": r.confidence} for r in RULES]
    if as_json:
        print(json.dumps(values, ensure_ascii=False, indent=2))
    else:
        for item in values:
            print(f"{item['id']:16} {item['severity']:8} {item['cwe']:10} {item['title']}")
    return 0


def _link_surface_evidence(findings: list, surface) -> None:
    """Correlate attack-surface evidence with each finding without inventing flow."""
    entry_files = {entry.path for entry in surface.entries}
    dynamic_by_file: dict[str, list[int]] = {}
    for call in surface.dynamic_calls:
        dynamic_by_file.setdefault(str(call.get("path")), []).append(int(call.get("line", 0)))
    for finding in findings:
        if finding.location.path in entry_files:
            finding.metadata["entry_coverage"] = True
        nearby = dynamic_by_file.get(finding.location.path, [])
        if any(abs(line - finding.location.line) <= 40 for line in nearby):
            finding.metadata["dynamic_call_on_path"] = True


def _confirm_scope(root: Path, auto_yes: bool) -> bool:
    """Ask the user to confirm the scan scope. The report never claims authorization on its own."""
    if auto_yes or not sys.stdin.isatty():
        print(f"[范围] {root}（使用 --yes 或非交互环境自动继续；授权状态由使用者自行确认）")
        return True
    answer = input(f"请确认已获授权扫描 {root}（y/N）：").strip().lower()
    return answer in {"y", "yes"}


def _scan(args: argparse.Namespace) -> int:
    target_path = Path(args.target).expanduser().resolve()
    if not _confirm_scope(target_path, args.yes):
        print("已取消。", file=sys.stderr)
        return 2
    try:
        config_path = discover_config(target_path, args.config)
        config = load_config(config_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"错误：配置文件无效：{exc}", file=sys.stderr)
        return 2
    exclude_paths = list(config.get("exclude_paths") or []) + list(args.exclude or [])
    from .project import set_excluded_globs
    set_excluded_globs(exclude_paths)
    try:
        project = detect_project(target_path)
    except (OSError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    requested = [name.strip() for name in args.scanners.split(",") if name.strip()] if args.scanners else list(config["scanners"])
    unknown = [name for name in requested if name not in RUNNERS]
    if unknown:
        print(f"错误：未知扫描器：{', '.join(unknown)}", file=sys.stderr)
        return 2

    root = Path(project.root)
    # Git 增量审计：先确定变更范围，再把扫描器限制在「变更文件 + 依赖闭包」上。
    # detect_project 在此之前执行，因此项目画像中的 java_files 仍是全量数字。
    # --diff 不带参数时用哨兵 WORKING，需要还原成「工作区未提交变更」模式
    diff_ref = None if args.diff == "WORKING" else args.diff
    diff_context = collect_diff(root, diff_ref, args.commit, closure=not args.changed_only)
    # 分析历史提交时，工作树内容并不是那个提交的状态：
    # 直接扫描当前文件会得出「没有问题」的错误结论，因此按该提交重建源码快照。
    scan_root = root
    revision_snapshot: Path | None = None
    if needs_revision_snapshot(diff_context):
        revision_snapshot = Path(tempfile.mkdtemp(prefix="java-audit-rev-"))
        build_revision_snapshot(root, diff_context.base, revision_snapshot)
        scan_root = revision_snapshot
        atexit.register(shutil.rmtree, str(revision_snapshot), ignore_errors=True)
        print(f"[增量] 工作区不在 {diff_context.base}，已按该提交状态重建源码快照用于扫描")
    # 扫描范围必须相对实际扫描根目录计算，否则历史提交快照下会过滤掉全部文件。
    if diff_context.available:
        scope = diff_context.scan_scope(args.changed_only)
        from .project import set_scan_scope
        set_scan_scope([str(scan_root / rel) for rel in scope])
        print(f"[增量] 模式 {diff_context.mode}（基准 {diff_context.base}）："
              f"Java 变更 {diff_context.stats['java_files_changed']} 个，闭包 {diff_context.stats['closure_files']} 个")
    elif args.diff or args.commit:
        print("[增量] 未获取到 Git 变更信息，回退为全量扫描。")
    # TTY 自动开进度，CI/管道默认静默；--progress / --no-progress 强制覆盖
    progress = args.progress if args.progress is not None else sys.stderr.isatty()
    if args.workers is not None and args.workers < 1:
        print("错误：--workers 必须是大于 0 的整数", file=sys.stderr)
        return 2
    worker_count = int(args.workers) if args.workers is not None else None
    # 命令行规则相对当前目录；配置中的规则相对配置文件所在目录。
    extra_rule_paths = [str(Path(value).expanduser().resolve()) for value in (args.rules or [])]
    config_base = config_path.parent if config_path is not None else root
    for value in config.get("extra_rules") or []:
        configured = Path(str(value)).expanduser()
        extra_rule_paths.append(str((configured if configured.is_absolute() else config_base / configured).resolve()))
    # 项目内嵌规则目录：自动加载 <root>/.java-audit/rules/*.yaml
    rules_dir = root / ".java-audit" / "rules"
    if rules_dir.is_dir():
        extra_rule_paths.extend(sorted(p.as_posix() for p in rules_dir.glob("*.yml") if p.is_file()))
        extra_rule_paths.extend(sorted(p.as_posix() for p in rules_dir.glob("*.yaml") if p.is_file()))
        extra_rule_paths.extend(sorted(p.as_posix() for p in rules_dir.glob("*.json") if p.is_file()))
    extra_rule_paths = list(dict.fromkeys(extra_rule_paths))
    results: list[RunnerResult] = []
    use_cache = bool(config.get("cache", True)) and not args.no_cache
    cache_dir = root / ".java-audit-cache"
    with tempfile.TemporaryDirectory(prefix="java-audit-") as temp:
        work_dir = Path(temp)
        for name in requested:
            print(f"[运行] {name}")
            key = project_digest(
                scan_root,
                name,
                __version__,
                settings=json.dumps({"exclude_paths": exclude_paths}, ensure_ascii=False, sort_keys=True),
                extra_paths=[Path(path) for path in extra_rule_paths] if name == "builtin" else None,
            )
            result = load_cached(cache_dir, name, key) if use_cache else None
            if result is None:
                try:
                    from .runners.builtin import load_extra_rules
                    extra_rules = load_extra_rules(extra_rule_paths) if name == "builtin" and extra_rule_paths else None
                    runner = RUNNERS[name]()
                    if hasattr(runner, "_progress"):
                        runner._progress = progress
                    if extra_rules is not None:
                        runner._rules = extra_rules
                    if worker_count and hasattr(runner, "_workers"):
                        runner._workers = worker_count
                    result = runner.run(scan_root, work_dir)
                except Exception as exc:  # scanner failure must not destroy other evidence
                    result = RunnerResult(name, True, False, [], f"扫描器未处理异常：{type(exc).__name__}: {exc}")
                if use_cache and revision_snapshot is None:
                    save_cached(cache_dir, result, key)
            results.append(result)
            print(f"       {result.message}")
        for sarif_name in args.sarif:
            sarif_path = Path(sarif_name).resolve()
            try:
                imported = parse_sarif(sarif_path, root)
                result = RunnerResult(f"sarif:{sarif_path.name}", True, True, imported, f"导入 {len(imported)} 条。")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                result = RunnerResult(f"sarif:{sarif_path.name}", True, False, [], f"SARIF 导入失败：{exc}")
            results.append(result)
        import_specs = [
            ("spotbugs-xml", value, parse_spotbugs_xml) for value in args.spotbugs_xml
        ] + [
            ("dependency-check-json", value, parse_dependency_check_json) for value in args.dependency_check_json
        ]
        for kind, import_name, parser in import_specs:
            import_path = Path(import_name).resolve()
            try:
                imported = parser(import_path, root)
                result = RunnerResult(f"{kind}:{import_path.name}", True, True, imported, f"导入 {len(imported)} 条。")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                result = RunnerResult(f"{kind}:{import_path.name}", True, False, [], f"导入失败：{exc}")
            results.append(result)

    findings = consolidate_findings([finding for result in results for finding in result.findings])
    for finding in findings:
        finding.metadata.setdefault("scope", source_scope(finding.location.path))
    root_dir = Path(project.root)
    print("[阶段] 收集入口与信任边界……")
    surface = collect_surface(scan_root, progress=progress, workers=worker_count)
    _link_surface_evidence(findings, surface)
    for finding in findings:
        assess_path(finding)
        finding.metadata["evidence_record"] = build_evidence_record(finding)
    print("[阶段] 构建端点权限矩阵……")
    # 权限矩阵必须全量解析：安全配置类往往不在变更文件里，
    # 若沿用增量范围会把有配置的端点误判为「权限缺失」。
    from .project import set_scan_scope
    set_scan_scope(None)
    public_endpoints = [str(item) for item in config.get("public_endpoints") or []]
    authz = collect_authorization(scan_root, progress=progress, workers=worker_count, public_patterns=public_endpoints)
    link_findings_to_endpoints(findings, authz)
    authz_changes: list[dict] = []
    if diff_context.available and diff_context.files:
        print("[增量] 回退变更文件，对比权限声明变化……")
        with tempfile.TemporaryDirectory(prefix="java-audit-old-") as old_dir:
            snapshot = build_old_snapshot(scan_root, diff_context, Path(old_dir) / "old", git_root=root)
            if snapshot is not None:
                old_authz = collect_authorization(snapshot, progress=False, workers=worker_count, public_patterns=public_endpoints)
                authz_changes = compare_authorization(old_authz, authz)
    generalize_findings(findings)
    if args.ai:
        ai_level = args.ai_level or str(config.get("ai_level", "beginner"))
        ai_config = config_from_env(ai_level)
        if ai_config is None:
            print("[AI] 未配置 JAVA_AUDIT_AI_ENDPOINT 和 JAVA_AUDIT_AI_MODEL，已跳过。")
        else:
            print(f"[AI] 使用 {ai_config.model} 生成 {ai_level} 解释……")
            for index, finding in enumerate(findings, start=1):
                finding.metadata["ai_explanation"] = explain_with_ai(finding, ai_config)
                print(f"     {index}/{len(findings)} {finding.rule_id}")
    try:
        baseline = compare_with_baseline(findings, Path(args.baseline).resolve() if args.baseline else None)
        reviews = load_reviews(Path(args.review_file).resolve() if args.review_file else None)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"错误：基线或复核档案无法读取：{exc}", file=sys.stderr)
        return 2
    baseline_details = load_baseline_details(Path(args.baseline).resolve() if args.baseline else None)
    incremental = analyze_incremental(diff_context, findings, baseline, baseline_details, authz_changes)
    new_fingerprints = set(baseline["new"])
    for finding in findings:
        if finding.fingerprint in new_fingerprints:
            finding.review_priority = min(100, finding.review_priority + 5)
            finding.priority_factors.append({"factor": "基线变化", "points": 5, "reason": "本轮新增"})
    findings.sort(key=lambda item: (-item.review_priority, SEVERITY_ORDER.get(item.severity, 99), item.location.path, item.location.line))
    playbook = evaluate_playbook(project, surface, results, findings, reviews, baseline, ["JSON", "SARIF", "HTML", "Markdown"], authz)
    output_dir = Path(args.output).resolve()
    json_path, html_path, md_path = write_reports(output_dir, project, findings, results, baseline, reviews, surface.to_dict(), playbook, authz.to_dict(), incremental)
    progress = playbook["progress"]
    print(f"\n完成：{len(findings)} 条待复核发现；新增 {len(baseline['new'])}；已修复 {len(baseline['fixed'])}")
    print(f"审计阶段：已完成 {progress['completed']}/{progress['total']}，部分完成 {progress['partial']}")
    print(f"JSON: {json_path}\nSARIF: {output_dir / 'report.sarif'}\nHTML: {html_path}\nMarkdown: {md_path}")
    fail_on = args.fail_on or str(config.get("fail_on", "none"))
    if fail_on != "none":
        new = set(baseline["new"])
        threshold = SEVERITY_ORDER[fail_on]
        if any(item.fingerprint in new and SEVERITY_ORDER.get(item.severity, 99) <= threshold for item in findings):
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        return _doctor()
    if args.command == "rules":
        return _list_rules(args.json)
    if args.command == "benchmark":
        manifest = Path(args.manifest).resolve() if args.manifest else Path(__file__).resolve().parent / "benchmarks" / "manifest.json"
        try:
            result = run_benchmark(manifest)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            print(f"错误：无法运行基准：{exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if all(case["passed"] for case in result["cases"]) else 1
    return _scan(args)

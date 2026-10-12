#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""语料评测器。

对语料清单中的每个案例运行内置规则扫描，按标准答案统计：

    TP：危险样本正确检出        FP：安全样本错误检出
    FN：危险样本没有检出        TN：安全样本正确未检出

并按规则输出 Precision / Recall / F1。

零第三方依赖。用法（在仓库根目录）：

    python corpus/tools/evaluate_corpus.py [--strict-locations] [--json 输出.json]
                                          [--fail-on any|fp|fn|none]
                                          [--scanners builtin,taint,secrets] [语料目录]

可选扫描器（默认 builtin,taint,secrets）：

    builtin  逐行正则规则 JAL-SQL-001 等
    taint    方法内污点追踪 JAL-SQL-101 等
    secrets  配置文件凭据 JAL-CONFIG-SECRET-001

expected.json 里声明的规则若不属于任何已启用扫描器，则不参与判定，
只在报告中标注为“未接入”，不会冒充为零分。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from audit.frameworks import SINKS  # noqa: E402
from audit.runners.builtin import BuiltinRunner, RULES  # noqa: E402
from audit.runners.secrets import SecretsRunner  # noqa: E402
from audit.runners.taint import TaintRunner  # noqa: E402

BUILTIN_IDS = {rule.rule_id for rule in RULES}
TAINT_IDS = {sink.rule_id for sink in SINKS}
SECRETS_IDS = {"JAL-CONFIG-SECRET-001"}

SCANNERS: dict[str, tuple[str, callable, set[str]]] = {
    "builtin": ("内置正则规则", BuiltinRunner, BUILTIN_IDS),
    "taint": ("方法内污点追踪", TaintRunner, TAINT_IDS),
    "secrets": ("配置文件凭据", SecretsRunner, SECRETS_IDS),
}
DEFAULT_SCANNERS = ("builtin", "taint", "secrets")


def assessable_rules(names: tuple[str, ...]) -> set[str]:
    """当前启用扫描器能够判定的规则 ID 全集。"""
    ids: set[str] = set()
    for name in names:
        ids |= SCANNERS[name][2]
    return ids


def load_known_limitations(corpus: Path) -> dict[tuple[str, str], dict]:
    """读取已登记的能力边界：(case_id, rule_id) -> 条目。"""
    path = corpus / "known-limitations.json"
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {(e["case_id"], e["rule_id"]): e for e in payload.get("entries", [])}


def scan_case(case_dir: Path, scanner_names: tuple[str, ...]) -> list[dict]:
    findings: list[dict] = []
    for name in scanner_names:
        _label, factory, allowed = SCANNERS[name]
        result = factory().run(case_dir, case_dir)
        if getattr(result, "failed", False):
            print(f"警告：{name} 扫描器在 {case_dir.name} 上失败：{result.message}", file=sys.stderr)
            continue
        for finding in result.findings:
            # 扫描器可能顺带产生不属于自己声明范围的发现，如实保留并按实际 ID 计数
            findings.append({
                "rule_id": finding.rule_id,
                "path": finding.location.path,
                "line": finding.location.line,
                "evidence": finding.evidence[:160],
                "scanner": name,
                "confidence": finding.confidence,
                # 带反证的发现：工具同时给出了「这可能是安全的」线索，
                # 不静默算成通过，也不直接判死，由两种口径分别统计。
                "caveated": bool(getattr(finding, "evidence_against", None)),
            })
    return findings


def evaluate(corpus: Path, strict_locations: bool,
             scanner_names: tuple[str, ...] = DEFAULT_SCANNERS,
             splits: tuple[str, ...] | None = None) -> dict:
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    assessable = assessable_rules(scanner_names)
    per_rule: dict[str, dict[str, int]] = {}
    case_results: list[dict] = []
    tp = fp = fn = tn = unscored = caveated = known = 0
    known_index = load_known_limitations(corpus)
    known_hits: list[tuple[str, str]] = []
    evaluated_cases: set[str] = set()
    splits = splits or ("train", "validation")

    for entry in manifest.get("cases") or []:
        if entry.get("split", "train") not in splits:
            continue
        evaluated_cases.add(entry["case_id"])
        case_dir = corpus / entry["path"]
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        findings = scan_case(case_dir, scanner_names)
        finding_rules = {f["rule_id"] for f in findings}

        if expected["expected"] == "vulnerable":
            expected_rules = list(expected.get("expected_rules") or [])
            assessed_rules = [r for r in expected_rules if r in assessable]
            hit_rules = [r for r in assessed_rules if r in finding_rules]
            missing_rules = [r for r in assessed_rules if r not in finding_rules]
            for rule_id in expected_rules:
                bucket = per_rule.setdefault(rule_id, {"vuln": 0, "detected": 0, "safe": 0, "fp": 0})
                bucket["vuln"] += 1
                if rule_id in finding_rules:
                    bucket["detected"] += 1
            if not assessed_rules:
                case_status = "UNSCORED"
                unscored += 1
            elif not missing_rules:
                case_status = "TP"
                tp += 1
            else:
                case_status = "FN"
                fn += 1
            # 未声明的额外发现：不算失败，但要报告
            extras = [f for f in findings if f["rule_id"] not in expected_rules]
            # 严格模式：每个 expected_locations 都应有对应命中
            loc_misses = []
            if strict_locations:
                for loc in expected.get("expected_locations") or []:
                    location_rules = {str(loc.get("rule_id"))} if loc.get("rule_id") else set(assessed_rules)
                    if not any(
                        f["path"] == loc["path"] and f["line"] == loc["line"] and f["rule_id"] in location_rules
                        for f in findings
                    ):
                        loc_misses.append(f"{loc['path']}:{loc['line']}")
            case_results.append({
                "case_id": entry["case_id"],
                "category": entry["category"],
                "variant": entry.get("variant", ""),
                "expected": "vulnerable",
                "status": case_status,
                "hit_rules": hit_rules,
                "missing_rules": missing_rules,
                "extras": extras,
                "location_misses": loc_misses,
            })
        else:
            forbidden_rules = list(expected.get("forbidden_rules") or [])
            assessed_rules = [r for r in forbidden_rules if r in assessable]
            fp_rules = [r for r in assessed_rules if r in finding_rules]
            for rule_id in forbidden_rules:
                bucket = per_rule.setdefault(rule_id, {"vuln": 0, "detected": 0, "safe": 0, "fp": 0})
                bucket["safe"] += 1
                if rule_id in finding_rules:
                    bucket["fp"] += 1
            # 逐条登记过的已知能力边界：不计入门禁误报，但必须公示
            case_known = [f for f in findings
                          if (entry["case_id"], f["rule_id"]) in known_index]
            outstanding = [f for f in findings if f not in case_known]
            for f in case_known:
                known_hits.append((entry["case_id"], f["rule_id"]))
            extras = [f for f in outstanding if f["rule_id"] not in forbidden_rules]
            unexpected_rules = sorted({f["rule_id"] for f in extras})
            # 一个标为 safe 的案例出现任何发现都需要修正规则或修正标签，不能静默算 TN。
            # 已登记的条目走 KNOWN 状态；未登记的额外发现一律视为误报。
            if outstanding:
                case_status = "FP"
                fp += 1
                if all(f.get("caveated") for f in outstanding):
                    caveated += 1
            elif case_known:
                case_status = "KNOWN"
                known += 1
            else:
                case_status = "TN"
                tn += 1
            for rule_id in unexpected_rules:
                bucket = per_rule.setdefault(rule_id, {"vuln": 0, "detected": 0, "safe": 0, "fp": 0})
                bucket["safe"] += 1
                bucket["fp"] += 1
            case_results.append({
                "case_id": entry["case_id"],
                "category": entry["category"],
                "variant": entry.get("variant", ""),
                "expected": "safe",
                "status": case_status,
                "fp_rules": fp_rules,
                "unexpected_rules": unexpected_rules,
                "extras": extras,
            })

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    # 诚实口径：把已登记边界重新算回误报，用于对外说明真实准确率
    fp_all = fp + known
    precision_all = tp / (tp + fp_all) if (tp + fp_all) else 0.0
    f1_all = 2 * precision_all * recall / (precision_all + recall) if (precision_all + recall) else 0.0
    # 复核口径：带反证的低置信度误报视为复核人可快速消解，不计入
    fp_reviewed = fp - caveated
    precision_reviewed = tp / (tp + fp_reviewed) if (tp + fp_reviewed) else 0.0
    f1_reviewed = (2 * precision_reviewed * recall / (precision_reviewed + recall)
                   if (precision_reviewed + recall) else 0.0)
    rule_stats = []
    for rule_id in sorted(per_rule):
        bucket = per_rule[rule_id]
        p = bucket["detected"] / (bucket["detected"] + bucket["fp"]) if (bucket["detected"] + bucket["fp"]) else 0.0
        r = bucket["detected"] / bucket["vuln"] if bucket["vuln"] else 0.0
        f = 2 * p * r / (p + r) if (p + r) else 0.0
        rule_stats.append({"rule_id": rule_id, **bucket, "precision": p, "recall": r, "f1": f})
    return {
        "corpus": corpus.relative_to(REPO).as_posix() if corpus.is_relative_to(REPO) else str(corpus),
        "scanner": ",".join(scanner_names),
        "scanners": list(scanner_names),
        "totals": {"cases": len(case_results), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
                   "UNSCORED": unscored, "FP_CAVEATED": caveated, "KNOWN": known},
        # 只对本次实际评测过的案例做过期检查：没跑到的 split 里的条目不算过期
        "known_stale": sorted(k for k in set(known_index) - set(known_hits) if k[0] in evaluated_cases),
        "splits": list(splits),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "precision_all": precision_all,
        "f1_all": f1_all,
        "precision_reviewed": precision_reviewed,
        "f1_reviewed": f1_reviewed,
        "known_limitations": [known_index[k] for k in sorted(set(known_hits))],
        "rule_stats": rule_stats,
        "cases": case_results,
    }


def print_report(result: dict) -> None:
    assessable = assessable_rules(tuple(result.get("scanners") or DEFAULT_SCANNERS))
    totals = result["totals"]
    print("== Java Audit Lab 语料评测 ==")
    print(f"语料: {totals['cases']} 案例（危险 {totals['TP'] + totals['FN']}"
          f" / 安全 {totals['FP'] + totals['TN']}）  扫描器: {result['scanner']}  划分: {'+'.join(result['splits'])}")
    print()
    print("按规则统计：")
    print(f"{'规则':16}{'危险':>4}{'检出':>4}{'安全':>4}{'误报':>4}{'Precision':>11}{'Recall':>9}")
    for rule in result["rule_stats"]:
        if rule["rule_id"] not in assessable:
            # 声明了但当前评测器未接入的规则：只展示样本量，不给分数
            print(f"{rule['rule_id']:16}{rule['vuln']:>4}{rule['detected']:>4}{rule['safe']:>4}{rule['fp']:>4}"
                  f"{'（未接入）':>11}{'-':>9}")
            continue
        prec = f"{rule['precision']:>10.1%}" if (rule["detected"] or rule["fp"]) else "         -"
        rec = f"{rule['recall']:>9.1%}" if rule["vuln"] else "        -"
        print(f"{rule['rule_id']:16}{rule['vuln']:>4}{rule['detected']:>4}{rule['safe']:>4}{rule['fp']:>4}"
              f"{prec}{rec}")
    print()
    print(f"总体：TP {totals['TP']}  FP {totals['FP']}  FN {totals['FN']}  TN {totals['TN']}"
          f"  已登记边界 {totals['KNOWN']}")
    gate_total = totals["FP"]
    print(f"含已登记边界：Precision {result['precision_all']:.1%}  Recall {result['recall']:.1%}"
          f"  F1 {result['f1_all']:.1%}（把 {totals['KNOWN']} 例已登记边界算作误报）")
    print(f"门禁口径    ：Precision {result['precision']:.1%}  Recall {result['recall']:.1%}"
          f"  F1 {result['f1']:.1%}（已登记的不算误报，CI 用这个判定）")
    if totals["FP_CAVEATED"]:
        print(f"复核口径    ：Precision {result['precision_reviewed']:.1%}  Recall {result['recall']:.1%}"
              f"  F1 {result['f1_reviewed']:.1%}"
              f"（{totals['FP_CAVEATED']} 例未登记误报自带反证，复核人可快速消解）")
    print()
    known_entries = result.get("known_limitations") or []
    if known_entries:
        print("已登记的能力边界（不算门禁误报，但每次都要公示）：")
        for item in known_entries:
            print(f"  [{item['case_id']}] {item['rule_id']}：{item['reason']}")
            print(f"      计划：{item['plan']}")
        print()
    if result.get("known_stale"):
        print("以下登记条目已不再复现，请从 known-limitations.json 删除：")
        for case_id, rule_id in result["known_stale"]:
            print(f"  {case_id} / {rule_id}")
        print()
    print()
    problems = [c for c in result["cases"] if c["status"] in ("FN", "FP")]
    extras = [c for c in result["cases"] if c.get("extras")]
    loc_misses = [c for c in result["cases"] if c.get("location_misses")]
    if problems:
        print("不符合预期的案例：")
        for case in problems:
            if case["status"] == "FN":
                print(f"  [漏报] {case['case_id']}：未检出 {case.get('missing_rules', [])}")
            else:
                rules = sorted(set(case.get("fp_rules", [])) | set(case.get("unexpected_rules", [])))
                print(f"  [误报] {case['case_id']}：安全样本命中 {rules}")
        print()
    if loc_misses:
        print("行号未对齐（--strict-locations）：")
        for case in loc_misses:
            print(f"  {case['case_id']}: {', '.join(case['location_misses'])}")
        print()
    if extras:
        print("未声明的额外发现（不影响判定）：")
        for case in extras:
            for finding in case["extras"]:
                print(f"  {case['case_id']}: {finding['rule_id']} @ {finding['path']}:{finding['line']}")
        print()
    if not (problems or extras or loc_misses):
        print("全部案例符合预期，无额外发现。")


def should_fail(result: dict, fail_on: str, strict_locations: bool) -> bool:
    totals = result["totals"]
    location_failed = strict_locations and any(c.get("location_misses") for c in result["cases"])
    return bool(
        (fail_on == "any" and (totals["FP"] or totals["FN"]))
        or (fail_on == "fp" and totals["FP"])
        or (fail_on == "fn" and totals["FN"])
        or (fail_on != "none" and location_failed)
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="语料评测器")
    parser.add_argument("corpus", nargs="?", default=str(REPO / "corpus"), help="语料目录")
    parser.add_argument("--strict-locations", action="store_true", help="校验 expected_locations 行号对齐")
    parser.add_argument("--json", dest="json_out", help="把完整结果写成 JSON")
    parser.add_argument("--fail-on", choices=("any", "fp", "fn", "none"), default="any",
                        help="何时返回非零退出码（默认 any：出现 FP 或 FN 即失败）")
    parser.add_argument("--scanners", default=",".join(DEFAULT_SCANNERS),
                        help=f"启用的扫描器，逗号分隔。可选：{','.join(SCANNERS)}")
    parser.add_argument("--split", default="train,validation",
                        help="要评测的划分，逗号分隔：train/validation/holdout/all。"
                             "默认 train,validation；holdout 只在发布前用 --split all 运行")
    args = parser.parse_args(argv[1:])

    names = tuple(n.strip() for n in args.scanners.split(",") if n.strip())
    unknown = [n for n in names if n not in SCANNERS]
    if unknown:
        print(f"错误：未知扫描器 {unknown}，可选：{','.join(SCANNERS)}", file=sys.stderr)
        return 2
    if args.split.strip() == "all":
        splits = ("train", "validation", "holdout")
    else:
        splits = tuple(s.strip() for s in args.split.split(",") if s.strip())
    bad_splits = [s for s in splits if s not in {"train", "validation", "holdout"}]
    if bad_splits:
        print(f"错误：未知划分 {bad_splits}，可选 train/validation/holdout/all", file=sys.stderr)
        return 2

    corpus = Path(args.corpus).resolve()
    if not (corpus / "manifest.json").is_file():
        print(f"错误：找不到 {corpus / 'manifest.json'}", file=sys.stderr)
        return 2
    result = evaluate(corpus, args.strict_locations, names, splits)
    print_report(result)
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"JSON 结果：{args.json_out}")
    totals = result["totals"]
    return 1 if should_fail(result, args.fail_on, args.strict_locations) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

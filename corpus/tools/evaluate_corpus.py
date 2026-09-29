#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""语料评测器。

对语料清单中的每个案例运行内置规则扫描，按标准答案统计：

    TP：危险样本正确检出        FP：安全样本错误检出
    FN：危险样本没有检出        TN：安全样本正确未检出

并按规则输出 Precision / Recall / F1。

零第三方依赖。用法（在仓库根目录）：

    python corpus/tools/evaluate_corpus.py [--strict-locations] [--json 输出.json]
                                          [--fail-on any|fp|fn|none] [语料目录]

说明：当前只接入 builtin 扫描器；expected.json 中声明了 taint 引擎规则
（如 JAL-*-101）的样本，这些规则不会参与判定，只在报告中注明。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from audit.runners.builtin import BuiltinRunner, RULES  # noqa: E402

BUILTIN_IDS = {rule.rule_id for rule in RULES}


def scan_case(case_dir: Path) -> list[dict]:
    runner = BuiltinRunner()
    result = runner.run(case_dir, case_dir)
    return [
        {
            "rule_id": finding.rule_id,
            "path": finding.location.path,
            "line": finding.location.line,
            "evidence": finding.evidence[:160],
        }
        for finding in result.findings
    ]


def evaluate(corpus: Path, strict_locations: bool) -> dict:
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    per_rule: dict[str, dict[str, int]] = {}
    case_results: list[dict] = []
    tp = fp = fn = tn = unscored = 0

    for entry in manifest.get("cases") or []:
        case_dir = corpus / entry["path"]
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        findings = scan_case(case_dir)
        finding_rules = {f["rule_id"] for f in findings}

        if expected["expected"] == "vulnerable":
            expected_rules = list(expected.get("expected_rules") or [])
            assessed_rules = [r for r in expected_rules if r in BUILTIN_IDS]
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
            assessed_rules = [r for r in forbidden_rules if r in BUILTIN_IDS]
            fp_rules = [r for r in assessed_rules if r in finding_rules]
            for rule_id in forbidden_rules:
                bucket = per_rule.setdefault(rule_id, {"vuln": 0, "detected": 0, "safe": 0, "fp": 0})
                bucket["safe"] += 1
                if rule_id in finding_rules:
                    bucket["fp"] += 1
            extras = [f for f in findings if f["rule_id"] not in forbidden_rules]
            unexpected_rules = sorted({f["rule_id"] for f in extras})
            # 一个标为 safe 的案例出现任何发现都需要修正规则或修正标签，不能静默算 TN。
            case_status = "FP" if findings else "TN"
            if case_status == "FP":
                fp += 1
            else:
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
    rule_stats = []
    for rule_id in sorted(per_rule):
        bucket = per_rule[rule_id]
        p = bucket["detected"] / (bucket["detected"] + bucket["fp"]) if (bucket["detected"] + bucket["fp"]) else 0.0
        r = bucket["detected"] / bucket["vuln"] if bucket["vuln"] else 0.0
        f = 2 * p * r / (p + r) if (p + r) else 0.0
        rule_stats.append({"rule_id": rule_id, **bucket, "precision": p, "recall": r, "f1": f})
    return {
        "corpus": corpus.relative_to(REPO).as_posix() if corpus.is_relative_to(REPO) else str(corpus),
        "split": manifest.get("split", ""),
        "scanner": "builtin",
        "totals": {"cases": len(case_results), "TP": tp, "FP": fp, "FN": fn, "TN": tn, "UNSCORED": unscored},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "rule_stats": rule_stats,
        "cases": case_results,
    }


def print_report(result: dict) -> None:
    totals = result["totals"]
    print("== Java Audit Lab 语料评测 ==")
    print(f"语料: {totals['cases']} 案例（危险 {totals['TP'] + totals['FN']}"
          f" / 安全 {totals['FP'] + totals['TN']}）  扫描器: {result['scanner']}  划分: {result['split']}")
    print()
    print("按规则统计：")
    print(f"{'规则':16}{'危险':>4}{'检出':>4}{'安全':>4}{'误报':>4}{'Precision':>11}{'Recall':>9}")
    for rule in result["rule_stats"]:
        if rule["rule_id"] not in BUILTIN_IDS:
            # 声明了但当前评测器未接入的规则：只展示样本量，不给分数
            print(f"{rule['rule_id']:16}{rule['vuln']:>4}{rule['detected']:>4}{rule['safe']:>4}{rule['fp']:>4}"
                  f"{'（未接入）':>11}{'-':>9}")
            continue
        prec = f"{rule['precision']:>10.1%}" if (rule["detected"] or rule["fp"]) else "         -"
        rec = f"{rule['recall']:>9.1%}" if rule["vuln"] else "        -"
        print(f"{rule['rule_id']:16}{rule['vuln']:>4}{rule['detected']:>4}{rule['safe']:>4}{rule['fp']:>4}"
              f"{prec}{rec}")
    print()
    print(f"总体：TP {totals['TP']}  FP {totals['FP']}  FN {totals['FN']}  TN {totals['TN']}")
    print(f"Precision {result['precision']:.1%}  Recall {result['recall']:.1%}  F1 {result['f1']:.1%}")
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
    args = parser.parse_args(argv[1:])

    corpus = Path(args.corpus).resolve()
    if not (corpus / "manifest.json").is_file():
        print(f"错误：找不到 {corpus / 'manifest.json'}", file=sys.stderr)
        return 2
    result = evaluate(corpus, args.strict_locations)
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

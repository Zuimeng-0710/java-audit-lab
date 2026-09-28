from __future__ import annotations

import json
from pathlib import Path

from .runners.builtin import BuiltinRunner


def run_benchmark(manifest_path: Path) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    base = manifest_path.parent
    true_positive = false_positive = false_negative = 0
    cases = []
    for case in manifest.get("cases", []):
        target = (base / case["target"]).resolve()
        actual = {item.rule_id for item in BuiltinRunner().run(target, target).findings}
        expected = set(case.get("expected_rules", []))
        tp, fp, fn = actual & expected, actual - expected, expected - actual
        true_positive += len(tp)
        false_positive += len(fp)
        false_negative += len(fn)
        cases.append({"target": case["target"], "passed": not fp and not fn, "matched": sorted(tp), "unexpected": sorted(fp), "missed": sorted(fn)})
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
    return {"precision": precision, "recall": recall, "true_positive": true_positive, "false_positive": false_positive, "false_negative": false_negative, "cases": cases}

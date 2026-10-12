from __future__ import annotations

import json
from pathlib import Path

from typing import Any

from .findings import Finding


def _secondary_key(rule_id: str | None, path: str | None, evidence: str | None) -> str:
    """指纹失配时的对齐键：规则 + 正斜杠路径 + 空白归一化命中文本。

    用于两种场景（issue #6）：
    - 指纹方案升级后对比旧报告（旧指纹含绝对行号，新指纹不含）
    - 代码重排导致同一逻辑条目的行号变化
    """
    normalized = " ".join(str(evidence or "").split())
    posix_path = str(path or "").replace("\\", "/")
    return f"{rule_id or ''}|{posix_path}|{normalized}"


def compare_with_baseline(findings: list[Finding], baseline_path: Path | None) -> dict[str, object]:
    current = {item.fingerprint for item in findings}
    if baseline_path is None:
        return {"enabled": False, "new": sorted(current), "existing": [], "fixed": []}
    payload = json.loads(baseline_path.read_text(encoding="utf-8-sig"))
    previous_items = [item for item in payload.get("findings", []) if item.get("fingerprint")]
    previous = {item["fingerprint"] for item in previous_items}
    existing = set(current & previous)
    # 二次对齐：指纹不匹配但「规则 + 路径 + 归一化文本」一致的条目视为同一条，
    # 避免格式化改动把存量发现误报成 new + fixed 噪声。
    previous_by_key: dict[str, list[str]] = {}
    for item in previous_items:
        location = item.get("location") or {}
        key = _secondary_key(item.get("rule_id"), location.get("path"), item.get("evidence"))
        previous_by_key.setdefault(key, []).append(str(item["fingerprint"]))
    relocated: list[str] = []
    consumed: set[str] = set()
    for finding in findings:
        if finding.fingerprint in previous or finding.fingerprint in relocated:
            continue
        key = _secondary_key(finding.rule_id, finding.location.path, finding.evidence)
        for candidate in previous_by_key.get(key, []):
            if candidate in consumed or candidate in existing:
                continue
            consumed.add(candidate)
            relocated.append(finding.fingerprint)
            break
    existing |= set(relocated)
    return {
        "enabled": True,
        "source": str(baseline_path),
        "new": sorted(current - existing),
        "existing": sorted(existing),
        "fixed": sorted(previous - existing - consumed),
        "relocated": sorted(relocated),
    }


def load_reviews(review_path: Path | None) -> dict[str, dict[str, Any]]:
    if review_path is None:
        return {}
    payload = json.loads(review_path.read_text(encoding="utf-8-sig"))
    reviews = payload.get("reviews", payload)
    return reviews if isinstance(reviews, dict) else {}

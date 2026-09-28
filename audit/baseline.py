from __future__ import annotations

import json
from pathlib import Path

from .findings import Finding


def compare_with_baseline(findings: list[Finding], baseline_path: Path | None) -> dict[str, object]:
    current = {item.fingerprint for item in findings}
    if baseline_path is None:
        return {"enabled": False, "new": sorted(current), "existing": [], "fixed": []}
    payload = json.loads(baseline_path.read_text(encoding="utf-8-sig"))
    previous = {item.get("fingerprint") for item in payload.get("findings", []) if item.get("fingerprint")}
    return {
        "enabled": True,
        "source": str(baseline_path),
        "new": sorted(current - previous),
        "existing": sorted(current & previous),
        "fixed": sorted(previous - current),
    }


def load_reviews(review_path: Path | None) -> dict[str, dict[str, str]]:
    if review_path is None:
        return {}
    payload = json.loads(review_path.read_text(encoding="utf-8-sig"))
    reviews = payload.get("reviews", payload)
    return reviews if isinstance(reviews, dict) else {}

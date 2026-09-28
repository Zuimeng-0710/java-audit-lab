from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULTS: dict[str, Any] = {
    "scanners": ["builtin", "secrets", "taint", "semgrep", "spotbugs", "dependency-check", "codeql"],
    "fail_on": "none",
    "ai_level": "beginner",
    "cache": True,
    "exclude_paths": [],
    "extra_rules": [],
    "public_endpoints": [],
}


def load_config(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return dict(DEFAULTS)
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        loaded = json.loads(text)
    else:
        loaded = _simple_yaml(text)
    if not isinstance(loaded, dict):
        raise ValueError("配置文件顶层必须是对象")
    result = dict(DEFAULTS)
    result.update(loaded)
    if not isinstance(result["scanners"], list):
        raise ValueError("scanners 必须是列表")
    if not isinstance(result["exclude_paths"], list):
        raise ValueError("exclude_paths 必须是列表")
    if not isinstance(result["extra_rules"], list):
        raise ValueError("extra_rules 必须是列表")
    if not isinstance(result["public_endpoints"], list):
        raise ValueError("public_endpoints 必须是列表")
    return result


def discover_config(target: Path, explicit: str | None) -> Path | None:
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        if not candidate.is_file():
            raise FileNotFoundError(f"配置文件不存在：{candidate}")
        return candidate
    for name in (".java-audit.yml", ".java-audit.yaml", ".java-audit.json"):
        candidate = target / name
        if candidate.exists():
            return candidate
    return None


def _simple_yaml(text: str) -> dict[str, Any] | list[Any]:
    """Parse the intentionally small project config format without adding a dependency.

    Two top-level shapes are supported:
    - Mapping (default for .java-audit.yml):  key: value   /  key:\n  - item
    - List of mappings (used by external rule files): each "- key: value" starts a new item
      and subsequent "key: value" lines attach to that item.
    """
    lines = text.splitlines()
    # Detect top-level shape: scan for the first non-blank, non-comment line.
    first: str | None = None
    for raw in lines:
        line = raw.split("#", 1)[0].rstrip()
        if line.strip():
            first = line.strip()
            break
    if first is None:
        return {}

    if first.startswith("-"):
        # List-of-mappings mode (e.g. external rule files).
        items: list[Any] = []
        current: dict[str, Any] | None = None
        for number, raw in enumerate(lines, start=1):
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            stripped = line.strip()
            if stripped.startswith("-"):
                content = stripped[1:].strip()
                if not content:
                    current = {}
                    items.append(current)
                    continue
                if ":" in content:
                    key, value = (part.strip() for part in content.split(":", 1))
                    current = {}
                    items.append(current)
                    if value:
                        current[key] = _scalar(value)
                    else:
                        # Inline nested list under a "- key:" — rare in rule files; treat as empty list.
                        current[key] = []
                else:
                    current = {"_": _scalar(content)}
                    items.append(current)
                continue
            # Indented "key: value" line — attach to current item.
            if current is None:
                raise ValueError(f"第 {number} 行缺少对应的列表项")
            if ":" not in stripped:
                raise ValueError(f"第 {number} 行缺少冒号")
            key, value = (part.strip() for part in stripped.split(":", 1))
            if not value:
                current[key] = []
            else:
                current[key] = _scalar(value)
        return items

    # Mapping mode (the original behavior, used by .java-audit.yml).
    result: dict[str, Any] = {}
    active_list: str | None = None
    for number, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("-"):
            if active_list is None:
                raise ValueError(f"第 {number} 行的列表没有对应键")
            result[active_list].append(_scalar(stripped[1:].strip()))
            continue
        if ":" not in stripped:
            raise ValueError(f"第 {number} 行缺少冒号")
        key, value = (part.strip() for part in stripped.split(":", 1))
        if not value:
            result[key] = []
            active_list = key
        else:
            result[key] = _scalar(value)
            active_list = None
    return result


def _scalar(value: str) -> Any:
    if value.startswith("[") and value.endswith("]"):
        return [_scalar(part.strip()) for part in value[1:-1].split(",") if part.strip()]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() in {"null", "none"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value

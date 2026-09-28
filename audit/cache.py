from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .findings import Finding, Location
from .project import iter_config_files, iter_java_files
from .runners.base import RunnerResult


def project_digest(
    root: Path,
    scanner: str,
    version: str,
    *,
    settings: str = "",
    extra_paths: list[Path] | None = None,
) -> str:
    """Hash source state plus scanner settings that can change results.

    External rules may live outside the project, so their contents are included
    directly instead of relying only on project-relative file metadata.
    """
    digest = hashlib.sha256(f"{scanner}:{version}:{settings}".encode())
    candidates = list(iter_java_files(root))
    if scanner == "secrets":
        candidates.extend(iter_config_files(root))
    candidates.extend(path for path in (root / "pom.xml", root / "build.gradle", root / "build.gradle.kts") if path.exists())
    for path in sorted(candidates):
        stat = path.stat()
        digest.update(str(path.relative_to(root)).encode())
        digest.update(f"{stat.st_size}:{stat.st_mtime_ns}".encode())
    for path in sorted((item.expanduser().resolve() for item in (extra_paths or [])), key=str):
        digest.update(str(path).encode())
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<missing>")
    return digest.hexdigest()[:24]


def load_cached(cache_dir: Path, scanner: str, key: str) -> RunnerResult | None:
    path = cache_dir / f"{scanner}-{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = [_finding_from_dict(item) for item in data.get("findings", [])]
        return RunnerResult(scanner, data["available"], data["success"], findings, f"缓存命中：{data['message']}", data.get("command"))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def save_cached(cache_dir: Path, result: RunnerResult, key: str) -> None:
    if not result.success:
        return
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload = result.summary() | {"message": result.message, "command": result.command, "findings": [item.to_dict() for item in result.findings]}
    (cache_dir / f"{result.name}-{key}.json").write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _finding_from_dict(data: dict[str, Any]) -> Finding:
    copied = dict(data)
    copied["location"] = Location(**copied["location"])
    return Finding(**copied)

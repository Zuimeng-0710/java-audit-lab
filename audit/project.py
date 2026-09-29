from __future__ import annotations

import fnmatch
import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


IGNORED_DIRS = {".git", ".gradle", ".idea", ".mvn", ".java-audit-cache", "audit-report", "build", "dist", "node_modules", "out", "output", "target"}
CONFIG_SUFFIXES = {".yml", ".yaml", ".properties", ".xml", ".json", ".env"}
SOURCE_SUFFIXES = {".java", ".kt", ".kts", ".groovy", ".scala"}
WEB_SUFFIXES = {".jsp", ".jspx", ".html", ".htm", ".js", ".ts", ".css", ".vue"}
TEXT_SUFFIXES = SOURCE_SUFFIXES | WEB_SUFFIXES | CONFIG_SUFFIXES | {".sql", ".gradle"}

# Glob patterns applied to repo-relative posix paths, e.g. "src/test/*".
# Mutated at runtime by set_excluded_globs(); we keep it as a module-level list
# so worker processes (spawn) inherit the same exclusions via import.
_EXCLUDED_GLOBS: list[str] = []

# 增量扫描范围：只分析这些文件（绝对路径集合）。
# 多进程用 spawn 启动时会重新 import 本模块，模块级变量不会继承，
# 因此额外把清单落到临时文件、用环境变量传递路径，保证子进程同样生效。
_SCOPE_ENV = "JAVA_AUDIT_SCOPE_FILE"
_INCLUDED_FILES: set[str] | None = None


def set_excluded_globs(patterns: list[str]) -> None:
    """Replace the exclusion list. Patterns use fnmatch syntax against posix paths."""
    _EXCLUDED_GLOBS[:] = list(patterns)


def _read_scope_from_env() -> set[str] | None:
    target = os.environ.get(_SCOPE_ENV)
    if not target:
        return None
    path = Path(target)
    if not path.is_file():
        return None
    try:
        return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    except OSError:
        return None


def set_scan_scope(paths: list[str] | None) -> None:
    """Limit iteration to an explicit file set. Pass None/empty for full scan."""
    global _INCLUDED_FILES
    if not paths:
        _INCLUDED_FILES = None
        os.environ.pop(_SCOPE_ENV, None)
        return
    _INCLUDED_FILES = {str(Path(item).resolve()) for item in paths}
    handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    try:
        handle.write("\n".join(sorted(_INCLUDED_FILES)))
        handle.close()
        os.environ[_SCOPE_ENV] = handle.name
    except OSError:
        _INCLUDED_FILES = None
        os.environ.pop(_SCOPE_ENV, None)


def _in_scope(path: Path) -> bool:
    global _INCLUDED_FILES
    if _INCLUDED_FILES is None:
        _INCLUDED_FILES = _read_scope_from_env()
    if _INCLUDED_FILES is None:
        return True
    return str(path.resolve()) in _INCLUDED_FILES


def _is_excluded(rel_parts: tuple[str, ...]) -> bool:
    if any(part in IGNORED_DIRS for part in rel_parts):
        return True
    if not _EXCLUDED_GLOBS:
        return False
    rel = "/".join(rel_parts)
    return any(fnmatch.fnmatch(rel, pat) for pat in _EXCLUDED_GLOBS)


@dataclass(slots=True)
class ProjectInfo:
    root: str
    name: str
    build_system: str
    java_files: int
    manifests: list[str]
    frameworks: list[str]
    inventory: dict[str, object]
    revision: str
    branch: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def iter_java_files(root: Path):
    for path in root.rglob("*.java"):
        rel_parts = path.relative_to(root).parts
        if not _is_excluded(rel_parts) and _in_scope(path):
            yield path


def iter_config_files(root: Path):
    """Yield text configuration files while honoring project exclusions."""
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if _is_excluded(rel_parts) or not _in_scope(path):
            continue
        if path.name == ".env" or path.suffix.lower() in CONFIG_SUFFIXES:
            yield path


def source_scope(path: str | Path) -> str:
    """Classify a repository-relative location for report triage."""
    parts = [part.lower() for part in Path(path).as_posix().split("/")]
    joined = "/".join(parts)
    if "generated" in parts or "build/generated" in joined or "target/generated" in joined:
        return "generated"
    if "src/test" in joined or "src/it" in joined or "test" in parts or "tests" in parts:
        return "test"
    if any(part in {"example", "examples", "sample", "samples", "demo", "demos"} for part in parts):
        return "example"
    return "production"


def collect_inventory(root: Path) -> dict[str, object]:
    """Build a small, reproducible scope manifest without retaining file contents."""
    by_extension: dict[str, int] = {}
    total_files = source_files = config_files = web_files = estimated_lines = counted_files = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if _is_excluded(rel_parts):
            continue
        total_files += 1
        suffix = path.suffix.lower() or "[no extension]"
        by_extension[suffix] = by_extension.get(suffix, 0) + 1
        if suffix in SOURCE_SUFFIXES:
            source_files += 1
        if path.name == ".env" or suffix in CONFIG_SUFFIXES:
            config_files += 1
        if suffix in WEB_SUFFIXES:
            web_files += 1
        if suffix in TEXT_SUFFIXES:
            try:
                if path.stat().st_size <= 5 * 1024 * 1024:
                    data = path.read_bytes()
                    estimated_lines += data.count(b"\n") + (1 if data else 0)
                    counted_files += 1
            except OSError:
                pass
    return {
        "total_files": total_files,
        "source_files": source_files,
        "config_files": config_files,
        "web_files": web_files,
        "estimated_lines": estimated_lines,
        "line_counted_files": counted_files,
        "by_extension": dict(sorted(by_extension.items(), key=lambda item: (-item[1], item[0]))[:12]),
    }


def _git_metadata(root: Path) -> tuple[str, str]:
    def value(*args: str) -> str:
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), *args], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=3, check=False,
            )
            return completed.stdout.strip() if completed.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""
    return value("rev-parse", "--short=12", "HEAD"), value("branch", "--show-current")


def detect_project(target: str | Path) -> ProjectInfo:
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"目标路径不存在：{root}")
    if not root.is_dir():
        raise NotADirectoryError(f"目标必须是目录：{root}")

    manifests: list[str] = []
    if (root / "pom.xml").exists():
        build_system = "maven"
        manifests.append("pom.xml")
    elif (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        build_system = "gradle"
        manifests.extend(p.name for p in (root / "build.gradle", root / "build.gradle.kts") if p.exists())
    else:
        build_system = "plain-java"

    manifest_text = ""
    for manifest in manifests:
        try:
            manifest_text += (root / manifest).read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            pass
    framework_markers = {
        "Spring Boot": ("spring-boot",), "Spring Security": ("spring-security", "starter-security"),
        "MyBatis": ("mybatis",), "Hibernate/JPA": ("hibernate", "jakarta.persistence", "javax.persistence"),
        "Struts": ("struts",), "Jersey": ("jersey",), "WebFlux": ("spring-webflux",),
    }
    frameworks = [name for name, markers in framework_markers.items() if any(marker in manifest_text for marker in markers)]
    revision, branch = _git_metadata(root)
    return ProjectInfo(
        root=str(root),
        name=root.name,
        build_system=build_system,
        java_files=sum(1 for _ in iter_java_files(root)),
        manifests=manifests,
        frameworks=frameworks,
        inventory=collect_inventory(root),
        revision=revision,
        branch=branch,
    )

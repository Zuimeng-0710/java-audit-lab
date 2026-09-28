"""阶段 C-1：Git 增量审计。

企业产品的增量扫描会分析变更文件及其依赖闭包，再把结果并入完整扫描。
本模块提供同等能力，并按本项目的证据原则处理不确定性：

    - 只报告真实存在的变更，不推断"没变"
    - 权限"声明消失"与"确实没有权限控制"区分开：前者是主动移除，后者是缺失
    - 修复是否真正切断路径，只做可达性提示，最终结论留给人工

三个入口：

    java-audit scan . --diff              # 工作区未提交变更
    java-audit scan . --diff main         # 相对 main 分支的全部变更
    java-audit scan . --commit HEAD~1     # 单次提交引入的变更
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .project import iter_java_files

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
IMPORT_RE = re.compile(r"^\s*import\s+([\w.]+)\s*;", re.M)

# 权限强度序：数值越高约束越强。
# unknown 排在 anonymous 之上：它是"未找到声明"，不等于"明确允许匿名"。
REQUIREMENT_STRENGTH = {
    "anonymous": 0,
    "unknown": 1,
    "ownership": 2,
    "authenticated": 3,
    "permission": 4,
    "role": 5,
}

REQUIREMENT_LABELS = {
    "anonymous": "匿名可访问",
    "unknown": "未知",
    "ownership": "需数据归属",
    "authenticated": "需登录",
    "permission": "需权限",
    "role": "需角色",
}


@dataclass(slots=True)
class FileChange:
    path: str                                  # 相对扫描根目录的 posix 路径
    status: str                                # added / modified / deleted / renamed
    ranges: list[tuple[int, int]] = field(default_factory=list)   # 新版本中的变更行区间
    old_path: str = ""
    java: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "status": self.status,
            "ranges": [list(item) for item in self.ranges],
            "old_path": self.old_path,
            "java": self.java,
        }


@dataclass
class DiffContext:
    available: bool = False
    mode: str = "none"            # none / working / ref / commit
    base: str = ""                # 展示用基准（如 HEAD / main）
    old_ref: str = ""             # 取回旧版本文件的 ref，commit 模式下是父提交
    head_commit: str = ""         # git rev-parse HEAD
    target_commit: str = ""       # git rev-parse <base>，判断工作树是否就在该提交上
    repo_root: str = ""
    files: list[FileChange] = field(default_factory=list)
    closure: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def java_files(self) -> list[str]:
        return [item.path for item in self.files if item.java and item.status != "deleted"]

    def scan_scope(self, changed_only: bool) -> list[str]:
        """需要分析的文件集合：变更文件 + 依赖闭包。"""
        paths = list(self.java_files)
        if not changed_only:
            paths.extend(self.closure)
        return list(dict.fromkeys(paths))

    def hits_change(self, path: str, line: int) -> bool:
        """该位置是否落在本次变更的行区间内。"""
        normalized = str(path).replace("\\", "/")
        for change in self.files:
            if change.path != normalized:
                continue
            if change.status == "added":
                return True
            for start, end in change.ranges:
                if start <= line <= end:
                    return True
        return False

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "mode": self.mode,
            "base": self.base,
            "old_ref": self.old_ref,
            "repo_root": self.repo_root,
            "files": [item.to_dict() for item in self.files],
            "closure": list(self.closure),
            "stats": dict(self.stats),
            "notes": list(self.notes),
        }


# ---------------- Git 基础 ----------------


def _git(root: Path, *args: str) -> tuple[int, str]:
    """执行 git 命令。返回 (returncode, stdout)；失败时 stdout 为空、stderr 丢弃。"""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"{type(exc).__name__}: {exc}"
    return completed.returncode, completed.stdout or ""


def is_git_repo(root: Path) -> bool:
    code, _ = _git(root, "rev-parse", "--is-inside-work-tree")
    return code == 0


def _repo_root(root: Path) -> str:
    code, out = _git(root, "rev-parse", "--show-toplevel")
    return out.strip() if code == 0 else ""


def _name_status(root: Path, *diff_args: str) -> list[tuple[str, str, str]]:
    """解析 git diff --name-status 输出为 (status, path, old_path)。"""
    code, out = _git(root, "diff", "--name-status", "--find-renames", "--relative", *diff_args)
    if code != 0:
        return []
    rows: list[tuple[str, str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0][:1]
        if status == "R" and len(parts) >= 3:
            rows.append(("renamed", parts[2], parts[1]))
        elif len(parts) >= 2:
            rows.append(({"A": "added", "D": "deleted", "M": "modified"}.get(status, "modified"), parts[1], ""))
    return rows


def _line_ranges(root: Path, *diff_args: str) -> dict[str, list[tuple[int, int]]]:
    """用 -U0 精确拿到每个文件在新版本中的新增/修改行区间。"""
    code, out = _git(root, "diff", "-U0", "--relative", *diff_args)
    if code != 0:
        return {}
    ranges: dict[str, list[tuple[int, int]]] = {}
    current = ""
    for line in out.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            # /dev/null 表示删除，其行区间无意义
            current = "" if target == "/dev/null" else target.split("\t", 1)[0].removeprefix("b/")
        elif line.startswith("@@"):
            match = HUNK_RE.match(line)
            if not match or not current:
                continue
            start = int(match.group(3))
            length = int(match.group(4) or "1")
            if length <= 0:
                continue                        # 纯删除，新版本没有对应行
            ranges.setdefault(current, []).append((start, start + length - 1))
    return ranges


def _untracked_java(root: Path) -> list[str]:
    # 注意：git ls-files 没有 --relative 选项；git -C root 已让输出相对 root
    code, out = _git(root, "ls-files", "--others", "--exclude-standard")
    if code != 0:
        return []
    return [line.strip().replace("\\", "/") for line in out.splitlines() if line.strip().endswith(".java")]


def _full_range(path: Path) -> list[tuple[int, int]]:
    try:
        count = len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
    except OSError:
        return []
    return [(1, max(1, count))]


# ---------------- 依赖闭包 ----------------


def compute_closure(root: Path, changed: list[str], max_files: int = 4000) -> list[str]:
    """变更文件的依赖闭包：同包（同目录）文件 + import 了变更类的文件。

    这是 Checkmarx 增量扫描"变更文件加依赖闭包"的轻量实现。
    闭包文件不是本次变更，仅作为上下文一并分析，报告中会明确标注。
    """
    if not changed:
        return []
    all_java = [path for path in iter_java_files(root)]
    if len(all_java) > max_files:
        return []
    changed_set = set(changed)

    simple_names: set[str] = set()
    qualified: set[str] = set()
    directories: set[str] = set()
    for rel in changed:
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = ""
        package_match = PACKAGE_RE.search(text)
        package = package_match.group(1) + "." if package_match else ""
        qualified.add(package + Path(rel).stem)
        simple_names.add(Path(rel).stem)
        parent = str(Path(rel).parent).replace("\\", "/")
        if parent and parent != ".":
            directories.add(parent)

    closure: list[str] = []
    for path in all_java:
        rel = path.relative_to(root).as_posix()
        if rel in changed_set:
            continue
        parent = str(Path(rel).parent).replace("\\", "/")
        if parent in directories:
            closure.append(rel)
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        imports = set(IMPORT_RE.findall(text))
        if imports & qualified:
            closure.append(rel)
    return sorted(set(closure))


# ---------------- 主入口 ----------------


def collect_diff(
    root: Path,
    diff_ref: str | None = None,
    commit_ref: str | None = None,
    *,
    closure: bool = True,
) -> DiffContext:
    """收集 Git 增量上下文。非 Git 目录或 git 不可用时返回 available=False。"""
    context = DiffContext()
    if not is_git_repo(root):
        context.notes.append("目标目录不在 Git 仓库中，已回退为全量扫描。")
        return context
    context.repo_root = _repo_root(root)

    if commit_ref:
        # 单次提交引入的变更：diff 是 <commit>^ → <commit>，旧版本取父提交
        code, _ = _git(root, "rev-parse", "--verify", "--quiet", f"{commit_ref}^")
        has_parent = code == 0
        diff_args = (f"{commit_ref}^", commit_ref) if has_parent else (commit_ref,)
        context.mode = "commit"
        context.base = commit_ref
        context.old_ref = f"{commit_ref}^" if has_parent else commit_ref
        if not has_parent:
            context.notes.append(f"无法解析 {commit_ref} 的父提交（可能是根提交），已改为与 {commit_ref} 直接比较。")
    elif diff_ref:
        # 相对指定分支/提交的累计变更
        context.mode = "ref"
        context.base = diff_ref
        context.old_ref = diff_ref
        diff_args = (diff_ref,)
    else:
        # 工作区未提交变更（含已暂存与未暂存）
        context.mode = "working"
        context.base = "HEAD"
        context.old_ref = "HEAD"
        diff_args = ("HEAD",)

    rows = _name_status(root, *diff_args)
    ranges = _line_ranges(root, *diff_args)

    if context.mode == "working":
        for rel in _untracked_java(root):
            rows.append(("added", rel, ""))
            ranges.setdefault(rel, _full_range(root / rel))

    files: list[FileChange] = []
    for status, rel, old_path in rows:
        normalized = rel.replace("\\", "/")
        files.append(FileChange(
            path=normalized,
            status=status,
            ranges=ranges.get(normalized, []),
            old_path=old_path,
            java=normalized.endswith(".java"),
        ))
    context.files = files
    context.available = True
    _, head = _git(root, "rev-parse", "HEAD")
    context.head_commit = head.strip()
    if context.mode == "commit":
        _, target = _git(root, "rev-parse", context.base)
        context.target_commit = target.strip()
    else:
        context.target_commit = context.head_commit
    java_changed = context.java_files
    if closure:
        context.closure = compute_closure(root, java_changed)
    else:
        context.notes.append("已按 --changed-only 关闭依赖闭包：只分析变更文件本身。")

    lines_added = sum(end - start + 1 for item in context.files for start, end in item.ranges)
    context.stats = {
        "files_changed": len(context.files),
        "java_files_changed": len(java_changed),
        "files_added": sum(1 for item in context.files if item.status == "added"),
        "files_deleted": sum(1 for item in context.files if item.status == "deleted"),
        "closure_files": len(context.closure),
        "lines_changed": lines_added,
    }
    if not context.files:
        context.notes.append(f"与 {context.base} 相比没有任何变更，扫描范围不变。")
    return context


def build_old_snapshot(root: Path, context: DiffContext, dest: Path | None = None, git_root: Path | None = None) -> Path | None:
    """重建"变更前的源码快照"：当前源码 + 变更文件回退到旧版本。

    用于对比权限声明在本次变更前后是否被移除或放宽。
    git_root 与 root 分离：分析历史提交时 root 是临时快照目录（不是 Git 仓库），
    取旧版本内容必须回到原始仓库执行。
    """
    if not context.available or not context.files:
        return None
    target = Path(dest) if dest else Path(tempfile.mkdtemp(prefix="java-audit-old-"))
    target.mkdir(parents=True, exist_ok=True)
    changed = {item.path: item for item in context.files if item.java}
    restored = 0
    for path in iter_java_files(root):
        rel = path.relative_to(root).as_posix()
        out_path = target / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        change = changed.get(rel)
        if change is None:
            try:
                out_path.write_bytes(path.read_bytes())
            except OSError:
                pass
            continue
        # 新增文件在旧版本中不存在；删除/重命名文件用旧路径取回
        source_ref = f"{context.old_ref}:{change.old_path or rel}"
        if change.status == "added":
            continue
        code, old_text = _git(git_root or root, "show", source_ref)
        if code != 0 or not old_text:
            continue
        out_path.write_text(old_text, encoding="utf-8", errors="replace")
        restored += 1
    return target if restored else None


def build_revision_snapshot(root: Path, ref: str, dest: Path) -> Path:
    """重建某个提交状态下的源码快照（只含 Java 文件，保持相对路径）。

    分析历史提交时必须用它：工作树内容早已不是那个提交的状态，
    直接扫描当前文件会把"该提交引入的问题"扫成"没有问题"，这是危险的假阴性。
    """
    dest.mkdir(parents=True, exist_ok=True)
    code, listing = _git(root, "ls-tree", "-r", "--name-only", ref)
    if code != 0:
        return dest
    for rel in listing.splitlines():
        rel = rel.strip().replace("\\", "/")
        if not rel.endswith(".java"):
            continue
        file_code, text = _git(root, "show", f"{ref}:{rel}")
        if file_code != 0:
            continue
        out_path = dest / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8", errors="replace")
    return dest


def needs_revision_snapshot(context: DiffContext) -> bool:
    """当前工作树是否不在被分析的提交上（--commit 指向历史提交）。"""
    return bool(
        context.available and context.mode == "commit"
        and context.head_commit and context.target_commit
        and context.head_commit != context.target_commit
    )


# ---------------- 权限变更对比 ----------------


def _endpoint_key(endpoint) -> tuple[str, str]:
    return (str(endpoint.http_method).upper(), endpoint.route)


def compare_authorization(old_matrix, new_matrix) -> list[dict[str, object]]:
    """对比两次快照的端点权限声明，识别放宽、收紧、新增与移除。"""
    old_map = {_endpoint_key(item): item for item in getattr(old_matrix, "endpoints", [])}
    new_map = {_endpoint_key(item): item for item in getattr(new_matrix, "endpoints", [])}
    changes: list[dict[str, object]] = []

    for key, new_item in sorted(new_map.items()):
        old_item = old_map.get(key)
        method, route = key
        row = {
            "method": method,
            "route": route,
            "old_requirement": getattr(old_item, "requirement", "") if old_item else "",
            "new_requirement": new_item.requirement,
            "old_roles": (old_item.roles + old_item.permissions) if old_item else [],
            "new_roles": (new_item.roles + new_item.permissions),
            "finding_count": new_item.finding_count,
            "dangerous_ops": list(new_item.dangerous_ops),
        }
        if old_item is None:
            row["change"] = "added"
            row["risk"] = "review" if new_item.requirement in ("unknown", "anonymous") else "info"
            row["detail"] = "本次新增端点" + ("，且未发现权限声明" if new_item.requirement in ("unknown", "anonymous") else "")
            changes.append(row)
            continue

        old_strength = REQUIREMENT_STRENGTH.get(old_item.requirement, 1)
        new_strength = REQUIREMENT_STRENGTH.get(new_item.requirement, 1)
        old_roles = set(old_item.roles) | set(old_item.permissions)
        new_roles = set(new_item.roles) | set(new_item.permissions)

        if new_item.requirement == "unknown" and old_item.requirement != "unknown":
            row["change"] = "weakened"
            row["risk"] = "high"
            row["detail"] = f"权限声明被移除（原为 {REQUIREMENT_LABELS.get(old_item.requirement, old_item.requirement)}），需确认是否有意"
        elif new_strength < old_strength:
            row["change"] = "weakened"
            row["risk"] = "high"
            row["detail"] = f"身份要求由 {REQUIREMENT_LABELS.get(old_item.requirement, old_item.requirement)} 放宽为 {REQUIREMENT_LABELS.get(new_item.requirement, new_item.requirement)}"
        elif old_roles - new_roles and new_roles:
            row["change"] = "weakened"
            row["risk"] = "medium"
            row["detail"] = f"角色/权限要求减少：移除 {', '.join(sorted(old_roles - new_roles))}"
        elif new_strength > old_strength or (new_roles - old_roles):
            row["change"] = "strengthened"
            row["risk"] = "info"
            row["detail"] = "权限要求收紧"
        elif old_roles != new_roles:
            row["change"] = "role_changed"
            row["risk"] = "review"
            row["detail"] = f"角色/权限变化：{', '.join(sorted(old_roles)) or '—'} → {', '.join(sorted(new_roles)) or '—'}"
        else:
            continue
        changes.append(row)

    for key, old_item in sorted(old_map.items()):
        if key in new_map:
            continue
        changes.append({
            "method": key[0], "route": key[1],
            "old_requirement": old_item.requirement, "new_requirement": "",
            "old_roles": old_item.roles + old_item.permissions, "new_roles": [],
            "change": "removed", "risk": "info",
            "detail": "端点在本次变更中被移除",
            "finding_count": 0, "dangerous_ops": [],
        })
    order = {"high": 0, "medium": 1, "review": 2, "info": 3}
    changes.sort(key=lambda item: (order.get(str(item["risk"]), 9), str(item["route"])))
    return changes


# ---------------- 修复验证与同类位置 ----------------


def load_baseline_details(path: Path | None) -> dict[str, dict[str, object]]:
    """从上一份 report.json 读取发现的详情，用于判断修复是否真正切断路径。"""
    if path is None or not Path(path).is_file():
        return {}
    import json
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}
    details: dict[str, dict[str, object]] = {}
    for item in payload.get("findings", []):
        fingerprint = item.get("fingerprint")
        if not fingerprint:
            continue
        location = item.get("location") or {}
        details[str(fingerprint)] = {
            "rule_id": item.get("rule_id", ""),
            "path": location.get("path", ""),
            "line": location.get("line", 0),
            "severity": item.get("severity", ""),
            "cwe": item.get("cwe", ""),
        }
    return details


def analyze_incremental(
    context: DiffContext,
    findings: list,
    baseline: dict[str, object] | None,
    baseline_details: dict[str, dict[str, object]] | None,
    authz_changes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """汇总增量结论：新增路径、同类新位置、修复验证、权限变更。"""
    result: dict[str, object] = {
        "enabled": bool(context.available),
        "mode": context.mode,
        "base": context.base,
        "stats": dict(context.stats),
        "changed_files": [item.to_dict() for item in context.files if item.java],
        "closure_files": list(context.closure),
        "notes": list(context.notes),
        "new_findings": [],
        "variant_findings": [],
        "fixed_findings": [],
        "authz_changes": authz_changes or [],
        "review_focus": [],
    }
    if not context.available:
        result["summary"] = "未启用增量审计（非 Git 仓库或未指定 diff）。"
        return result

    baseline = baseline or {}
    baseline_new = set(baseline.get("new") or [])
    baseline_fixed = set(baseline.get("fixed") or [])
    baseline_enabled = bool(baseline.get("enabled"))

    # 当前发现按 (rule, path) 建索引，用于判断"疑似未真正修复"
    live_index: dict[tuple[str, str], list[dict]] = {}
    for finding in findings:
        live_index.setdefault((finding.rule_id, finding.location.path), []).append({
            "line": finding.location.line,
            "fingerprint": finding.fingerprint,
        })

    variant_seen: set[str] = set()
    for finding in findings:
        in_change = context.hits_change(finding.location.path, finding.location.line)
        is_new = (finding.fingerprint in baseline_new) if baseline_enabled else in_change
        if not (is_new or in_change):
            continue
        row = {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "cwe": finding.cwe,
            "path": finding.location.path,
            "line": finding.location.line,
            "in_changed_lines": in_change,
            "new_vs_baseline": finding.fingerprint in baseline_new,
            "endpoint": (finding.metadata.get("authorization") or {}).get("endpoint", ""),
            "requirement": (finding.metadata.get("authorization") or {}).get("requirement", ""),
        }
        result["new_findings"].append(row)  # type: ignore[union-attr]
        # 同类新位置：本轮新增，且同一规则在存量发现中已经出现过
        if is_new and finding.rule_id in variant_seen:
            result["variant_findings"].append(row)  # type: ignore[union-attr]
        variant_seen.add(finding.rule_id)

    for fingerprint in sorted(baseline_fixed):
        detail = (baseline_details or {}).get(fingerprint, {})
        rule_id = str(detail.get("rule_id", ""))
        path = str(detail.get("path", ""))
        survivors = live_index.get((rule_id, path), [])
        if survivors:
            status = "疑似未真正修复"
            note = f"同规则同文件仍有 {len(survivors)} 处命中（行 {', '.join(str(s['line']) for s in survivors[:5])}），需确认原路径是否已被切断"
        else:
            status = "已消失"
            note = "原命中不再出现；建议重新扫描确认路径已被切断"
        result["fixed_findings"].append({  # type: ignore[union-attr]
            "fingerprint": fingerprint,
            "rule_id": rule_id,
            "path": path,
            "line": detail.get("line", 0),
            "severity": detail.get("severity", ""),
            "status": status,
            "note": note,
        })

    # 复核焦点：把最值得看的事情挑出来
    weakened = [item for item in (authz_changes or []) if item.get("change") == "weakened"]
    high_new = [item for item in result["new_findings"] if item.get("in_changed_lines") and item.get("severity") in ("critical", "high")]  # type: ignore[union-attr]
    focus: list[str] = []
    if weakened:
        focus.append(f"{len(weakened)} 个端点的权限声明被放宽或移除，优先复核")
    if high_new:
        focus.append(f"本次变更引入 {len(high_new)} 条高危及以上发现")
    if result["variant_findings"]:  # type: ignore[union-attr]
        focus.append(f"{len(result['variant_findings'])} 处属于已确认规则的同类新位置")  # type: ignore[union-attr]
    if result["fixed_findings"]:  # type: ignore[union-attr]
        unresolved = sum(1 for item in result["fixed_findings"] if item.get("status") == "疑似未真正修复")  # type: ignore[union-attr]
        resolved = len(result["fixed_findings"]) - unresolved  # type: ignore[union-attr]
        if unresolved:
            focus.append(f"{unresolved} 条基线命中仍有同规则残留，需确认修复是否真正切断路径")
        if resolved:
            focus.append(f"{resolved} 条基线命中已消失，建议重新扫描确认原路径不再可达")
    if context.closure:
        focus.append(f"依赖闭包纳入 {len(context.closure)} 个未变更文件作为上下文")
    result["review_focus"] = focus
    result["summary"] = "；".join(focus) if focus else "本次变更未引入需要优先复核的新证据。"
    return result

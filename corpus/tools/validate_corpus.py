#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""语料校验器。

检查每个案例的目录结构、expected.json 完整性、规则 ID 有效性、
行号是否仍指向规则命中点（防漂移），以及匿名化卫生
（阻止真实凭据、内网 IP、邮箱、本机用户目录等进入语料）。

零第三方依赖，只用标准库。用法（在仓库根目录）：

    python corpus/tools/validate_corpus.py [语料目录，默认 corpus]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from audit.runners.builtin import RULES  # noqa: E402

RULE_BY_ID = {rule.rule_id: rule for rule in RULES}
CASE_ID_RE = re.compile(r"^[A-Z]+-\d{3}$")
VARIANTS = {"vulnerable", "safe", "edge"}

# 匿名化卫生：命中即报错。allowlist 中的测试占位符除外。
HYGIENE_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "疑似 OpenAI 风格 API Key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "疑似 AWS Access Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "疑似 GitHub Token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "疑似 Slack Token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "私钥内容"),
    (re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"), "内网 IP"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"), "邮箱地址"),
    (re.compile(r"C:\\Users\\[^\\/\s]+|/home/[^/\s]+/", re.I), "本机用户目录"),
    (re.compile(r"\b[A-Za-z]:[\\/](?![/\\])"), "Windows 绝对路径"),
    (re.compile(r"\b1[3-9]\d{9}\b"), "疑似手机号"),
    (re.compile(r"\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"), "疑似身份证号"),
]
HYGIENE_ALLOWLIST = (
    "CORPUS_FAKE", "example.com", "example.org", "lab.corpus",
    "127.0.0.1", "maven.apache.org", "w3.org", "springframework",
)

REQUIRED_BASE = ("case_id", "title", "category", "expected", "source", "license")
TEXT_SUFFIXES = {
    ".java", ".json", ".xml", ".md", ".yml", ".yaml", ".properties",
    ".env", ".sh", ".ps1", ".bat", ".cmd", ".toml", ".gradle", ".kts",
}
TEXT_NAMES = {"Dockerfile", ".env", "Jenkinsfile"}
IGNORED_DIRS = {".git", ".java-audit-cache", "__pycache__", "target", "build", "dist"}


JSON_TYPES = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}


def validate_schema_subset(data: dict, schema: dict, tag: str, errors: list[str]) -> None:
    """Enforce the field constraints used by the bundled JSON Schema without dependencies."""
    for field in schema.get("required") or []:
        if field not in data or data[field] in (None, ""):
            errors.append(f"{tag}: expected.json 缺少 schema 必填字段 {field}")
    for field, spec in (schema.get("properties") or {}).items():
        if field not in data:
            continue
        expected_type = JSON_TYPES.get(str(spec.get("type", "")))
        value = data[field]
        if expected_type and (not isinstance(value, expected_type) or (expected_type is int and isinstance(value, bool))):
            errors.append(f"{tag}: {field} 类型应为 {spec.get('type')}")
            continue
        if spec.get("enum") and value not in spec["enum"]:
            errors.append(f"{tag}: {field} 不在允许值 {spec['enum']} 中")
        if spec.get("pattern") and isinstance(value, str) and not re.match(str(spec["pattern"]), value):
            errors.append(f"{tag}: {field} 不符合格式 {spec['pattern']}")
        if isinstance(value, list) and int(spec.get("minItems", 0)) > len(value):
            errors.append(f"{tag}: {field} 至少需要 {spec['minItems']} 项")


def check_case(case_dir: Path, entry: dict, schema: dict, errors: list[str], warnings: list[str]) -> dict | None:
    tag = str(case_dir.relative_to(case_dir.parents[2]))
    # 1. 目录与构建文件
    if not (case_dir / "pom.xml").is_file():
        errors.append(f"{tag}: 缺少 pom.xml")
    java_files = sorted((case_dir / "src" / "main" / "java").rglob("*.java")) if (case_dir / "src").is_dir() else []
    if not java_files:
        errors.append(f"{tag}: src/main/java 下没有 Java 源码")
    # 2. expected.json
    expected_path = case_dir / "expected.json"
    if not expected_path.is_file():
        errors.append(f"{tag}: 缺少 expected.json")
        return None
    try:
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{tag}: expected.json 无法解析：{exc}")
        return None
    if not isinstance(expected, dict):
        errors.append(f"{tag}: expected.json 顶层必须是对象")
        return None
    validate_schema_subset(expected, schema, tag, errors)
    # 3. 基础字段
    for field in REQUIRED_BASE:
        if not expected.get(field):
            errors.append(f"{tag}: expected.json 缺少必填字段 {field}")
    if expected.get("expected") not in ("vulnerable", "safe"):
        errors.append(f"{tag}: expected 只能是 vulnerable / safe，当前为 {expected.get('expected')!r}")
        return expected
    if not CASE_ID_RE.match(str(expected.get("case_id", ""))):
        errors.append(f"{tag}: case_id 必须形如 SQL-001，当前为 {expected.get('case_id')!r}")
    elif not case_dir.name.startswith(expected["case_id"] + "-"):
        errors.append(f"{tag}: 目录名应以 {expected['case_id']}- 开头")
    variant = case_dir.name.rsplit("-", 1)[-1]
    if variant not in VARIANTS:
        errors.append(f"{tag}: 目录名后缀应为 vulnerable/safe/edge，当前为 {variant!r}")
    if entry.get("case_id") != expected.get("case_id"):
        errors.append(f"{tag}: manifest 与 expected.json 的 case_id 不一致")
    if entry.get("expected") != expected.get("expected"):
        errors.append(f"{tag}: manifest 与 expected.json 的 expected 不一致")
    # 4. 规则 ID 有效性
    rule_ids = list(expected.get("expected_rules") or []) + list(expected.get("forbidden_rules") or [])
    for rule_id in rule_ids:
        if rule_id not in RULE_BY_ID:
            # taint/frameworks 引擎的规则不算错误，但提醒当前评测器未覆盖
            warnings.append(f"{tag}: 规则 {rule_id} 不在 builtin 规则集中（评测时不会被检查）")
    # 5. 危险样本：行号漂移检查
    if expected["expected"] == "vulnerable":
        builtin_rules = [r for r in expected.get("expected_rules") or [] if r in RULE_BY_ID]
        if not expected.get("expected_rules"):
            errors.append(f"{tag}: 危险样本缺少 expected_rules")
        if not expected.get("expected_locations"):
            errors.append(f"{tag}: 危险样本缺少 expected_locations")
        for loc in expected.get("expected_locations") or []:
            java_path = case_dir / str(loc.get("path", ""))
            if not java_path.is_file():
                errors.append(f"{tag}: expected_locations 指向不存在的文件 {loc.get('path')}")
                continue
            try:
                lines = java_path.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                errors.append(f"{tag}: 无法读取 {loc.get('path')}：{exc}")
                continue
            line_no = int(loc.get("line", 0))
            if not 1 <= line_no <= len(lines):
                errors.append(f"{tag}: 行号 {line_no} 超出 {loc.get('path')} 范围（共 {len(lines)} 行）")
                continue
            line_text = lines[line_no - 1]
            if builtin_rules and not any(RULE_BY_ID[r].pattern.search(line_text) for r in builtin_rules):
                errors.append(
                    f"{tag}: 行号漂移——{loc.get('path')}:{line_no} 不再命中任何 expected_rules：{line_text.strip()[:80]}"
                )
    else:
        if not expected.get("forbidden_rules"):
            errors.append(f"{tag}: 安全样本缺少 forbidden_rules")
    return expected


def hygiene_scan(scan_root: Path, errors: list[str], *, label_root: Path | None = None) -> None:
    """Scan corpus text without ever echoing a matched secret value."""
    display_root = label_root or scan_root
    for path in sorted(scan_root.rglob("*")):
        if not path.is_file() or any(part in IGNORED_DIRS for part in path.relative_to(scan_root).parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in TEXT_NAMES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = path.relative_to(display_root).as_posix()
        except ValueError:
            rel = path.name
        for pattern, label in HYGIENE_PATTERNS:
            for match in pattern.finditer(text):
                snippet = match.group(0)
                if any(marker in snippet for marker in HYGIENE_ALLOWLIST):
                    continue
                line_no = text.count("\n", 0, match.start()) + 1
                errors.append(f"匿名化卫生：{rel}:{line_no} {label}（内容已隐藏）")


def main(argv: list[str]) -> int:
    corpus = Path(argv[1]).resolve() if len(argv) > 1 else REPO / "corpus"
    manifest_path = corpus / "manifest.json"
    errors: list[str] = []
    warnings: list[str] = []
    if not manifest_path.is_file():
        print(f"错误：找不到 {manifest_path}", file=sys.stderr)
        return 2
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"错误：manifest.json 无法解析：{exc}", file=sys.stderr)
        return 2
    schema_path = corpus / "schemas" / "case.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"错误：case.schema.json 无法解析：{exc}", file=sys.stderr)
        return 2
    corpus = corpus.resolve()
    seen_dirs: list[Path] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    cases = manifest.get("cases") or []
    if not isinstance(cases, list):
        print("错误：manifest.json 的 cases 必须是列表", file=sys.stderr)
        return 2
    for entry in cases:
        if not isinstance(entry, dict):
            errors.append("manifest: 每个案例必须是对象")
            continue
        case_id = str(entry.get("case_id", ""))
        raw_path = str(entry.get("path", ""))
        if case_id in seen_ids:
            errors.append(f"manifest: case_id 重复：{case_id}")
        seen_ids.add(case_id)
        if raw_path in seen_paths:
            errors.append(f"manifest: 案例路径重复：{raw_path}")
        seen_paths.add(raw_path)
        case_dir = (corpus / raw_path).resolve()
        if not case_dir.is_relative_to(corpus):
            errors.append(f"manifest: 案例路径越过语料根目录：{raw_path}")
            continue
        seen_dirs.append(case_dir)
        if not case_dir.is_dir():
            errors.append(f"manifest: 案例目录不存在 {entry.get('path')}")
            continue
        check_case(case_dir, entry, schema, errors, warnings)
    # 扫描整个语料目录，覆盖 manifest、文档、结果文件、.env、Dockerfile 与 CI 脚本。
    hygiene_scan(corpus, errors, label_root=corpus)
    # manifest 与磁盘双向对齐
    on_disk = {p.parent for p in (corpus / "cases").rglob("expected.json")} if (corpus / "cases").is_dir() else set()
    for extra in sorted(on_disk - set(seen_dirs)):
        errors.append(f"manifest: 磁盘上存在未登记的案例 {extra.relative_to(corpus).as_posix()}")
    for message in warnings:
        print(f"[警告] {message}")
    if errors:
        for message in errors:
            print(f"[失败] {message}")
        print(f"\n校验未通过：{len(errors)} 个错误，{len(warnings)} 个警告。")
        return 1
    total = len(cases)
    vuln = sum(1 for c in cases if isinstance(c, dict) and c.get("expected") == "vulnerable")
    print(f"校验通过：{total} 个案例（危险 {vuln} / 安全 {total - vuln}），{len(warnings)} 个警告，0 个错误。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

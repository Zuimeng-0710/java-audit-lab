from __future__ import annotations

import hashlib
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from ..findings import Finding, Location
from ..project import iter_java_files
from .base import RunnerResult


# Single-file threshold below which process-pool overhead exceeds the savings.
# Tuned against the 500-file benchmark: 2→3ms serial vs 200ms spawn cost.
PARALLEL_THRESHOLD = 32
MAX_WORKERS = 8


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    title: str
    cwe: str
    severity: str
    confidence: str
    pattern: re.Pattern[str]
    description: str
    review_steps: tuple[str, ...]
    remediation: str


# The educational rule set is intentionally small, conservative and explainable.
# It is also re-exported as JSON via `java-audit rules --json` so external tooling
# can render it without importing the package.
RULES = (
    Rule(
        "JAL-SQL-001", "SQL 字符串拼接", "CWE-89", "high", "medium",
        re.compile(r"(?:executeQuery|executeUpdate|prepareStatement|createQuery)\s*\([^;\n]*\+"),
        "SQL 执行点接收了拼接表达式；若拼接值来自外部输入，可能改变 SQL 结构。",
        ("找出拼接变量的来源，确认是否来自请求、消息或文件。", "检查是否存在白名单或参数化处理。", "用安全测试数据验证 SQL 结构能否被改变。"),
        "使用 PreparedStatement 占位符绑定数据；动态表名或排序字段使用固定白名单。",
    ),
    Rule(
        "JAL-CMD-001", "动态系统命令", "CWE-78", "critical", "medium",
        re.compile(r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\([^;\n]*(?:\+|\b(?:input|param|cmd|command|user)\w*\b)", re.I),
        "命令执行 API 的参数看起来包含动态数据，可能允许攻击者改变程序行为。",
        ("追踪命令参数是否来自不可信边界。", "确认参数是直接传给进程还是经过 shell 解释。", "检查允许值是否采用严格白名单。"),
        "避免执行系统命令；确有需要时使用固定程序和独立参数列表，并对白名单值做校验。",
    ),
    Rule(
        "JAL-PATH-001", "外部输入参与文件路径", "CWE-22", "high", "low",
        re.compile(r"new\s+(?:File|FileInputStream|FileOutputStream)\s*\([^;\n]*(?:\+|\b(?:path|file|name|input|param|user)\w*\b)", re.I),
        "文件访问路径含动态值；若缺少边界检查，可能访问预期目录之外的文件。",
        ("确定路径片段是否由用户控制。", "检查 normalize/toRealPath 后是否验证 allowedRoot。", "考虑符号链接、绝对路径和编码后的 ../。"),
        "对规范化后的真实路径执行目录边界检查，并优先使用服务端生成的文件标识。",
    ),
    Rule(
        "JAL-XXE-001", "XML 解析器缺少可见的加固配置", "CWE-611", "high", "low",
        re.compile(r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(\)"),
        "创建了 XML 解析器工厂；当前行无法证明外部实体和 DTD 已被禁用。",
        ("查看工厂创建后到 parse 调用前的全部配置。", "确认禁用 DOCTYPE、外部通用实体和外部参数实体。", "用与实际解析器实现匹配的测试验证配置。"),
        "按照所用 XML API 设置禁止 DTD/外部实体的选项，并限制外部资源访问。",
    ),
    Rule(
        "JAL-SECRET-001", "疑似硬编码凭据", "CWE-798", "high", "medium",
        re.compile(r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|token)\b\s*=\s*\"[^\"]{6,}\"", re.I),
        "名称类似凭据的变量被赋予固定字符串，可能导致秘密进入版本历史或构建产物。",
        ("判断该值是示例、测试夹具还是真实凭据。", "搜索同一值是否出现在配置和历史中。", "若是真实凭据，先轮换再清理历史。"),
        "从环境变量或秘密管理服务读取，并避免在日志和异常中输出该值。",
    ),
    Rule(
        "JAL-DESER-001", "Java 原生反序列化", "CWE-502", "critical", "low",
        re.compile(r"\b[A-Za-z_$][\w$]*\.readObject\s*\(\s*\)"),
        "发现 Java 原生反序列化入口；风险取决于输入是否可控以及类路径中的可利用类型。",
        ("追踪 ObjectInputStream 的底层输入来源。", "确认是否存在类型白名单或 ObjectInputFilter。", "检查依赖中是否存在危险 gadget 链。"),
        "优先改用结构化安全格式；必须兼容时配置严格 ObjectInputFilter 并认证数据来源。",
    ),
    Rule(
        "JAL-SSRF-001", "动态服务端请求目标", "CWE-918", "high", "low",
        re.compile(r"new\s+URL\s*\(\s*(?!\")[A-Za-z_$][\w$]*|\.openConnection\s*\(\s*\)"),
        "发现动态 URL 或网络连接创建点，需要确认外部输入能否控制请求目标。",
        ("追踪协议、主机、端口和路径的来源。", "解析 DNS 后检查所有目标 IP。", "验证重定向后是否重新执行相同限制。"),
        "使用目标白名单，禁止非 HTTP(S) 协议、私网和元数据地址，并限制重定向。",
    ),
    Rule(
        "JAL-SPEL-001", "动态表达式解析", "CWE-917", "critical", "medium",
        re.compile(r"\.parseExpression\s*\(\s*(?!\")[A-Za-z_$][\w$]*"),
        "表达式解析 API 接收动态变量；若变量可控，可能执行非预期属性或方法访问。",
        ("追踪表达式字符串来源。", "确认 EvaluationContext 暴露的对象和类型。", "区分表达式本身与安全变量绑定。"),
        "固定表达式结构，将动态数据作为变量绑定，并使用受限的求值上下文。",
    ),
    Rule(
        "JAL-CRYPTO-001", "弱哈希算法", "CWE-327", "medium", "high",
        re.compile(r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"", re.I),
        "检测到 MD5 或 SHA-1；如果用于密码、签名或安全完整性，该算法不再合适。",
        ("确认散列值的业务用途。", "若用于密码，检查是否采用专用慢哈希及随机盐。", "若用于签名或完整性，确认是否可迁移到 SHA-256 以上。"),
        "密码使用 Argon2、scrypt、bcrypt 或 PBKDF2；完整性和签名根据协议使用现代算法。",
    ),
    Rule(
        "JAL-AUTH-001", "疑似明文密码比较", "CWE-256", "high", "medium",
        re.compile(r"(?:password|passwd|pwd)\s*\.equals\s*\(|\.equals\s*\(\s*\w*(?:password|passwd|pwd)\w*\s*\)", re.I),
        "密码字段直接参与 equals 比较，可能表示系统存储或处理了明文密码。",
        ("确认比较两侧数据的来源与存储形式。", "检查注册、改密和导入路径是否统一采用密码哈希。", "确认迁移旧密码时不会继续保留明文。"),
        "使用 Argon2、bcrypt、scrypt 或 PBKDF2 验证密码，并为每个密码使用独立随机盐。",
    ),
    Rule(
        "JAL-LOG-001", "日志中疑似包含敏感对象", "CWE-532", "high", "medium",
        re.compile(r"(?:log|logger)\.(?:trace|debug|info|warn|error)\s*\([^;\n]*(?:password|passwd|pwd|token|secret|loginDTO|loginDto)", re.I),
        "日志调用包含密码、令牌或登录对象名称，可能把凭据写入日志系统。",
        ("确认对象 toString 是否包含敏感字段。", "检查生产日志级别与集中日志保留策略。", "搜索异常处理和审计日志中的同类输出。"),
        "只记录必要的非敏感标识；对令牌、密码和密钥使用字段级屏蔽且不记录原值。",
    ),
    Rule(
        "JAL-TOKEN-001", "从 URL 查询参数读取令牌", "CWE-598", "high", "high",
        re.compile(r"getParameter\s*\([^;\n]*(?:token|jwt|authorization)[^;\n]*\)", re.I),
        "身份令牌从查询参数读取，可能进入浏览器历史、代理日志和 Referer。",
        ("确认该参数是否承担登录身份认证。", "检查网关、Web 服务器和 APM 是否记录完整 URL。", "确认是否同时支持安全的 Authorization 请求头。"),
        "通过 Authorization 请求头传递短期令牌，并禁用 URL 参数回退。",
    ),
)


def load_extra_rules(paths: list[str] | None) -> tuple[Rule, ...]:
    """Load community rules from YAML/JSON files; merge with built-ins.

    Rule files may declare a small subset of fields; missing fields fall back
    to conservative defaults so a misconfigured rule never crashes the scan.
    Schema (one rule per item):
        - id, title, cwe, severity, confidence, pattern, description,
          review_steps (list), remediation
    """
    if not paths:
        return RULES
    from ..config import _simple_yaml
    import json as _json
    extras: list[Rule] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8-sig")
        try:
            data = _json.loads(text) if path.suffix.lower() == ".json" else _simple_yaml(text)
        except (ValueError, _json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict) or not item.get("id") or not item.get("pattern"):
                continue
            try:
                rule = Rule(
                    rule_id=str(item["id"]),
                    title=str(item.get("title", "外部规则")),
                    cwe=str(item.get("cwe", "CWE-Unknown")),
                    severity=str(item.get("severity", "medium")),
                    confidence=str(item.get("confidence", "medium")),
                    pattern=re.compile(item["pattern"]),
                    description=str(item.get("description", "")),
                    review_steps=tuple(item.get("review_steps") or ["人工确认线索与上下文。"]),
                    remediation=str(item.get("remediation", "")),
                )
            except re.error:
                continue
            extras.append(rule)
    return (*RULES, *extras)


SOURCE_PATTERN = re.compile(r"(?:getParameter|getHeader|getInputStream|@RequestParam|@PathVariable|@RequestBody|readLine)\b")
IDENTIFIER_PATTERN = re.compile(r"\b[A-Za-z_$][\w$]*\b")


def _local_trace(lines: list[str], sink_index: int, path: str, sink_line: str) -> list[dict[str, object]]:
    """Build a conservative, explainable same-file trace without claiming full data flow."""
    sink_names = set(IDENTIFIER_PATTERN.findall(sink_line))
    trace: list[dict[str, object]] = []
    start = max(0, sink_index - 40)
    for index in range(start, sink_index):
        candidate = lines[index]
        stripped = candidate.strip()
        if not stripped:
            continue
        names = set(IDENTIFIER_PATTERN.findall(candidate))
        if SOURCE_PATTERN.search(candidate):
            trace.append({"kind": "source-candidate", "path": path, "line": index + 1, "label": f"疑似外部输入：{stripped[:160]}"})
        elif "(" in candidate and ")" in candidate and "{" in candidate and sink_names.intersection(names):
            trace.append({"kind": "parameter-candidate", "path": path, "line": index + 1, "label": f"疑似方法参数来源：{stripped[:160]}"})
        elif "=" in candidate and sink_names.intersection(names):
            trace.append({"kind": "propagation-candidate", "path": path, "line": index + 1, "label": f"可能的赋值传播：{stripped[:160]}"})
    trace.append({"kind": "sink", "path": path, "line": sink_index + 1, "label": f"规则命中点：{sink_line.strip()[:160]}"})
    return trace[-8:]


def _scan_file(task: tuple[str, str, tuple[Rule, ...]]) -> list[Finding]:
    """Worker: scan one Java file against all rules. Top-level for picklability."""
    abs_path_str, root_str, rules = task
    path = Path(abs_path_str)
    root = Path(root_str)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    relative = path.relative_to(root).as_posix()
    lines = content.splitlines()
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        for rule in rules:
            match = rule.pattern.search(line)
            if not match:
                continue
            identity = f"{rule.rule_id}:{relative}:{line_number}:{line.strip()}"
            trace = _local_trace(lines, line_number - 1, relative, line)
            findings.append(Finding(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                cwe=rule.cwe,
                scanner="builtin",
                location=Location(relative, line_number, match.start() + 1),
                evidence=line.strip()[:500],
                description=rule.description,
                review_steps=list(rule.review_steps),
                remediation=rule.remediation,
                fingerprint=hashlib.sha256(identity.encode()).hexdigest()[:16],
                trace=trace,
                metadata={"educational_rule": True},
            ))
    return findings


class BuiltinRunner:
    name = "builtin"

    def __init__(self, progress: bool = False, rules: tuple[Rule, ...] | None = None, workers: int | None = None) -> None:
        # progress=True prints a compact stderr counter during large scans.
        # rules=None uses the built-in RULES tuple; pass load_extra_rules(...) to merge.
        self._progress = progress
        self._rules = rules if rules is not None else RULES
        self._workers = workers

    def run(self, root: Path, work_dir: Path) -> RunnerResult:
        files = list(iter_java_files(root))
        findings: list[Finding] = []

        if len(files) < PARALLEL_THRESHOLD:
            for path in files:
                findings.extend(_scan_file((str(path), str(root), self._rules)))
            if self._progress:
                print(f"[builtin] {len(files)} files (serial)", file=sys.stderr)
        else:
            workers = self._workers or min(MAX_WORKERS, os.cpu_count() or 4)
            chunksize = max(1, len(files) // (workers * 8))
            tasks = [(str(path), str(root), self._rules) for path in files]
            completed = 0
            next_mark = len(tasks) // 10
            with ProcessPoolExecutor(max_workers=workers) as pool:
                for batch in pool.map(_scan_file, tasks, chunksize=chunksize):
                    findings.extend(batch)
                    completed += 1
                    if self._progress and completed >= next_mark:
                        print(f"[builtin] {completed}/{len(tasks)}", file=sys.stderr)
                        next_mark += len(tasks) // 10
            if self._progress:
                print(f"[builtin] done: {len(findings)} findings across {len(files)} files (workers={workers})", file=sys.stderr)

        return RunnerResult(
            name=self.name,
            available=True,
            success=True,
            findings=findings,
            message=f"内置教学规则完成，共匹配 {len(findings)} 条待复核发现。",
        )

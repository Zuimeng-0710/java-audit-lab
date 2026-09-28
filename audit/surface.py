"""Stage 1-2 of the evidence driven playbook: entry points and trust boundaries.

The collector is intentionally conservative: every entry is a *candidate* surface
that a human must correlate with findings. It never claims a route is exploitable.
"""

from __future__ import annotations

import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .project import iter_java_files


ROUTE_PATTERN = re.compile(
    r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?"
    r"(?:\"([^\"]*)\"|'([^']*)')?\s*[,)]"
)
CONTROLLER_PATTERN = re.compile(r"@(?:Rest)?Controller\b")
REQUEST_SOURCE_PATTERN = re.compile(
    r"@RequestParam\b|@PathVariable\b|@RequestBody\b|HttpServletRequest\b|ServerWebExchange\b"
)
FILTER_PATTERN = re.compile(r"\bimplements\s+(?:javax\.servlet\.|jakarta\.servlet\.)?Filter\b|OncePerRequestFilter\b")
INTERCEPTOR_PATTERN = re.compile(r"HandlerInterceptor\b|WebMvcConfigurer\b")
SECURITY_CONFIG_PATTERN = re.compile(r"SecurityFilterChain\b|WebSecurityConfigurerAdapter\b|@EnableWebSecurity\b")
UPLOAD_PATTERN = re.compile(r"\bMultipartFile\b")
MQ_CONSUMER_PATTERN = re.compile(r"@(?:Kafka|Rabbit|Jms|Stream|RocketMQ)Listener\b")
SCHEDULED_PATTERN = re.compile(r"@Scheduled\b")
MYBATIS_DOLLAR_PATTERN = re.compile(r"\$\{")
MYBATIS_ANNOTATION_PATTERN = re.compile(r"@(?:Select|Update|Delete|Insert)\s*\(")
JPA_NATIVE_PATTERN = re.compile(r"@Query\s*\([^)]*nativeQuery\s*=\s*true", re.I)
REFLECTION_PATTERN = re.compile(r"\.invoke\s*\(|Class\.forName\s*\(")

CONTROL_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("deserialization-filter", re.compile(r"ObjectInputFilter\b"), "存在 ObjectInputFilter 反序列化类型过滤"),
    ("xxe-hardening", re.compile(r"disallow-doctype-decl|external-general-entities|SUPPORT_DTD|XMLConstants\.ACCESS_EXTERNAL"), "XML 解析器显式配置了 XXE 防护"),
    ("path-boundary-check", re.compile(r"(?:toRealPath|normalize)\s*\(\s*\)[^;\n]{0,80}startsWith\("), "文件路径做了规范化后的目录边界检查"),
    ("parameterized-query", re.compile(r"prepareStatement\s*\(\s*\"[^\"]*\?[^\"]*\"\s*\)"), "SQL 使用占位符参数化"),
    ("authorization-annotation", re.compile(r"@PreAuthorize\b|@Secured\b|@RolesAllowed\b|hasRole\s*\(|hasAuthority\s*\("), "存在方法级授权注解或表达式"),
)


@dataclass(slots=True)
class Entry:
    kind: str
    path: str
    line: int
    detail: str
    trust_boundary: str = ""
    route: str = ""
    http_method: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class Control:
    kind: str
    path: str
    line: int
    detail: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class AttackSurface:
    entries: list[Entry] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)
    dynamic_calls: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "entries": [item.to_dict() for item in self.entries],
            "controls": [item.to_dict() for item in self.controls],
            "dynamic_calls": self.dynamic_calls,
            "entry_count": len(self.entries),
            "control_count": len(self.controls),
        }

    def entries_by_kind(self) -> dict[str, list[Entry]]:
        grouped: dict[str, list[Entry]] = {}
        for entry in self.entries:
            grouped.setdefault(entry.kind, []).append(entry)
        return grouped


KIND_LABELS = {
    "controller": "HTTP 接口入口",
    "filter": "请求过滤链",
    "interceptor": "请求拦截器",
    "security-config": "安全配置",
    "upload": "文件上传入口",
    "mq-consumer": "消息队列消费者",
    "scheduled": "定时任务入口",
    "mybatis-dynamic": "MyBatis 动态 SQL",
    "jpa-native": "JPA 原生查询",
    "request-source": "外部输入参数",
}


def _class_routes(lines: list[str]) -> str:
    """Best-effort class level @RequestMapping prefix."""
    for line in lines[:200]:
        match = re.search(r"@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?[\"']([^\"']+)[\"']", line)
        if match:
            return match.group(1).rstrip("/")
    return ""


def _match_controller(entries: list, is_controller: bool, class_prefix: str, relative: str, number: int, stripped: str) -> None:
    route_match = ROUTE_PATTERN.search(stripped)
    if route_match:
        route = route_match.group(1) or route_match.group(2) or ""
        method_match = re.match(r"@(\w+)Mapping", stripped)
        http_method = (method_match.group(1).upper() if method_match else "REQUEST") if is_controller else "REQUEST"
        entries.append(Entry(
            "controller", relative, number,
            f"路由 {http_method} {class_prefix}/{route.lstrip('/')}".replace("//", "/") or "路由映射",
            "HTTP 请求直接触达的服务端入口",
            route=f"{class_prefix}/{route.lstrip('/')}".replace("//", "/"),
            http_method=http_method,
        ))
    elif is_controller and CONTROLLER_PATTERN.search(stripped):
        entries.append(Entry("controller", relative, number, "控制器类声明", "HTTP 请求直接触达的服务端入口"))


def _scan_surface_file(task: tuple[str, str]) -> dict[str, list]:
    """Worker: scan one Java file for surface evidence. Top-level for picklability.

    Returns a plain dict to keep cross-process pickling cheap and JSON-friendly.
    """
    abs_path_str, root_str = task
    path = Path(abs_path_str)
    root = Path(root_str)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"entries": [], "controls": [], "dynamic_calls": []}
    relative = path.relative_to(root).as_posix()
    lines = content.splitlines()
    is_controller = any(CONTROLLER_PATTERN.search(line) for line in lines)
    class_prefix = _class_routes(lines) if is_controller else ""

    entries: list[Entry] = []
    controls: list[Control] = []
    dynamic_calls: list[dict[str, object]] = []

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        _match_controller(entries, is_controller, class_prefix, relative, number, stripped)
        if REQUEST_SOURCE_PATTERN.search(line):
            entries.append(Entry(
                "request-source", relative, number,
                f"外部输入参数：{stripped[:160]}",
                "来自 HTTP 请求的参数进入服务端代码",
            ))
        if FILTER_PATTERN.search(line):
            entries.append(Entry("filter", relative, number, f"过滤器：{stripped[:160]}", "请求进入业务代码前的处理链"))
        if INTERCEPTOR_PATTERN.search(line):
            entries.append(Entry("interceptor", relative, number, f"拦截器：{stripped[:160]}", "请求进入业务代码前的处理链"))
        if SECURITY_CONFIG_PATTERN.search(line):
            entries.append(Entry("security-config", relative, number, f"安全配置：{stripped[:160]}", "定义认证与授权规则"))
        if UPLOAD_PATTERN.search(line):
            entries.append(Entry("upload", relative, number, f"文件上传：{stripped[:160]}", "攻击者可控的文件内容进入服务端"))
        if MQ_CONSUMER_PATTERN.search(line):
            entries.append(Entry("mq-consumer", relative, number, f"消息消费者：{stripped[:160]}", "消息负载进入服务端代码"))
        if SCHEDULED_PATTERN.search(line):
            entries.append(Entry("scheduled", relative, number, f"定时任务：{stripped[:160]}", "周期触发的服务端逻辑"))
        if JPA_NATIVE_PATTERN.search(line):
            entries.append(Entry("jpa-native", relative, number, f"JPA 原生查询：{stripped[:160]}", "SQL 文本可能包含动态拼接"))
        if MYBATIS_ANNOTATION_PATTERN.search(line) and MYBATIS_DOLLAR_PATTERN.search("\n".join(lines[number - 1:number + 6])):
            entries.append(Entry("mybatis-dynamic", relative, number, f"MyBatis 注解 SQL 含 ${{}}：{stripped[:160]}", "动态 SQL 可能拼接外部输入"))
        if REFLECTION_PATTERN.search(line):
            dynamic_calls.append({"path": relative, "line": number, "detail": f"反射或动态调用：{stripped[:160]}"})
        for kind, pattern, detail in CONTROL_PATTERNS:
            if pattern.search(line):
                controls.append(Control(kind, relative, number, detail))

    return {
        "entries": entries,
        "controls": controls,
        "dynamic_calls": dynamic_calls,
    }


# Tuned against the 500-file benchmark: 8s serial vs ~1.2s with 8 workers.
_PARALLEL_THRESHOLD = 32
_MAX_WORKERS = 8


def collect_surface(root: Path, progress: bool = False, workers: int | None = None) -> AttackSurface:
    """Stage 1-2: walk the project for entry candidates and trust-boundary evidence.

    Large projects are split across a process pool so a 500-file scan finishes
    in roughly 1s instead of 8s on an 8-core machine.
    """
    files = list(iter_java_files(root))
    surface = AttackSurface()

    if len(files) < _PARALLEL_THRESHOLD:
        for path in files:
            result = _scan_surface_file((str(path), str(root)))
            surface.entries.extend(result["entries"])
            surface.controls.extend(result["controls"])
            surface.dynamic_calls.extend(result["dynamic_calls"])
    else:
        worker_count = workers or min(_MAX_WORKERS, os.cpu_count() or 4)
        chunksize = max(1, len(files) // (worker_count * 8))
        tasks = [(str(path), str(root)) for path in files]
        completed = 0
        next_mark = len(tasks) // 10
        with ProcessPoolExecutor(max_workers=worker_count) as pool:
            for batch in pool.map(_scan_surface_file, tasks, chunksize=chunksize):
                surface.entries.extend(batch["entries"])
                surface.controls.extend(batch["controls"])
                surface.dynamic_calls.extend(batch["dynamic_calls"])
                completed += 1
                if progress and completed >= next_mark:
                    print(f"[surface] {completed}/{len(tasks)}", file=sys.stderr)
                    next_mark += len(tasks) // 10
        if progress:
            print(f"[surface] done: {len(surface.entries)} entries, {len(surface.controls)} controls (workers={worker_count})", file=sys.stderr)

    _scan_mybatis_xml(root, surface)
    return surface


def _scan_mybatis_xml(root: Path, surface: AttackSurface) -> None:
    """Mapper XML files declare trust boundaries outside Java sources."""
    for xml_path in root.rglob("*.xml"):
        if any(part in {"target", "build", ".git", "node_modules"} for part in xml_path.relative_to(root).parts):
            continue
        if not any(name in xml_path.name.lower() for name in ("mapper", "dao", "sqlmap")):
            continue
        try:
            lines = xml_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        relative = xml_path.relative_to(root).as_posix()
        for number, line in enumerate(lines, start=1):
            if MYBATIS_DOLLAR_PATTERN.search(line) and re.search(r"(?:select|insert|update|delete|sql|if|when|foreach|bind|order by|like)", line, re.I):
                surface.entries.append(Entry("mybatis-dynamic", relative, number, f"Mapper XML 动态替换 ${{}}：{line.strip()[:160]}", "SQL 文本中的动态替换点可能拼接外部输入"))

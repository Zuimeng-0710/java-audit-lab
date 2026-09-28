"""阶段 B：端点与权限矩阵。

把三类权限证据归并为一张矩阵：

    接口 | 方法 | 身份要求 | 角色/权限 | 数据对象 | 危险操作 | 证据状态

证据来源，按强度从高到低：
    1. 方法级注解        @PreAuthorize / @Secured / @RolesAllowed / Shiro 注解   → 已证明
    2. 安全配置匹配规则  SecurityFilterChain / HttpSecurity matcher 链           → 已证明（配置级）
    3. Shiro 过滤链      filterChainDefinitionMap                                → 已证明（配置级）
    4. 无匹配            → 缺失（必须人工确认，工具不猜测）

保守原则与工具其他部分一致：只报告代码中真实存在的声明，
不把"没有找到注解"推断为"没有权限控制"，也不把配置规则外推到匹配不到的路由。
"""

from __future__ import annotations

import fnmatch
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .project import iter_java_files


# ---------------- 端点与路由 ----------------

MAPPING_RE = re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(([^)]*)\)")
CONTROLLER_RE = re.compile(r"@(?:Rest)?Controller\b")
CLASS_MAPPING_RE = re.compile(r"@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?[\"']([^\"']+)[\"']")
ROUTE_VALUE_RE = re.compile(r"(?:value|path)\s*=\s*[\"']([^\"']+)[\"']|^\s*[\"']([^\"']+)[\"']")
METHOD_REQ_RE = re.compile(r"method\s*=\s*RequestMethod\.(\w+)")
SIGNATURE_RE = re.compile(r"^\s*(?:public|protected|private)\s+[\w<>\[\],.?\s]*\s(\w+)\s*\(")

# ---------------- 方法级授权注解 ----------------

PRE_AUTHORIZE_RE = re.compile(r"@(PreAuthorize|PostAuthorize)\s*\(\s*(?:\"([^\"]*)\"|'([^']*)')")
SECURED_RE = re.compile(r"@Secured\s*\(([^)]*)\)")
ROLES_ALLOWED_RE = re.compile(r"@RolesAllowed\s*\(([^)]*)\)")
SHIRO_ROLES_RE = re.compile(r"@RequiresRoles\s*\(([^)]*)\)")
SHIRO_PERMS_RE = re.compile(r"@RequiresPermissions\s*\(([^)]*)\)")
SHIRO_SIMPLE_RE = re.compile(r"@Requires(Authentication|User|Guest)\b")
STRING_LITERAL_RE = re.compile(r"[\"']([^\"']+)[\"']")

# SpEL / 表达式内部结构
ROLE_EXPR_RE = re.compile(r"has(?:Any)?Role\s*\(\s*([^)]*)\)")
AUTHORITY_EXPR_RE = re.compile(r"has(?:Any)?Authority\s*\(\s*([^)]*)\)")
PERMISSION_EXPR_RE = re.compile(r"hasPermission\s*\(")
OWNERSHIP_EXPR_RE = re.compile(r"authentication\.(?:name|principal)|principal\.|#\w+\s*==\s*authentication")

# ---------------- 安全配置链 ----------------

MATCHER_RE = re.compile(r"\.(?:antMatchers|requestMatchers|mvcMatchers|regexMatchers)\s*\(([^)]*)\)")
RULE_RE = re.compile(
    r"\.(hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|hasPermission|authenticated|"
    r"fullyAuthenticated|permitAll|anonymous|denyAll|rememberMe)\s*(?:\(([^)]*)\))?"
)
IGNORING_RE = re.compile(r"(?:web|webSecurity)\s*\.?\s*ignoring\s*\(\s*\)")
SECURITY_CONFIG_HINT_RE = re.compile(r"SecurityFilterChain|HttpSecurity|WebSecurityConfigurerAdapter|@EnableWebSecurity")

# ---------------- Shiro 过滤链 ----------------

SHIRO_CHAIN_RE = re.compile(r"[\"'](/[^\"']*)[\"']\s*(?:,|=|:)\s*[\"']([^\"']*)[\"']")
SHIRO_CHAIN_HINT_RE = re.compile(r"filterChainDefinitionMap|ShiroFilterFactoryBean|FilterChainDefinition")
SHIRO_ROLES_FILTER_RE = re.compile(r"roles\s*\[([^\]]*)\]")
SHIRO_PERMS_FILTER_RE = re.compile(r"perms\s*\[([^\]]*)\]")

# ---- Spring MVC 拦截器（WebMvcConfigurer.addInterceptors）----
# 国内项目最常见的鉴权方式：自定义 HandlerInterceptor + registry.addInterceptor(...)
INTERCEPTOR_HINT_RE = re.compile(r"addInterceptors\s*\(\s*InterceptorRegistry|InterceptorRegistry\s+\w+")
ADD_INTERCEPTOR_RE = re.compile(r"\.addInterceptor\s*\(([^)]*)\)")
PATH_PATTERNS_RE = re.compile(r"\.(addPathPatterns|excludePathPatterns)\s*\(([^)]*)\)")
# 只有名字带鉴权语义的拦截器才算权限证据；日志、耗时统计之类不能当作鉴权。
# 必须按驼峰拆词后整词匹配：直接子串匹配会把 accessLogInterceptor 里的 "LogIn" 当成 login。
_CAMEL_WORD_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
AUTH_WORDS = {"token", "jwt", "login", "auth", "authentication", "authorize",
              "permission", "role", "security", "session", "sign"}


def _is_auth_interceptor(name: str) -> bool:
    base = name.strip().split(".")[-1]
    words = {word.lower() for word in _CAMEL_WORD_RE.findall(base)}
    return bool(words & AUTH_WORDS)
# 拦截器实现里出现角色/权限判断时，可以 upgrading 为角色级要求
ROLE_CHECK_IN_INTERCEPTOR_RE = re.compile(r"getRole\s*\(\s*\)|hasRole|isAdmin|getAuthority|checkPermission", re.I)
TOKEN_READ_RE = re.compile(r"getHeader\s*\(|getParameter\s*\(|(?:token|jwt|session)", re.I)
TOKEN_VERIFY_RE = re.compile(r"parseJWT|verify|validate|decode|checkToken|isTokenValid", re.I)
REQUEST_REJECT_RE = re.compile(r"return\s+false|SC_UNAUTHORIZED|\b401\b|throw\s+new", re.I)

ANONYMOUS_TOKENS = {"permitAll", "anonymous", "anon"}
AUTHENTICATED_TOKENS = {"authenticated", "fullyAuthenticated", "authc", "user", "rememberMe"}


@dataclass(slots=True)
class Endpoint:
    path: str
    line: int
    http_method: str
    route: str
    handler: str
    requirement: str = "unknown"       # anonymous / authenticated / role / permission / ownership / unknown
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    expression: str = ""
    evidence: list[dict] = field(default_factory=list)
    status: str = "missing"            # proven / inferred / missing
    dangerous_ops: list[str] = field(default_factory=list)
    finding_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class AuthorizationMatrix:
    endpoints: list[Endpoint] = field(default_factory=list)
    rules: list[dict] = field(default_factory=list)
    coverage: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoints": [item.to_dict() for item in self.endpoints],
            "rules": self.rules,
            "coverage": self.coverage,
        }


REQUIREMENT_LABELS = {
    "anonymous": "无需登录",
    "authenticated": "需登录",
    "role": "需角色",
    "permission": "需权限",
    "ownership": "需数据归属",
    "unknown": "未知",
}
STATUS_LABELS = {"proven": "权限已证明", "inferred": "权限推测", "missing": "权限缺失"}


def _strings(text: str) -> list[str]:
    return STRING_LITERAL_RE.findall(text)


def _pre_text(match: re.Match) -> str:
    """@PreAuthorize 的表达式：外层可能是双引号（内含单引号）或单引号。"""
    return match.group(2) or match.group(3) or ""


def _classify_expression(expression: str) -> tuple[str, list[str], list[str]]:
    """把 SpEL/注解表达式解析为（身份要求, 角色, 权限）。"""
    roles = [item for group in ROLE_EXPR_RE.findall(expression) for item in _strings(group)]
    authorities = [item for group in AUTHORITY_EXPR_RE.findall(expression) for item in _strings(group)]
    roles.extend(authorities)
    permissions = _strings(expression) if PERMISSION_EXPR_RE.search(expression) else []
    lowered = expression.lower()
    if "permitall" in lowered or "isanonymous" in lowered or "anonymous" in lowered:
        return "anonymous", roles, permissions
    if "denyall" in lowered:
        return "role", roles or ["DENY_ALL"], permissions
    if OWNERSHIP_EXPR_RE.search(expression):
        return "ownership", roles, permissions
    if roles:
        return "role", roles, permissions
    if permissions:
        return "permission", roles, permissions
    if "isauthenticated" in lowered or "isfullyauthenticated" in lowered or "isrememberme" in lowered:
        return "authenticated", roles, permissions
    return "unknown", roles, permissions


def _classify_shiro_filter(chain: str) -> tuple[str, list[str], list[str]]:
    roles: list[str] = []
    permissions: list[str] = []
    for group in SHIRO_ROLES_FILTER_RE.findall(chain):
        roles.extend(item.strip() for item in group.split(",") if item.strip())
    for group in SHIRO_PERMS_FILTER_RE.findall(chain):
        permissions.extend(item.strip() for item in group.split(",") if item.strip())
    tokens = {token.strip().lower() for token in re.split(r"[,\s]+", chain) if token.strip()}
    if roles:
        return "role", roles, permissions
    if permissions:
        return "permission", roles, permissions
    if tokens & ANONYMOUS_TOKENS or "anon" in tokens:
        return "anonymous", roles, permissions
    if tokens & AUTHENTICATED_TOKENS:
        return "authenticated", roles, permissions
    return "unknown", roles, permissions


def _strip_java_comments(lines: list[str]) -> list[str]:
    """剥离 Java 注释但保留行号与行结构。

    被注释掉的权限声明不是证据：若把 `// @PreAuthorize(...)` 当成真实注解，
    会把"权限已被删除"误报为"权限仍然存在"，这是增量审计里最危险的假阴性。
    字符串字面量原样保留，避免把 "http://x" 或 "/**" 误判为注释起点。
    """
    result: list[str] = []
    in_block = False
    for line in lines:
        buffer: list[str] = []
        index = 0
        while index < len(line):
            if in_block:
                end = line.find("*/", index)
                if end == -1:
                    index = len(line)
                    break
                in_block = False
                index = end + 2
                continue
            if line.startswith("//", index):
                break
            if line.startswith("/*", index):
                in_block = True
                index += 2
                continue
            char = line[index]
            if char in "\"'":
                cursor = index + 1
                while cursor < len(line):
                    if line[cursor] == "\\":
                        cursor += 2
                        continue
                    if line[cursor] == char:
                        cursor += 1
                        break
                    cursor += 1
                buffer.append(line[index:cursor])
                index = cursor
                continue
            buffer.append(char)
            index += 1
        result.append("".join(buffer))
    return result


def _parse_mvc_interceptors(content: str, relative: str) -> list[dict]:
    """解析 WebMvcConfigurer.addInterceptors 注册的路径模式。

    典型写法（国内项目最常见的鉴权方式）：

        registry.addInterceptor(adminLoginTokenInterceptor)
                .addPathPatterns("/user/**")
                .addPathPatterns("/api/chat/**")
                .excludePathPatterns("/user/login");

    只有名称含鉴权语义的拦截器才生成权限规则，日志、耗时统计之类不能当作鉴权证据。
    排除路径（excludePathPatterns）优先级高于包含路径。
    """
    if not INTERCEPTOR_HINT_RE.search(content):
        return []
    marks = [(match.end(), match.group(1).strip()) for match in ADD_INTERCEPTOR_RE.finditer(content)]
    if not marks:
        return []
    rules: list[dict] = []
    for match in PATH_PATTERNS_RE.finditer(content):
        owner = None
        for end, name in marks:
            if end > match.start():
                break
            owner = name
        if owner is None or not _is_auth_interceptor(owner):
            continue
        kind, args = match.group(1), match.group(2)
        patterns = [item for item in _strings(args) if item.startswith("/") or "*" in item]
        if not patterns:
            continue
        line_no = content[:match.start()].count("\n") + 1
        if kind == "excludePathPatterns":
            rules.append({
                "kind": "mvc-interceptor-exclude",
                "patterns": patterns,
                "requirement": "anonymous",
                "roles": [], "permissions": [],
                "detail": f"{owner} 显式排除，无需令牌",
                "path": relative, "line": line_no,
                "priority": 0,
            })
        else:
            rules.append({
                "kind": "mvc-interceptor",
                "patterns": patterns,
                "requirement": "authenticated",
                "roles": [], "permissions": [],
                "detail": f"{owner} → 需有效令牌（未发现角色判断）",
                "path": relative, "line": line_no,
                "priority": 1,
            })
    return rules


def _scan_authz_file(task: tuple[str, str]) -> dict[str, list]:
    """Worker: 扫描单个 Java 文件的端点与权限证据。顶层函数以便多进程 pickle。"""
    abs_path_str, root_str = task
    path = Path(abs_path_str)
    root = Path(root_str)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"endpoints": [], "rules": []}
    relative = path.relative_to(root).as_posix()
    lines = _strip_java_comments(content.splitlines())

    is_controller = any(CONTROLLER_RE.search(line) for line in lines)
    class_prefix = ""
    for line in lines[:200]:
        match = CLASS_MAPPING_RE.search(line)
        if match:
            class_prefix = match.group(1).rstrip("/")
            break

    # 1) 类的整体授权（类级注解对全部 handler 生效）
    class_requirement = "unknown"
    class_roles: list[str] = []
    class_permissions: list[str] = []
    class_expression = ""
    class_evidence: list[dict] = []
    # 类级注解只可能出现在类声明之前：窗口必须截断在 class 声明行，
    # 否则会把文件后面某个方法的注解误当成对整个类生效。
    class_decl_index = next(
        (index for index, line in enumerate(lines[:200]) if re.search(r"\bclass\s+\w+", line)),
        len(lines[:60]),
    )
    head = "\n".join(lines[:class_decl_index])
    pre = PRE_AUTHORIZE_RE.search(head)
    if pre:
        expression_text = _pre_text(pre)
        class_requirement, class_roles, class_permissions = _classify_expression(expression_text)
        class_expression = expression_text
        class_evidence.append({"kind": "class-annotation", "detail": f"@{pre.group(1)} {expression_text}", "path": relative, "line": 0})
    secured = SECURED_RE.search(head)
    if secured and class_requirement == "unknown":
        class_requirement = "role"
        class_roles = _strings(secured.group(1))
        class_expression = secured.group(0)
        class_evidence.append({"kind": "class-annotation", "detail": secured.group(0)[:160], "path": relative, "line": 0})
    roles_allowed = ROLES_ALLOWED_RE.search(head)
    if roles_allowed and class_requirement == "unknown":
        class_requirement = "role"
        class_roles = _strings(roles_allowed.group(1))
        class_expression = roles_allowed.group(0)
        class_evidence.append({"kind": "class-annotation", "detail": roles_allowed.group(0)[:160], "path": relative, "line": 0})

    endpoints: list[Endpoint] = []
    last_signature_line = 0

    # 2) 方法级：mapping 注解 + 紧随其后的签名 + 窗口内的授权注解
    for number, line in enumerate(lines, start=1):
        mapping = MAPPING_RE.search(line)
        if not mapping or not is_controller:
            continue
        route_match = ROUTE_VALUE_RE.search(mapping.group(2))
        route_value = ""
        if route_match:
            route_value = route_match.group(1) or route_match.group(2) or ""
        method_match = METHOD_REQ_RE.search(mapping.group(2))
        http_method = method_match.group(1).upper() if method_match else (
            mapping.group(1).upper() if mapping.group(1).upper() != "REQUEST" else "ANY"
        )
        full_route = f"{class_prefix}/{route_value.lstrip('/')}".replace("//", "/")

        handler_name = ""
        signature_line = number
        is_class_level = False
        for offset in range(0, 12):
            index = number - 1 + offset
            if index >= len(lines):
                break
            stripped_line = lines[index].strip()
            # 类声明出现在方法签名之前 → 这是类级 @RequestMapping，不是端点
            if re.search(r"\bclass\s+\w+", stripped_line) and "(" not in stripped_line:
                is_class_level = True
                break
            signature = SIGNATURE_RE.match(lines[index])
            if signature and "@" not in stripped_line:
                handler_name = signature.group(1)
                signature_line = index + 1
                break
        if is_class_level:
            continue

        # 授权注解窗口：上一个方法签名之后 → 本方法签名之前（最多回看 7 行），
        # 否则会把上一个方法的注解算到本方法头上。
        window_start = max(last_signature_line, number - 7)
        window = "\n".join(lines[window_start:signature_line])
        last_signature_line = signature_line
        requirement, roles, permissions = "unknown", [], []
        expression = ""
        evidence: list[dict] = []

        pre = PRE_AUTHORIZE_RE.search(window)
        if pre:
            expression = _pre_text(pre)
            requirement, roles, permissions = _classify_expression(expression)
            evidence.append({"kind": "method-annotation", "detail": f"@{pre.group(1)} {expression}", "path": relative, "line": number})
        secured = SECURED_RE.search(window)
        if secured and requirement == "unknown":
            requirement, roles, permissions = "role", _strings(secured.group(1)), []
            expression = secured.group(0).strip()
            evidence.append({"kind": "method-annotation", "detail": expression[:160], "path": relative, "line": number})
        roles_allowed = ROLES_ALLOWED_RE.search(window)
        if roles_allowed and requirement == "unknown":
            requirement, roles, permissions = "role", _strings(roles_allowed.group(1)), []
            expression = roles_allowed.group(0).strip()
            evidence.append({"kind": "method-annotation", "detail": expression[:160], "path": relative, "line": number})
        shiro_roles = SHIRO_ROLES_RE.search(window)
        if shiro_roles and requirement == "unknown":
            requirement, roles, permissions = "role", _strings(shiro_roles.group(1)), []
            expression = shiro_roles.group(0).strip()
            evidence.append({"kind": "shiro-annotation", "detail": expression[:160], "path": relative, "line": number})
        shiro_perms = SHIRO_PERMS_RE.search(window)
        if shiro_perms and requirement == "unknown":
            requirement, roles, permissions = "permission", [], _strings(shiro_perms.group(1))
            expression = shiro_perms.group(0).strip()
            evidence.append({"kind": "shiro-annotation", "detail": expression[:160], "path": relative, "line": number})
        shiro_simple = SHIRO_SIMPLE_RE.search(window)
        if shiro_simple and requirement == "unknown":
            token = shiro_simple.group(1)
            requirement = "anonymous" if token == "Guest" else "authenticated"
            expression = shiro_simple.group(0)
            evidence.append({"kind": "shiro-annotation", "detail": expression, "path": relative, "line": number})

        # 类级兜底
        if requirement == "unknown" and class_requirement != "unknown":
            requirement = class_requirement
            roles = list(class_roles)
            permissions = list(class_permissions)
            expression = class_expression
            evidence.extend(class_evidence)

        status = "proven" if requirement != "unknown" else "missing"
        endpoints.append(Endpoint(
            path=relative, line=signature_line, http_method=http_method, route=full_route,
            handler=handler_name, requirement=requirement, roles=roles, permissions=permissions,
            expression=expression, evidence=evidence, status=status,
        ))

    # 3) 配置链规则（Spring Security / Shiro），同一文件内解析
    rules: list[dict] = []
    if SECURITY_CONFIG_HINT_RE.search(content):
        joined = "\n".join(lines)
        matcher_positions = list(MATCHER_RE.finditer(joined))
        for index, matcher in enumerate(matcher_positions):
            patterns = _strings(matcher.group(1))
            patterns = [item for item in patterns if item.startswith("/") or "*" in item]
            rule_start = matcher.end()
            rule_end = matcher_positions[index + 1].start() if index + 1 < len(matcher_positions) else len(joined)
            segment = joined[rule_start:rule_end]
            rule = RULE_RE.search(segment)
            if not rule:
                continue
            token = rule.group(1)
            args = rule.group(2) or ""
            requirement = "unknown"
            roles = _strings(args)
            permissions = []
            if token in ANONYMOUS_TOKENS:
                requirement = "anonymous"
            elif token in AUTHENTICATED_TOKENS:
                requirement = "authenticated"
            elif token in {"hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority"}:
                requirement = "role"
            elif token == "hasPermission":
                requirement = "permission"
                permissions = _strings(args)
            elif token == "denyAll":
                requirement = "role"
                roles = roles or ["DENY_ALL"]
            line_no = joined[:matcher.start()].count("\n") + 1
            rules.append({
                "kind": "spring-security",
                "patterns": patterns,
                "requirement": requirement,
                "roles": roles,
                "permissions": permissions,
                "detail": f".{token}({args})",
                "path": relative,
                "line": line_no,
            })
    if SHIRO_CHAIN_HINT_RE.search(content):
        for number, line in enumerate(lines, start=1):
            for match in SHIRO_CHAIN_RE.finditer(line):
                route_pattern, chain = match.group(1), match.group(2)
                requirement, roles, permissions = _classify_shiro_filter(chain)
                rules.append({
                    "kind": "shiro-chain",
                    "patterns": [route_pattern],
                    "requirement": requirement,
                    "roles": roles,
                    "permissions": permissions,
                    "detail": chain,
                    "path": relative,
                    "line": number,
                })

    # 4) Spring MVC 拦截器注册（addInterceptors）
    rules.extend(_parse_mvc_interceptors(content, relative))

    # 5) 本文件是否定义了鉴权拦截器实现（用于跨文件判断是否含角色检查）
    impls: list[dict] = []
    if "HandlerInterceptor" in content:
        for match in re.finditer(r"class\s+(\w+)[^{]*?(?:implements[^{]*?HandlerInterceptor|extends\s+HandlerInterceptorAdapter)", content):
            name = match.group(1)
            if _is_auth_interceptor(name):
                impls.append({
                    "name": name,
                    "role_check": bool(ROLE_CHECK_IN_INTERCEPTOR_RE.search(content)),
                    "auth_check": bool(TOKEN_READ_RE.search(content) and TOKEN_VERIFY_RE.search(content) and REQUEST_REJECT_RE.search(content)),
                    "path": relative,
                })

    return {"endpoints": [item.to_dict() for item in endpoints], "rules": rules, "interceptor_impls": impls}


_PARALLEL_THRESHOLD = 32
_MAX_WORKERS = 8


def collect_authorization(root: Path, progress: bool = False, workers: int | None = None, public_patterns: list[str] | None = None) -> AuthorizationMatrix:
    """扫描全项目的端点与权限证据，并做配置规则匹配。"""
    files = list(iter_java_files(root))
    matrix = AuthorizationMatrix()
    if public_patterns:
        matrix.rules.append({
            "kind": "configured-public", "patterns": list(public_patterns),
            "requirement": "anonymous", "roles": [], "permissions": [],
            "detail": "项目配置声明的公开端点", "path": ".java-audit.yml", "line": 1,
            "priority": 0,
        })

    impls: list[dict] = []

    def _absorb(batch: dict) -> None:
        for item in batch["endpoints"]:
            matrix.endpoints.append(Endpoint(**item))
        matrix.rules.extend(batch["rules"])
        impls.extend(batch.get("interceptor_impls") or [])

    if len(files) < _PARALLEL_THRESHOLD:
        for path in files:
            _absorb(_scan_authz_file((str(path), str(root))))
    else:
        worker_count = workers or min(_MAX_WORKERS, os.cpu_count() or 4)
        chunksize = max(1, len(files) // (worker_count * 8))
        tasks = [(str(path), str(root)) for path in files]
        with ProcessPoolExecutor(max_workers=worker_count) as pool:
            for batch in pool.map(_scan_authz_file, tasks, chunksize=chunksize):
                _absorb(batch)
        if progress:
            print(f"[authz] scanned {len(files)} files (workers={worker_count})", file=sys.stderr)

    # 拦截器实现里若发现角色判断，补充说明（不擅自升级为角色要求，避免谎报）
    if impls:
        by_name = {item["name"].lower(): item for item in impls}
        for rule in matrix.rules:
            if rule.get("kind") != "mvc-interceptor":
                continue
            detail = str(rule.get("detail", ""))
            for name, item in by_name.items():
                if name in detail.lower():
                    rule["evidence_status"] = "proven" if item.get("auth_check") else "inferred"
                    if item["role_check"]:
                        rule["detail"] = f"{detail}；实现 {item['name']} 内发现角色判断，需人工确认具体角色"
                    rule["path"] = rule.get("path") or ""
                    break
    # 排除路径优先于包含路径，其次拦截器，最后 Spring Security / Shiro
    matrix.rules.sort(key=lambda item: int(item.get("priority", 2)))

    _apply_config_rules(matrix)
    _summarize(matrix)
    return matrix


def _rule_matches(route: str, pattern: str) -> bool:
    if not route:
        return False
    candidate = route if route.startswith("/") else f"/{route}"
    if pattern.startswith("/") is False:
        pattern = f"/{pattern}"
    if fnmatch.fnmatch(candidate, pattern):
        return True
    # "/admin/**" 这类通配符：补一层不含尾部通配的比较
    return fnmatch.fnmatch(candidate, pattern.rstrip("/") + "/*") if pattern.endswith("/**") else False


def _apply_config_rules(matrix: AuthorizationMatrix) -> None:
    """配置规则优先级低于方法注解：只给未知权限的端点补证据。"""
    for endpoint in matrix.endpoints:
        if endpoint.status == "proven":
            continue
        for rule in matrix.rules:
            if not any(_rule_matches(endpoint.route, pattern) for pattern in rule.get("patterns", [])):
                continue
            endpoint.requirement = str(rule.get("requirement", "unknown"))
            endpoint.roles = list(rule.get("roles") or [])
            endpoint.permissions = list(rule.get("permissions") or [])
            if endpoint.requirement == "unknown":
                endpoint.status = "inferred"
            else:
                endpoint.status = str(rule.get("evidence_status", "inferred" if rule.get("kind") == "mvc-interceptor" else "proven"))
            endpoint.evidence.append({
                "kind": rule.get("kind", "config"),
                "detail": f"{', '.join(rule.get('patterns', []))} → {rule.get('detail', '')}",
                "path": str(rule.get("path", "")),
                "line": int(rule.get("line", 0)),
            })
            break


def _summarize(matrix: AuthorizationMatrix) -> None:
    proven = sum(1 for item in matrix.endpoints if item.status == "proven")
    inferred = sum(1 for item in matrix.endpoints if item.status == "inferred")
    missing = sum(1 for item in matrix.endpoints if item.status == "missing")
    anonymous = sum(1 for item in matrix.endpoints if item.requirement == "anonymous")
    total = len(matrix.endpoints)
    matrix.coverage = {
        "endpoints": total,
        "proven": proven,
        "inferred": inferred,
        "missing": missing,
        "anonymous": anonymous,
        "rules": len(matrix.rules),
        "confirmed_ratio": round(proven / total * 100, 1) if total else 0.0,
        "unprotected_high_risk": sum(
            1 for item in matrix.endpoints
            if item.requirement in {"anonymous", "unknown"} and item.finding_count > 0
        ),
    }


def link_findings_to_endpoints(findings: list, matrix: AuthorizationMatrix) -> None:
    """把发现挂到所属端点，并填充统一证据记录的 authorization 字段。"""
    by_file: dict[str, list[Endpoint]] = {}
    for endpoint in matrix.endpoints:
        by_file.setdefault(endpoint.path, []).append(endpoint)

    for finding in findings:
        location = getattr(finding, "location", None)
        if location is None:
            continue
        candidates = by_file.get(str(getattr(location, "path", "")), [])
        if not candidates:
            continue
        line = int(getattr(location, "line", 1))
        # 归属：端点签名行 <= 发现行，且取距离最近的一个
        owner = None
        for endpoint in sorted(candidates, key=lambda item: item.line):
            if endpoint.line <= line:
                owner = endpoint
            else:
                break
        if owner is None:
            continue
        owner.finding_count += 1
        owner.dangerous_ops.append(str(getattr(finding, "rule_id", "")))
        authorization = {
            "status": STATUS_LABELS.get(owner.status, owner.status),
            "endpoint": f"{owner.http_method} {owner.route}".strip(),
            "handler": owner.handler,
            "requirement": REQUIREMENT_LABELS.get(owner.requirement, owner.requirement),
            "roles": owner.roles,
            "permissions": owner.permissions,
            "expression": owner.expression,
            "evidence": owner.evidence,
            "endpoint_line": owner.line,
        }
        metadata = getattr(finding, "metadata", None)
        if metadata is not None:
            metadata["authorization"] = authorization
            metadata["endpoint"] = f"{owner.http_method} {owner.route}".strip()
            record = metadata.get("evidence_record")
            if isinstance(record, dict):
                record["authorization"] = authorization
    # 危险操作归属完成后重算覆盖率，"无保护且存在危险操作"才有意义
    _summarize(matrix)

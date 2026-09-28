"""Java 框架与危险操作模型包（阶段 C-2）。

把「哪些地方进来不可信数据」「哪些操作危险」「什么算净化」抽成数据驱动的模型，
而不是继续往扫描器里堆裸正则。污点引擎（audit/taint.py）消费这里的模型。

设计原则：
  - 只描述「事实」，不做「判断」。是否可利用由人工复核和五问流程决定。
  - 每一行模型都要能说清：来源是什么、为什么危险、什么情况能推翻它。
  - 宁可漏，不可把猜测包装成事实。
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SourceModel:
    """不可信数据来源。"""

    name: str
    pattern: re.Pattern[str]
    kind: str            # http / upload / mq / rpc / cli / env
    framework: str
    note: str


@dataclass(frozen=True, slots=True)
class SinkModel:
    """危险操作终点。"""

    rule_id: str
    title: str
    cwe: str
    severity: str
    pattern: re.Pattern[str]
    sink_kind: str       # sql / command / file / ssrf / deser / el / ldap / redirect / upload / log
    framework: str
    description: str
    review_steps: tuple[str, ...]
    remediation: str


@dataclass(frozen=True, slots=True)
class SanitizerModel:
    """净化/校验信号：命中即作为「可推翻漏洞假设」的反证，而不是直接判定安全。"""

    name: str
    pattern: re.Pattern[str]
    applies_to: tuple[str, ...]   # 适用的 sink_kind
    note: str


# ---------------------------------------------------------------- 不可信来源

SOURCES: tuple[SourceModel, ...] = (
    SourceModel("Servlet 请求参数", re.compile(r"request\.getParameter\s*\(|req\.getParameter\s*\("),
                "http", "servlet", "直接来自 HTTP 查询串或表单。"),
    SourceModel("Servlet 请求头", re.compile(r"request\.getHeader\s*\(|req\.getHeader\s*\("),
                "http", "servlet", "请求头可被客户端完全控制。"),
    SourceModel("Servlet 请求体", re.compile(r"request\.getInputStream\s*\(|request\.getReader\s*\("),
                "http", "servlet", "原始请求体。"),
    SourceModel("Spring MVC 参数注解", re.compile(r"@RequestParam\b|@PathVariable\b|@RequestBody\b|@ModelAttribute\b|@RequestHeader\b"),
                "http", "spring-mvc", "由框架从请求绑定的参数。"),
    SourceModel("Spring MVC 请求对象", re.compile(r"\bHttpServletRequest\b\s+\w+|@Context\s+HttpServletRequest"),
                "http", "spring-mvc", "持有完整请求上下文。"),
    SourceModel("文件上传", re.compile(r"\bMultipartFile\b\s+\w+|@RequestPart\b"),
                "upload", "spring-mvc", "文件名与内容均由客户端提供。"),
    SourceModel("MQ 消费者消息", re.compile(r"@KafkaListener\b|@RabbitListener\b|@RocketMQMessageListener\b|@JmsListener\b"),
                "mq", "mq", "消息体来自外部生产者。"),
    SourceModel("Dubbo/gRPC 入参", re.compile(r"@DubboService\b|@Service\s*\(\s*.*dubbo| DubboReference"),
                "rpc", "rpc", "远程调用入参。"),
    SourceModel("命令行入参", re.compile(r"\bargs\s*\[\s*\d*\s*\]|String\[\]\s+args"),
                "cli", "java", "进程启动参数。"),
    SourceModel("环境变量与配置", re.compile(r"System\.getenv\s*\(|System\.getProperty\s*\("),
                "env", "java", "部署环境可控，通常可信度高于请求，但不等于已校验。"),
)


# ---------------------------------------------------------------- 危险终点

_SQL = ("找出拼接值或参数的来源，确认是否来自请求、消息或上传。",
        "检查是否使用参数绑定，或存在字段白名单。",
        "用能改变语法结构的测试数据验证。")

_CMD = ("追踪命令或参数的来源。", "确认是否经过 shell 解释。", "检查是否使用固定程序与白名单参数。")

_PATH = ("确定路径片段是否由客户端控制。",
         "检查 normalize/toRealPath 之后是否做了目录边界比较。",
         "考虑符号链接、绝对路径和编码后的 ../。")

_SSRF = ("追踪协议、主机、端口的来源。", "解析 DNS 后检查全部目标 IP。", "确认重定向后是否重新校验。")

_DESER = ("追踪反序列化输入的来源。", "确认是否存在类型白名单或 ObjectInputFilter。", "检查依赖中的 gadget 链。")

_EL = ("追踪表达式字符串来源。", "确认求值上下文暴露的对象和类型。", "区分表达式结构与变量绑定。")

SINKS: tuple[SinkModel, ...] = (
    SinkModel("JAL-SQL-101", "SQL 拼接执行", "CWE-89", "high",
              re.compile(r"\.(?:executeQuery|executeUpdate|execute)\s*\(|\.createNativeQuery\s*\(|\.createQuery\s*\("),
              "sql", "jdbc",
              "SQL 执行点接收了可能为拼接结果的表达式。",
              _SQL, "使用预编译参数绑定；动态表名或排序字段走固定白名单。"),
    SinkModel("JAL-SQL-102", "MyBatis ${} 拼接", "CWE-89", "high",
              re.compile(r"\$\{[^}]+\}"),
              "sql", "mybatis",
              "MyBatis 映射里使用 ${} 会直接拼接进 SQL，#{} 才是参数绑定。",
              _SQL, "改用 #{} 参数绑定；确需动态片段时在服务端白名单里选择。"),
    SinkModel("JAL-CMD-101", "系统命令执行", "CWE-78", "critical",
              re.compile(r"Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|new\s+ProcessBuilder\s*\(|\.start\s*\(\s*\)"),
              "command", "java",
              "命令执行 API 被调用。",
              _CMD, "避免执行系统命令；必要时用固定程序与独立参数列表，并严格白名单。"),
    SinkModel("JAL-PATH-101", "文件路径访问", "CWE-22", "high",
              re.compile(r"new\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(|Paths\.get\s*\(|\.transferTo\s*\("),
              "file", "java",
              "文件访问路径被构造。",
              _PATH, "对规范化后的真实路径做目录边界检查，优先使用服务端生成的文件标识。"),
    SinkModel("JAL-SSRF-101", "出站请求", "CWE-918", "high",
              re.compile(r"new\s+URL\s*\(|\.openConnection\s*\(|\.(?:getForObject|postForObject|exchange|execute)\s*\("),
              "ssrf", "http-client",
              "构造了出站请求目标。",
              _SSRF, "目标走白名单，禁止非 HTTP(S) 协议、私网与元数据地址，限制重定向。"),
    SinkModel("JAL-DESER-101", "反序列化入口", "CWE-502", "critical",
              re.compile(r"\.readObject\s*\(|ObjectInputStream\s*\(|JSON\.parseObject\s*\(|JSON\.parseArray\s*\(|\.readValue\s*\("),
              "deser", "java",
              "反序列化或动态 JSON 解析入口被调用。",
              _DESER, "改用结构化格式；必须兼容时配置类型白名单与 ObjectInputFilter。"),
    SinkModel("JAL-EL-101", "表达式求值", "CWE-917", "critical",
              re.compile(r"\.parseExpression\s*\(|Ognl\.getValue\s*\(|MVEL\.eval\s*\(|\.getValue\s*\(\s*[^)]*Context"),
              "el", "expression",
              "表达式求值 API 被调用。",
              _EL, "固定表达式结构，动态数据作为变量绑定，使用受限求值上下文。"),
    SinkModel("JAL-LDAP-101", "LDAP/JNDI 查询", "CWE-90", "high",
              re.compile(r"\.search\s*\(\s*[^)]*,|new\s+InitialDirContext\s*\(|\.lookup\s*\("),
              "ldap", "jndi",
              "目录服务查询被调用。",
              ("追踪查询过滤器的来源。", "确认特殊字符是否转义。", "检查是否限制返回条目数。"),
              "对过滤器中的特殊字符转义，并使用参数化的目录查询 API。"),
    SinkModel("JAL-REDIR-101", "重定向目标", "CWE-601", "medium",
              re.compile(r"\.sendRedirect\s*\(|\"redirect:\"|\"forward:\""),
              "redirect", "spring-mvc",
              "重定向或转发目标被构造。",
              ("追踪目标 URL 来源。", "确认是否限制为站内相对路径。", "检查协议与域名是否被校验。"),
              "限制为预定义路径或站内相对路径，不接受完整 URL。"),
    SinkModel("JAL-UPLOAD-101", "上传落地", "CWE-434", "high",
              re.compile(r"\.transferTo\s*\(|\.write\s*\(\s*(?:byte|data|content|file)"),
              "upload", "spring-mvc",
              "上传内容被写入服务端存储。",
              ("确认文件类型与扩展名是否白名单校验。", "确认落盘目录不可执行且随机命名。", "检查大小与数量限制。"),
              "校验类型白名单、随机化文件名、限制大小，存储目录禁用脚本执行。"),
)


# ---------------------------------------------------------------- 净化信号（反证）

SANITIZERS: tuple[SanitizerModel, ...] = (
    SanitizerModel("参数绑定占位符", re.compile(r"\?\s*[,)]|:\w+\s*[,)]|\.setString\s*\(|\.setObject\s*\(|\.setInt\s*\("),
                   ("sql",), "使用了占位符或 setter 绑定，说明数据未直接进 SQL 文本。"),
    SanitizerModel("路径规范化", re.compile(r"\.normalize\s*\(|\.toRealPath\s*\(|getCanonicalPath\s*\("),
                   ("file",), "路径被规范化，但还需确认之后是否做了目录边界比较。"),
    SanitizerModel("目录边界校验", re.compile(r"startsWith\s*\(|\.contains\s*\(\s*(?:allowed|white|base|root)"),
                   ("file", "redirect"), "存在前缀或包含判断，可能限制在允许范围内。"),
    SanitizerModel("白名单校验", re.compile(r"(?:allow|white)\w*\.contains\s*\(|isAllowed\s*\(|inArray\s*\(|Enum\.valueOf\s*\("),
                   ("command", "sql", "redirect", "ldap"), "存在白名单或枚举收敛。"),
    SanitizerModel("类型收敛", re.compile(r"Integer\.parseInt\s*\(|Long\.parseLong\s*\(|UUID\.fromString\s*\(|Boolean\.parseBoolean\s*\("),
                   ("sql", "command", "ldap"), "被强制转成数值或固定格式，注入空间被压缩。"),
    SanitizerModel("转义处理", re.compile(r"(?:escape|encode)\w*\s*\(|HtmlUtils\.|StringEscapeUtils\.|URLEncoder\.encode\s*\("),
                   ("sql", "ldap", "redirect", "log"), "存在转义或编码调用。"),
    SanitizerModel("类型白名单（反序列化）", re.compile(r"ObjectInputFilter|setObjectInputFilter|addValidationFor|acceptClass"),
                   ("deser",), "配置了反序列化过滤器。"),
    SanitizerModel("表达式沙箱", re.compile(r"SimpleEvaluationContext|StandardEvaluationContext\.setVariable|setMethodResolvers"),
                   ("el",), "使用了受限求值上下文。"),
)


# ---------------------------------------------------------------- 传播函数

# 污点通过这些调用继续传播（不改变「是否可控」这一事实）。
PASSTHROUGH: tuple[re.Pattern[str], ...] = (
    re.compile(r"\.(?:trim|substring|toLowerCase|toUpperCase|replace|replaceAll|concat|strip)\s*\("),
    re.compile(r"\+\s*\w+|\w+\s*\+"),
    re.compile(r"String\.format\s*\(|String\.join\s*\("),
    re.compile(r"\.append\s*\("),
)


def sinks_for(kind: str) -> tuple[SinkModel, ...]:
    return tuple(sink for sink in SINKS if sink.sink_kind == kind)


def model_summary() -> dict[str, object]:
    """供 `java-audit rules` 与报告展示模型覆盖情况。"""
    frameworks = sorted({item.framework for item in SINKS} | {item.framework for item in SOURCES})
    kinds = sorted({item.sink_kind for item in SINKS})
    return {
        "sources": len(SOURCES),
        "sinks": len(SINKS),
        "sanitizers": len(SANITIZERS),
        "sink_kinds": kinds,
        "frameworks": frameworks,
    }

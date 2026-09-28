from __future__ import annotations

from .findings import Finding


LEARNING_NOTES = {
    "CWE-89": "SQL 注入的关键不是出现字符串拼接本身，而是攻击者可控数据是否进入 SQL 结构。",
    "CWE-78": "命令注入需要确认外部输入是否能影响命令或参数，以及调用是否经过 shell。",
    "CWE-22": "路径遍历需要沿着输入追踪到文件访问点，并检查规范化后是否仍被限制在允许目录。",
    "CWE-611": "XXE 审计要检查解析器的实际配置；不同 XML 工厂的安全开关并不完全相同。",
    "CWE-798": "硬编码凭据会进入源码历史和构建产物；示例值与测试夹具通常需要人工排除。",
}

EVIDENCE_GATES = {
    "CWE-89": (
        ["外部可控值到达 SQL 执行 API", "SQL 结构由字符串拼接或不安全模板改变"],
        ["所有动态值都通过参数占位符绑定", "命中内容只影响固定白名单字段"],
    ),
    "CWE-78": (
        ["外部输入影响可执行程序或命令参数", "危险调用在可达路径上执行"],
        ["程序和参数完全固定且不经过 shell", "动态值经过严格枚举白名单"],
    ),
    "CWE-22": (
        ["外部输入参与最终文件路径", "规范化后的路径可以离开允许根目录"],
        ["toRealPath/normalize 后验证 startsWith 允许根目录", "外部仅能使用服务端生成的不可猜测标识"],
    ),
    "CWE-611": (
        ["解析内容可被外部控制", "解析器允许 DTD 或外部实体"],
        ["解析前明确禁止 DTD、外部实体和外部资源访问", "输入由可信常量生成"],
    ),
    "CWE-798": (
        ["固定值是真实有效的凭据", "该值会进入源码历史或构建产物"],
        ["值仅为无效测试夹具", "运行时从秘密管理服务注入"],
    ),
    "CWE-502": (["攻击者可控字节进入 readObject", "反序列化类路径中存在可利用 gadget"], ["仅允许经过认证和签名的固定类型数据", "使用安全数据格式替代 Java 原生反序列化"]),
    "CWE-918": (["攻击者能控制 URL 的协议、主机或端口", "服务端请求可访问敏感网络或云元数据"], ["解析后对协议、主机、端口和解析 IP 执行严格白名单", "请求目标完全由服务端常量决定"]),
    "CWE-917": (["外部数据成为表达式内容", "表达式上下文允许访问敏感类型或方法"], ["外部数据只作为表达式变量值", "使用受限上下文并固定表达式"]),
    "CWE-327": (["MD5/SHA-1 用于密码、签名或安全完整性", "攻击者可利用碰撞或快速暴力破解"], ["算法仅用于非安全去重标识", "已使用适合场景的现代算法和参数"]),
}


FIVE_QUESTIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "entry",
        "入口与触达路径：该线索对应的入口和 HTTP 路径（或其他触发方式）是什么？",
        ("已定位入口", "未发现入口", "待确认"),
    ),
    (
        "identity",
        "身份与权限：触达该问题需要什么身份和权限（匿名、低权限、管理员）？",
        ("已确认所需权限", "无需权限即可触达", "待确认"),
    ),
    (
        "dataflow",
        "数据流：外部输入如何一步步到达危险操作？路径证据是已证明、推测还是缺失？",
        ("已证明路径", "仅推测路径", "缺失/无法解析"),
    ),
    (
        "controls",
        "安全控制：哪些防护（参数化、白名单、权限、净化）已经确认有效？",
        ("已确认有效控制", "未发现有效控制", "待确认"),
    ),
    (
        "gap",
        "证据缺口：哪些成立条件仍然缺少证据，需要人工补充什么信息？",
        ("无关键缺口", "存在关键缺口", "待确认"),
    ),
)

PATH_CONCLUSION_LABELS = {
    "proven": "已证明路径（扫描器级数据流）",
    "inferred": "推测路径（保守的同类候选）",
    "missing": "缺失路径（没有可用路径证据）",
    "unresolved": "无法解析（路径上存在动态调用）",
}


def learning_note(finding: Finding) -> str:
    """Deterministic teaching text. It never upgrades a finding to confirmed."""
    return LEARNING_NOTES.get(
        finding.cwe,
        "先验证输入是否可控、危险操作是否可达，再结合运行环境判断真实影响。",
    )


def evidence_gates(finding: Finding) -> tuple[list[str], list[str]]:
    return EVIDENCE_GATES.get(
        finding.cwe,
        (["危险操作在真实运行路径中可达", "相关输入可被不可信主体控制"], ["存在经过验证的净化、权限或不可达条件"]),
    )


def path_conclusion_label(finding: Finding) -> str:
    return PATH_CONCLUSION_LABELS.get(
        str(finding.metadata.get("path_assessment", {}).get("conclusion", "missing")),
        PATH_CONCLUSION_LABELS["missing"],
    )

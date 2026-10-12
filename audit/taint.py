"""方法内污点追踪（阶段 C-2）。

消费 audit/frameworks.py 的模型，在**单个方法体**内做变量级污点传播：

    source 赋值 → 变量污染 → 传播/净化 → sink 调用参数命中

只做方法内追踪：跨方法的调用关系需要真实的控制流与类型信息，超出静态文本分析的可靠范围，
宁可标注「未解析」也不猜测。

输出的是 Finding，trace 里带上 source → 传播 → sink 的路径步骤，
供 evidence.py 归并成统一证据记录。
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .findings import Finding, Location
from .project import iter_java_files
from .frameworks import SANITIZERS, SINKS, SOURCES

PARALLEL_THRESHOLD = 32
MAX_WORKERS = 8

# 局部变量声明/赋值：String x = ...;  或  var x = ...;  或 x = ...;
_ASSIGN_RE = re.compile(r"^\s*(?:(?:final|static|private|public|protected)\s+)*"
                        r"(?:[\w.<>\[\],?\s]+?\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$")
# 方法签名起点：修饰符 + 返回类型 + 方法名(
_METHOD_RE = re.compile(r"^\s{0,8}(?:@\w+.*)?\s*(?:public|protected|private|static|final|synchronized|abstract|default)\s+"
                        r"[\w.<>\[\],?\s]+?\s+(\w+)\s*\([^;{]*\)\s*(?:throws\s+[\w.,\s]+)?\{?\s*$")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_SPRING_PARAM_RE = re.compile(
    r"@(?:RequestParam|PathVariable|RequestBody|ModelAttribute|RequestHeader|RequestPart)"
    # 类型 = 标识符 + 可选泛型（<> 内允许逗号与空格）+ 可选数组维度。
    # 不能用 [\w,<>\[\]] 之类扁平字符类：逗号会把参数分隔符当成泛型内部内容，
    # 从而跨参数吞并（@RequestParam String a, HttpServletResponse b 会错捕 b）。
    r"(?:\s*\([^)]*\))?\s+(?:final\s+)?"
    r"[\w.]+(?:\s*<\s*[\w.<>,?\[\]\s]*\s*>)?(?:\s*\[\s*\])*"
    r"\s+([A-Za-z_$][\w$]*)"
)
_MULTIPART_PARAM_RE = re.compile(r"\bMultipartFile\s+([A-Za-z_$][\w$]*)")
_REQUEST_OBJECT_RE = re.compile(r"\bHttpServletRequest\s+([A-Za-z_$][\w$]*)")
# 字面量目标主机：引号内以 scheme:// 开头且 authority 非空、未被 + 拼接打断。
# 例："https://status.example.com/api?nonce=" 命中；"http://" + host 不命中。
_LITERAL_HOST_URL = re.compile(r'"(?:https?|ftp)://[^/"\s+]+')
_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
_LINE_COMMENT_RE = re.compile(r"//.*$")


def strip_literals(line: str) -> str:
    """去掉字符串/字符字面量内容与行注释，只留下真正的代码。

    变量名出现在引号里（如 "?nonce=" 中的 nonce）不构成引用；
    不先做这一步，会把字面量里的标识符误判为变量使用。
    """
    return _LINE_COMMENT_RE.sub("", _STRING_LITERAL_RE.sub('""', line))


def split_methods(lines: list[str]) -> list[tuple[int, int, str]]:
    """按大括号配平切出方法体，返回 (起始行号, 结束行号, 方法名)。

    配平失败时退化为整段返回，避免丢代码导致漏报。
    """
    blocks: list[tuple[int, int, str]] = []
    index = 0
    total = len(lines)
    while index < total:
        match = _METHOD_RE.match(lines[index])
        if not match:
            index += 1
            continue
        name = match.group(1)
        start = index
        depth = 0
        end = index
        while end < total:
            depth += lines[end].count("{") - lines[end].count("}")
            if depth <= 0 and end > start and "{" in "".join(lines[start:end + 1]):
                break
            end += 1
        if end >= total:
            end = total - 1
        if end > start:
            blocks.append((start + 1, end + 1, name))
        index = end + 1
    return blocks


def analyze_method(body: list[str], base_line: int, rel_path: str, handler: str, occurrences: dict | None = None) -> list[Finding]:
    """在单个方法体内做污点追踪，返回发现列表。

    净化信号不清除污点，而是记为该发现的**反证**（evidence_against）——
    净化是否充分必须人工判断，工具不能替用户宣布安全。
    occurrences：跨方法共享的位移容忍身份计数器（issue #6），由 _analyze_file 持有。
    """
    findings: list[Finding] = []
    tainted: dict[str, dict] = {}          # 变量名 -> 来源信息
    sanitized: dict[str, list[str]] = {}   # 变量名 -> 净化信号说明（反证）

    def _sanitize_hits(line: str, kind: str) -> list[str]:
        notes = []
        for item in SANITIZERS:
            if kind not in item.applies_to:
                continue
            if item.pattern.search(line):
                notes.append(f"{item.name}：{item.note}")
        return notes

    for offset, raw in enumerate(body):
        line = raw.strip()
        if not line:
            continue
        line_no = base_line + offset

        # 1) 来源：声明处来自不可信入口，或参数带请求绑定注解
        for source in SOURCES:
            if not source.pattern.search(line):
                continue
            assign = _ASSIGN_RE.match(line)
            if assign:
                var = assign.group(1)
                if var in ("return", "new") or var.isupper():
                    continue
                tainted[var] = {"line": line_no, "label": f"{source.name} 赋给 {var}",
                                "source": source.name, "via": None}
                continue
            # 注解或框架参数：只提取明确的参数变量，不能用“行尾最后一个标识符”，
            # 因为 throws Exception、方法名等会被误当成污点变量。
            variables: list[str] = []
            if source.framework == "spring-mvc":
                variables.extend(_SPRING_PARAM_RE.findall(line))
                variables.extend(_MULTIPART_PARAM_RE.findall(line))
                variables.extend(_REQUEST_OBJECT_RE.findall(line))
            elif source.framework == "servlet":
                variables.extend(_REQUEST_OBJECT_RE.findall(line))
            elif source.kind == "cli" and re.search(r"String\s*\[\s*\]\s+args", line):
                variables.append("args")
            for token in dict.fromkeys(variables):
                tainted[token] = {"line": line_no, "label": f"{source.name} 绑定的参数 {token}",
                                  "source": source.name, "via": None}

        # 2) 传播：右值引用了已污染变量
        assign = _ASSIGN_RE.match(line)
        if assign:
            var, rhs = assign.group(1), assign.group(2)
            rhs_code = strip_literals(rhs)
            hits = [name for name in tainted if re.search(rf"\b{re.escape(name)}\b", rhs_code)]
            if hits and var != hits[0]:
                origin = tainted[hits[0]]
                tainted[var] = {"line": line_no, "label": f"{var} 由 {hits[0]} 传播而来",
                                "source": origin["source"], "via": origin["line"], "text": rhs,
                                "literal_host": bool(_LITERAL_HOST_URL.search(rhs))
                                                or bool(origin.get("literal_host"))}
            if hits and hits[0] in sanitized:
                sanitized[var] = list(sanitized[hits[0]])

        # 3) 净化：记录反证，不从污点集合里移除
        for var in list(tainted):
            if not re.search(rf"\b{re.escape(var)}\b", line):
                continue
            for kind in {sink.sink_kind for sink in SINKS}:
                for note in _sanitize_hits(line, kind):
                    sanitized.setdefault(var, [])
                    if note not in sanitized[var]:
                        sanitized[var].append(note)

        # 4) 终点：危险调用的参数里出现污染变量
        for sink in SINKS:
            if not sink.pattern.search(line):
                continue
            code = strip_literals(line)
            arg_vars = [name for name in tainted if re.search(rf"\b{re.escape(name)}\b", code)]
            if not arg_vars:
                continue
            # 同一行可能同时提到多个污点变量：取行内最后出现的那个，
            # 它通常是真正进入调用的实参（"...".concat(x).getBytes() 里的 x）。
            arg_vars.sort(key=lambda n: code.rfind(n))
            var = arg_vars[-1]
            info = tainted[var]
            trace = [
                {"kind": "source-candidate", "path": rel_path, "line": info["line"], "label": info["label"]},
                {"kind": "sink", "path": rel_path, "line": line_no, "label": f"{sink.title}：{line[:80]}"},
            ]
            if info.get("via"):
                trace.insert(1, {"kind": "propagation-candidate", "path": rel_path, "line": info["via"],
                                 "label": f"{var} 在方法内的文本传播候选"})
            against = list(sanitized.get(var) or [])
            # SSRF 的可利用前提是「目标主机可控」。行内任一污点变量由字面量 URL
            # 拼接而来时（scheme 与 authority 都在引号内），目标主机很可能不可控。
            # 这只是反证而非判定：https://host/x + "@evil.example.com" 仍能改写主机，
            # 是否需要继续深挖由复核人决定。
            if sink.sink_kind == "ssrf" and any(tainted[n].get("literal_host") for n in arg_vars):
                against.append("字面量目标主机：URL 的协议与主机部分写在引号内，"
                               "外部输入只在主机之后拼接（仍需复核 @ 与路径注入等改写手法）")
            # 位移容忍身份（issue #6）：规则 + 路径 + 污点变量 + 空白归一化终点行 + 出现序号，
            # 不含绝对行号——格式化插入不会把旧基线条目误标为已修复。
            if occurrences is None:
                occurrences = {}
            normalized = " ".join(line.split())
            occ_key = (sink.rule_id, rel_path, var, normalized)
            index = occurrences.get(occ_key, 0)
            occurrences[occ_key] = index + 1
            fingerprint = hashlib.sha256(f"{sink.rule_id}:{rel_path}:{var}:{normalized}:{index}".encode()).hexdigest()[:16]
            findings.append(Finding(
                rule_id=sink.rule_id,
                title=f"{sink.title}（污点追踪）",
                severity=sink.severity,
                confidence="low" if against else "medium",
                cwe=sink.cwe,
                scanner="taint",
                location=Location(rel_path, line_no, 1),
                evidence=line[:300],
                description=sink.description,
                review_steps=list(sink.review_steps),
                remediation=sink.remediation,
                fingerprint=fingerprint,
                trace=trace,
                evidence_for=[f"不可信来源 {info['source']} 赋给变量 {var}",
                              f"同方法内 {var} 到达 {sink.title}"],
                evidence_against=list(against),
                metadata={
                    "taint": {
                        "source": info["source"],
                        "variable": var,
                        "sink_kind": sink.sink_kind,
                        "framework": sink.framework,
                        "sanitized": bool(against),
                        "handler": handler,
                    },
                },
            ))
    return findings


def _analyze_file(task: tuple[str, str]) -> list[Finding]:
    """Worker：分析单个 Java 文件。顶层函数以便多进程 pickle。"""
    abs_path_str, root_str = task
    path = Path(abs_path_str)
    root = Path(root_str)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = path.relative_to(root).as_posix()
    lines = content.splitlines()
    out: list[Finding] = []
    occurrences: dict = {}
    for start, end, name in split_methods(lines):
        out.extend(analyze_method(lines[start - 1:end], start, rel, name, occurrences))
    return out


def run_taint(root: Path, progress: bool = False, workers: int | None = None) -> list[Finding]:
    """对项目执行方法内污点分析。"""
    files = list(iter_java_files(root))
    findings: list[Finding] = []
    if len(files) < PARALLEL_THRESHOLD:
        for path in files:
            findings.extend(_analyze_file((str(path), str(root))))
    else:
        count = workers or min(MAX_WORKERS, os.cpu_count() or 4)
        chunksize = max(1, len(files) // (count * 8))
        tasks = [(str(path), str(root)) for path in files]
        with ProcessPoolExecutor(max_workers=count) as pool:
            for batch in pool.map(_analyze_file, tasks, chunksize=chunksize):
                findings.extend(batch)
        if progress:
            print(f"[taint] scanned {len(files)} files (workers={count})", file=sys.stderr)
    return findings

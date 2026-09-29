<div align="center">

![Java Audit Lab](docs/assets/readme-hero-v2.png)

[简体中文](README.md) · [English](README_EN.md)

[![Release](https://img.shields.io/github/v/release/Zuimeng-0710/java-audit-lab?style=flat-square&color=2563eb)](https://github.com/Zuimeng-0710/java-audit-lab/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Zuimeng-0710/java-audit-lab/ci.yml?branch=main&style=flat-square&label=tests)](https://github.com/Zuimeng-0710/java-audit-lab/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-0ea5e9?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-10b981?style=flat-square)](LICENSE)
[![Rules](https://img.shields.io/badge/Java_rules-12-f97316?style=flat-square)](#当前能力)

**把扫描命中整理成可复核的 Java 安全证据。**

[快速开始](#快速开始) · [使用场景](#适合谁使用) · [当前能力](#当前能力) · [路线图](#路线图) · [参与项目](#参与项目)

</div>

# Java Audit Lab

Java Audit Lab 是面向 **Java 学习者、开发者和安全审计人员** 的开源代码审计工作台。它把规则命中、数据流、权限声明和人工判断组织成一条可回看的证据链，帮助使用者回答：

- 问题从哪个入口进入？
- 输入如何到达危险操作？
- 中间是否存在净化、白名单或权限控制？
- 目前能证明什么，还有哪些条件缺少证据？
- 修复后问题是否真正消失？

> [!IMPORTANT]
> 扫描结果是待人工复核的安全线索，不等于已确认漏洞。请只分析自己拥有或已获得明确授权的项目与环境。

## 这个项目解决什么问题

| 常见困难 | Java Audit Lab 的处理方式 |
|---|---|
| 规则命中了，但不知道为什么 | 同时展示入口、Source、传播、Sanitizer、Sink 和代码位置 |
| 工具把猜测写成确定漏洞 | 区分**已证明、推测、缺失、无法解析**四类证据状态 |
| 不清楚接口是否需要登录或角色 | 生成端点权限矩阵，并标出权限证据来自注解、配置还是拦截器 |
| 扫描器结果分散 | 归并内置规则、Semgrep、SpotBugs、Dependency-Check、CodeQL 和 SARIF |
| 修复后无法确认结果 | 使用基线和 Git 增量审计识别新增、已有、已修复与同规则残留 |
| 学习时只看到结论 | 报告提供漏洞成立五问、反证提示、人工结论和信心记录 |

## 适合谁使用

| 使用者 | 可以完成的事情 |
|---|---|
| Java 安全学习者 | 从真实代码位置学习 Source → Propagation → Sink，并练习排除误报 |
| Java 开发者 | 在提交或合并前检查本次修改、权限变化和高风险调用 |
| 安全审计人员 | 汇总多个扫描器证据，记录人工结论并生成可交付报告 |
| 规则贡献者 | 使用 vulnerable / safe / edge 语料验证新规则和误报边界 |

Java Audit Lab 当前适合作为学习、初筛和人工复核工作台。需要完整跨方法、跨模块数据流证明的大型企业项目，应结合 CodeQL 等分析引擎并由安全人员确认。

## 快速开始

### 1. 安装当前源码版本

```bash
git clone https://github.com/Zuimeng-0710/java-audit-lab.git
cd java-audit-lab
python -m pip install -e .
```

需要 Python 3.10 或更新版本。基础扫描和报告生成没有第三方 Python 依赖。

### 2. 一条命令扫描并打开报告

```bash
jal . -O
```

`.` 表示当前 Java 项目，`-O` 表示完成后打开 HTML 报告。只生成报告时运行：

```bash
jal .
```

旧命令 `java-audit scan .` 继续兼容。已发布的 v1.8.0 wheel 可继续使用旧命令；`jal` 是 v1.9.0 源码版的推荐入口。

### 常用短命令

| 目的 | 命令 |
|---|---|
| 扫描当前项目 | `jal .` |
| 扫描并打开报告 | `jal . -O` |
| 检查本机环境 | `jal d` |
| 查看内置规则 | `jal r` |
| 运行规则基准 | `jal b` |
| 只用指定扫描器 | `jal . -s builtin,secrets,taint` |
| 审计未提交修改 | `jal . -d` |
| 与 main 分支比较 | `jal . -d main` |
| 审计单次提交 | `jal . -C HEAD~1` |
| 对比上一份报告 | `jal . -b old/report.json` |
| CI 中阻止新增高危问题 | `jal . -f high -y` |

完整参数：

```bash
jal -h
jal s -h
```

### 报告文件

| 文件 | 用途 |
|---|---|
| `report.html` | 离线交互复核：筛选、证据链、五问、人工结论与导出 |
| `report.json` | 完整结构化证据，可用于基线和二次开发 |
| `report.sarif` | SARIF 2.1，可接入代码托管平台和安全工具 |
| `report.md` | 适合工单、审计文档和 Pull Request |

## 审计工作流

### 🔵 ① 发现与建模

| `1.1` 项目画像 | `1.2` 入口与信任边界 | `1.3` Source / Sink | `1.4` 数据流扫描 |
|:---:|:---:|:---:|:---:|
| 框架、依赖、攻击面 | 路由、身份、数据归属 | 输入源、危险操作 | 传播、净化、不确定路径 |

### 🟠 ② 验证与泛化

| `2.1` 成立条件 | `2.2` 同类模式 | `2.3` 反证与绕过 |
|:---:|:---:|:---:|
| 触发条件、输入可控性 | 相似调用、关联文件 | 白名单、权限、安全控制 |

### 🟢 ③ 结论与复测

| `3.1` 人工结论 | `3.2` 修复复测 | `3.3` 结果归档 |
|:---:|:---:|:---:|
| 判定、依据、信心 | 基线对比、回归验证 | 报告、结论、审计轨迹 |

每个阶段都记录已有证据和缺失证据。扫描结果或人工回答可以推进状态，AI 解释只作为辅助说明。

### 漏洞成立五问

| 检查点 | 核心问题 | 期望证据 |
|---|---|---|
| **入口** | 外部入口和 HTTP 路径是什么？ | 路由、Controller、消息消费者或任务入口 |
| **权限** | 调用需要什么身份、角色或数据归属？ | Security 配置、权限注解、拦截器或所有权校验 |
| **传播** | 输入如何到达危险操作？ | Source、赋值与调用传播、最终 Sink |
| **反证** | 已确认哪些净化、白名单或安全控制？ | 参数化查询、规范化、编码、白名单或边界检查 |
| **缺口** | 哪些成立条件仍然缺少证据？ | 未解析调用、动态配置、运行时条件或人工确认项 |

## 当前能力

| 状态 | 能力 | 当前范围 |
|:---:|---|---|
| 稳定 | 教学规则 | SQL、命令、路径、XXE、SSRF 等 12 类规则 |
| 稳定 | 配置凭据扫描 | YAML、Properties、JSON、`.env`，原始密钥不进入报告 |
| 测试中 | 方法内污点分析 | 请求参数、赋值传播、净化反证、危险终点 |
| 稳定 | 攻击面画像 | Web 入口、拦截器、上传、消息、任务、数据访问层 |
| 测试中 | 端点权限矩阵 | Spring Security、Shiro、方法注解、MVC Interceptor |
| 稳定 | Git 增量审计 | 变更范围、权限放宽、同类位置、修复残留 |
| 稳定 | 多引擎归并 | SARIF、Semgrep、SpotBugs、Dependency-Check、CodeQL |
| 稳定 | 复核档案 | 本地保存、导入导出、基线新增与已修复分类 |
| 稳定 | 验证台账 | 任务卡、执行进度、成功判据、证据路径和误报归因 |
| 试点 | 匿名评测语料 | 四类 vulnerable / safe / edge 试点样本 |

**状态说明：** 稳定＝已纳入常规测试 · 测试中＝功能可用但仍在完善 · 试点＝用于验证方向和评测流程

每条发现会标注 `production`、`test`、`example` 或 `generated` 范围，避免测试与示例代码稀释生产风险。

## 证据模型

Java Audit Lab 不会为了让报告看起来完整而虚构调用链。每条发现统一记录：

```json
{
  "entry": {"covered": true, "note": "位置位于已识别入口文件"},
  "source": {"path": "src/main/java/lab/Demo.java", "line": 10},
  "propagation": [{"path": "...", "line": 11, "label": "可能的赋值传播"}],
  "sanitizers": [{"origin": "control", "detail": "发现白名单信号"}],
  "sink": {"path": "src/main/java/lab/Demo.java", "line": 12},
  "authorization": {"status": "权限推测"},
  "unresolved_steps": [],
  "engine_evidence": [{"scanner": "builtin", "rule_id": "JAL-SQL-001"}]
}
```

| 状态 | 含义 |
|---|---|
| **已证明** | 扫描器提供明确路径或代码配置提供直接证据 |
| **推测** | 内置规则或局部文本分析形成的保守候选 |
| **缺失** | 当前没有足够证据，工具不会自动补写 |
| **无法解析** | 反射、动态分派或运行时配置阻断静态路径 |

## 扫描器与集成

外部扫描器没有安装时，其他扫描器和报告仍会继续运行。

| 扫描器 | 条件 | 提供的证据 |
|---|---|---|
| `builtin` | 内置 | 教学规则与局部路径候选 |
| `secrets` | 内置 | 脱敏的配置凭据线索 |
| `taint` | 内置 | 方法内输入、传播、净化与终点 |
| Semgrep | 安装 `semgrep` | 本地 Java 规则结果 |
| SpotBugs | 安装 CLI，项目已有 class/JAR | 字节码缺陷 |
| Dependency-Check | 安装 CLI | 第三方依赖公开漏洞 |
| CodeQL | 安装 CLI | 跨文件数据流与安全查询 |

导入现有结果：

```bash
jal . -s builtin -S codeql.sarif
```

SpotBugs XML 和 Dependency-Check JSON 仍可通过 `--spotbugs-xml` 与 `--dependency-check-json` 导入。

## 项目配置

将 [`.java-audit.example.yml`](.java-audit.example.yml) 复制到待审计项目根目录并改名为 `.java-audit.yml`：

```yaml
scanners: [builtin, secrets, taint]
public_endpoints: [/login, /health]
fail_on: high
cache: true
exclude_paths: [src/test/*, generated/*]
extra_rules: [.java-audit/rules/team-rules.yaml]
report_owner: security-team
authorization_ref: AUTH-2026-001
scope_note: 本次仅扫描后端服务目录
retention_note: 项目结束后按授权约定清理源码和缓存
```

命令行参数覆盖配置文件。放在 `.java-audit/rules/` 中的 YAML 或 JSON 规则会自动加载。报告档案字段仅用于记录使用者提供的信息，工具不会据此自动声明已经获得授权。

## 可选 AI 解释

AI 只接收单条发现的脱敏证据，用来生成学习解释，不能把发现升级为“已确认漏洞”。配置兼容 `/chat/completions` 的接口后运行：

```bash
jal . -a -l beginner
```

支持 `beginner`、`intermediate`、`advanced` 三个解释层级。

## 路线图

路线图表示当前开发方向，不代表已经实现或承诺具体发布日期。

### v1.9：验证闭环

- [x] `jal` 短命令、默认扫描和常用参数别名
- [x] 完整中英文 README
- [x] 为每条发现生成不含攻击载荷的验证任务卡
- [x] 增加验证状态、执行人、尝试次数、成功判据和证据路径
- [x] 增加误报归因、验证台账和动态结果统计
- [ ] 将匿名语料扩展到更多规则、真实脱敏案例和独立 holdout 集
- [ ] 为 CLI 增加稳定的机器可读摘要和更清晰的退出码文档
- [ ] 增加 GitHub Actions 示例，让 Pull Request 自动执行增量审计

### 中期：分析能力

- [ ] Controller → Service → Mapper 的跨方法数据流
- [ ] 更精确的调用图、接口实现和继承关系解析
- [ ] Spring WebFlux、Dubbo、gRPC 和更多消息框架入口
- [ ] 对象级权限与 IDOR 场景的所有权证据
- [ ] 在授权靶场中生成安全的人工验证步骤与修复复测记录
- [ ] 从复核结论生成脱敏回归案例
- [ ] 规则抑制、风险接受和审计结论的团队配置

### 长期：可扩展工作台

- [ ] 稳定的扫描器插件 API 和第三方规则包
- [ ] VS Code / IntelliJ 结果跳转与本地复核
- [ ] 多人共享复核档案和审计差异
- [ ] 大型项目的持久化索引与增量调用图
- [ ] 在不改变证据状态的前提下，用 AI 辅助生成验证步骤和修复建议

欢迎通过 Issue 说明真实 Java 项目中的框架、误报或漏报案例。路线图优先级将以可复现样本和回归测试为依据。

## 当前边界

- `builtin` 与 `taint` 目前不提供完整的跨方法、跨模块路径证明。
- 未识别到权限声明表示证据缺失，不代表接口一定没有访问控制。
- 反射、动态分派、运行时配置和生成源码可能降低静态分析覆盖率。
- SpotBugs 需要先构建项目；Dependency-Check 首次更新漏洞库可能耗时较长。
- AI 解释可能错误，最终判断应回到源码、配置和扫描器证据。
- 内置 benchmark 和 train 语料用于回归，不代表真实项目准确率。

完整版本变化见 [CHANGELOG.md](CHANGELOG.md)。

## 参与项目

```bash
python -m unittest discover -s tests -v
jal b
python corpus/tools/validate_corpus.py
python corpus/tools/evaluate_corpus.py --strict-locations
```

贡献规则时，请同时提供：

1. 应当命中的危险样本；
2. 不应命中的安全样本；
3. 容易误报的边界样本；
4. 人工复核条件和修复建议。

参见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请按照 [SECURITY.md](SECURITY.md) 私密报告。

## License

Java Audit Lab 使用 [MIT License](LICENSE)。Semgrep、SpotBugs、Find Security Bugs、OWASP Dependency-Check 和 CodeQL 是独立项目，使用时需遵守各自许可证与条款。

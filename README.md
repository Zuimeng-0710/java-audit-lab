# Java Audit Lab 1.8.0

**Evidence Driven Audit Playbook** —— 面向 Java 学习者、开发者与安全审计人员的可复核代码审计工作台。它把九阶段审计方法论编码成状态机和证据门槛：规则引擎说明发现了什么，数据流引擎说明代码如何到达，人工复核决定漏洞是否成立，回归测试验证修复是否有效。

## 1.8 可开源发布候选

1.8.0 在方法内污点分析之外补齐了发布前的安全边界：配置凭据扫描全程脱敏、生产/测试/示例/生成代码作用域、显式公开端点配置，并降低 `URI.create` 仅用于路径解析时的 SSRF 误报。内置规则新增明文密码比较、敏感日志和 URL 查询参数令牌检查。

### 方法内污点分析

- 新增数据驱动的 Java 框架模型包，统一描述 Source、Sink 和 Sanitizer。
- 新增零依赖 `taint` 扫描器，追踪单个方法内的请求参数、变量赋值、净化信号与危险操作。
- 方法内文本传播只标记为“推测路径”；只有 CodeQL、Semgrep Pro 等扫描器级数据流才能标记为“已证明路径”。
- 当前不跨方法、跨类追踪，Controller → Service → Mapper 等链路需要 CodeQL、Semgrep 或后续调用图能力补充。

> 扫描结果是待复核线索，不是漏洞定论。请只扫描获得明确授权的代码和环境；授权状态由使用者自行确认，报告不代为声明。

## 1.3 大型项目适配

- **多进程并行**：BuiltinRunner 与 surface 收集器自动按文件分批并行；500 文件扫描从约 14.5s 提速到约 1.5s（9.7×）。CPU 核心数自动检测，最多用 8 个 worker；30 文件以下走串行路径避免进程开销。
- **进度反馈**：TTY 环境自动开 stderr 进度；CI/管道默认静默。可强制 `--progress` 或 `--no-progress`，可手动 `--workers N` 指定进程数。
- **排除路径**：`--exclude "glob"` 或 `.java-audit.yml` 中 `exclude_paths: [...]` 跳过 `src/test/*`、`generated/*` 等噪声目录，提升大型项目的复核效率。
- **外部规则**：内置 9 条规则之外，可用 YAML/JSON 扩展规则集。`--rules path.yaml` 显式指定，或放进 `<project>/.java-audit/rules/` 目录会被自动加载；缺省字段使用保守默认值，错配规则不会让扫描崩溃。示例见 `examples/extra-rules.yaml`。
- **分组视图**：HTML 报告工具栏加 view-mode 下拉，支持平铺列表 / 按严重度 / 按规则 / 按文件 / 按目录；分组头粘性吸顶、可折叠；与现有 search/severity/review-filter 联动。500+ 发现也能看清楚。

## 审计流水线（1.2 核心）

```
项目画像 → 入口与信任边界 → Source/Sink 建模 → 数据流扫描
        → 成立条件验证（五问） → 同类模式泛化 → 反证与绕过检查
        → 人工结论 → 复测与报告
```

每个阶段在报告中展示**完成状态、已获证据和缺失证据**。阶段不会被 AI 的自我声明推进，只由可核验证据或人工回答驱动。CLI 会在扫描前请求确认扫描范围（CI 用 `--yes` 跳过）。

### 漏洞成立五问

每条线索必须回答，关键问题都有证据后才能从「待复核」升级为「确认漏洞」：

1. 入口和 HTTP 路径是什么？
2. 需要什么身份和权限？
3. 输入如何到达危险操作？
4. 哪些安全控制已经确认？
5. 哪些条件仍然缺少证据？

### Source → Sink 路径证据等级

| 等级 | 含义 |
|---|---|
| 已证明路径 | CodeQL/SARIF 扫描器级数据流 |
| 推测路径 | 内置规则的保守同文件候选 |
| 缺失路径 | 没有可用路径证据，工具不虚构调用链 |
| 无法解析 | 路径上存在反射/动态调用 |

确认一条线索后，报告自动给出**同类模式排查**清单（同规则兄弟位置、同文件邻近写法、同 CWE 其他规则），支持举一反三。

## 与普通扫描报告的区别

- **可证伪复核**：同时列出支持漏洞假设的证据和能够推翻假设的安全条件。
- **保留不确定性**：扫描器证据、规则教学文本、AI 建议和人工结论分开保存。
- **学习可持续**：记录结论、判断依据和信心，导出后可在下一次扫描继续使用。
- **变化优先**：与旧报告比较新增、已有和已修复发现，适合代码评审与 CI。
- **公开优先级**：每条线索展示严重度、置信度、路径、交叉验证和基线变化的具体分值。
- **本地优先**：不启用 AI 时，源码和报告不会由本工具上传。

## 功能

- 识别 Maven、Gradle、普通 Java 项目和常见 Java 框架
- 12 类零依赖 Java 教学规则，并提供独立的配置凭据脱敏扫描器
- 调用并解析 Semgrep、SpotBugs、OWASP Dependency-Check 和 CodeQL
- 导入任意 SARIF 2.1 报告，导出 JSON、SARIF、HTML 和 Markdown 四种报告
- 多引擎统一证据层：把 CodeQL、Semgrep SARIF、SpotBugs、Dependency-Check 的结果归一为同一份证据记录（入口、来源、传播、净化/抑制反证、终点、权限、未解析步骤、引擎佐证）
- 九阶段审计状态机：每阶段列出完成状态、已获证据与缺失证据
- 端点权限矩阵：接口 × 方法 × 身份要求 × 角色/权限 × 危险操作 × 证据状态；支持 Spring Security 配置链、Shiro 过滤链、Spring MVC 自定义拦截器与方法级授权注解
- 攻击面画像：Controller 路由、Filter/Interceptor/Security、上传、MQ 消费者、定时任务、MyBatis ${}、JPA 原生查询
- 漏洞成立五问与同级引导式复核；路径分为已证明、推测、缺失、无法解析四类
- 同类模式泛化：自动列出同规则兄弟位置、同文件邻近写法和同 CWE 其他规则
- 安全控制反证信号扫描（参数化、类型过滤、XXE 加固、路径边界、方法级授权）
- Git 增量审计：`--diff` / `--diff <ref>` / `--commit <ref>`，只分析变更文件与依赖闭包，并对比权限声明变化、验证修复是否真正切断路径
- 展示 CodeQL/SARIF 数据流路径；为内置规则生成保守的局部传播候选路径
- 复核档案导出、重新导入和浏览器本地保存
- 基线差异和可配置的 CI 失败阈值
- 可选的 OpenAI 兼容接口 AI 分层解释，调用前自动遮盖常见凭据赋值
- `doctor` 环境诊断和 `rules` 规则清单
- 多扫描器语义归并，保留所有原始规则和证据
- 引导式复核问答、离线数据流图和查询式筛选
- `.java-audit.yml` 项目配置和基于源码状态的增量缓存
- 可分发的内置规则回归基准

## 快速开始

需要 Python 3.10 或更新版本。基础功能没有第三方 Python 依赖。

```powershell
cd java-audit
python -m audit doctor
python -m audit scan examples/vulnerable-demo -o audit-report --scanners builtin --yes
```

打开 `audit-report/report.html`，先看“审计阶段完成度”了解本次还缺哪些证据，再逐条回答五问。

| 文件 | 用途 |
|---|---|
| `report.html` | 互动复核工作台（阶段面板、五问、数据流图、同类模式） |
| `report.md` | 可粘贴进工单/文档的审计报告（含待人工确认项） |
| `report.json` | 完整证据模型，可作为下一轮基线 |
| `report.sarif` | SARIF 2.1，供 CI 与其他工具消费 |

CI 环境用 `--yes` 跳过扫描范围确认：

```powershell
python -m audit scan . -o report --scanners builtin,semgrep --yes
```

安装命令：

```powershell
python -m pip install -e .
java-audit scan D:\path\to\project -o report
```

## 扫描器

默认尝试以下扫描器，未安装或失败的扫描器不会阻止其他扫描器和报告生成。

```powershell
java-audit scan . -o report --scanners builtin,secrets,taint,semgrep,spotbugs,dependency-check,codeql
```

| 扫描器 | 输入条件 | 作用 |
|---|---|---|
| builtin | Java 源码 | 可读的教学规则与局部路径候选 |
| secrets | YAML、Properties、JSON 等配置 | 查找字面量凭据，证据和指纹不保留原值 |
| taint | Java 源码 | 方法内输入、赋值、净化反证与危险终点传播 |
| Semgrep | 安装 `semgrep` | 运行随包发布的本地 Java 规则 |
| SpotBugs | 安装 CLI，项目已有 class/JAR | 字节码缺陷；建议同时安装 Find Security Bugs |
| Dependency-Check | 安装 CLI | 已公开的第三方依赖漏洞 |
| CodeQL | 安装 CLI | 跨文件数据流和安全扩展查询 |

已有其他工具生成的 SARIF 可直接合并：

```powershell
java-audit scan . -o report --scanners builtin --sarif codeql.sarif --sarif another.sarif
```

导入时会尽量吃满 SARIF 里的证据：

- `security-severity`（CVSS 分值）优先于 `level` 决定严重度
- CWE 从规则 `relationships` 分类、`tags`（如 `external/cwe/cwe-079`）和 properties 中提取
- `codeFlows` 转为已证明的数据流步骤，`relatedLocations` 转为补充位置证据
- `suppressions` 自动进入「能够推翻假设」的反证面板
- 消息 `{0}` 占位符按 `arguments` 还原成完整句子

### 统一证据记录

每条发现（含跨引擎合并后的发现）都会生成一份统一证据记录，随报告输出：

```json
{
  "entry": {"covered": true, "note": "位置位于已识别的入口文件"},
  "source": {"path": "src/main/java/lab/AuditPractice.java", "line": 10},
  "propagation": [{"path": "...", "line": 11, "label": "拼接进入 executeQuery 参数"}],
  "sanitizers": [{"origin": "sarif-suppression", "detail": "inSource：@SuppressWarnings"}],
  "sink": {"path": "src/main/java/lab/AuditPractice.java", "line": 11},
  "authorization": {"status": "未采集"},
  "unresolved_steps": [],
  "engine_evidence": [{"scanner": "builtin", "rule_id": "JAL-SQL-001"}]
}
```

缺失的部分如实标注为「未采集」，工具不会为了报告好看而补写不存在的证据。

### 端点权限矩阵

每条 HTTP 端点都会解析身份要求，找不到权限声明时标记为「权限缺失」而不是猜测为「无控制」：

| 证据来源 | 强度 |
|---|---|
| 方法级注解：`@PreAuthorize` / `@Secured` / `@RolesAllowed` / Shiro 注解 | 权限已证明 |
| 配置链匹配：`SecurityFilterChain` matcher / Shiro `filterChainDefinitionMap` | 权限已证明（配置级） |
| Spring MVC 拦截器：`WebMvcConfigurer.addInterceptors()` 的 `addPathPatterns` / `excludePathPatterns` | 权限已证明（配置级，仅校验令牌有效性） |
| 无匹配 | 权限缺失（需人工确认） |

拦截器解析规则：只有名称含鉴权语义（`token` / `jwt` / `login` / `auth` / `role` 等驼峰整词）的
拦截器才计为权限证据，日志或耗时统计类拦截器不会被当作鉴权；`excludePathPatterns` 优先级高于
`addPathPatterns`；拦截器实现内若发现角色判断，只在证据里补充说明，不会擅自升级为具体角色要求。

支持识别数据归属校验（`#id == authentication.name`）并单独标注为「需数据归属」。
存在危险操作但身份要求为匿名或未知的端点，会在报告顶部给出警示。

### Git 增量审计

只分析变更文件及其依赖闭包，适合 PR 与日常提交场景：

```powershell
java-audit scan . -o report --diff                # 工作区未提交变更
java-audit scan . -o report --diff main           # 与 main 分支比较
java-audit scan . -o report --commit HEAD~1       # 单次提交引入的变更
java-audit scan . -o report --diff --changed-only # 不纳入依赖闭包
java-audit scan . -o report --commit HEAD --baseline report/report.json  # 验证修复
```

报告新增「Git 增量审计」章节，回答六件事：

| 问题 | 实现方式 |
|---|---|
| 本次新增哪些路径 | `git diff -U0` 行区间 + 发现落点匹配 |
| 本次新增哪些 Sink | 落在变更行上的危险操作命中 |
| 权限是否被删除或放宽 | 回退变更文件重建旧快照，对比前后端点权限声明 |
| 修复是否真正切断原路径 | 结合基线报告，同规则仍有命中时标记为「同规则残留」 |
| 是否引入同类新位置 | 新增发现与存量规则比对 |
| 变更影响哪些上下文 | 依赖闭包（同包文件与 import 方） |

分析历史提交（如 `--commit HEAD~1`）时，会自动按该提交状态重建源码快照；
否则用当前工作树扫描会把「该提交引入的问题」扫成「没有问题」。

已有 SpotBugs 或 Dependency-Check 报告也可以直接导入：

```powershell
java-audit scan . -o report --scanners builtin `
  --spotbugs-xml target/spotbugsXml.xml `
  --dependency-check-json dependency-check-report.json
```

## 项目配置和缓存

将 `.java-audit.example.yml` 复制为目标项目根目录下的 `.java-audit.yml`。命令行参数会覆盖配置文件。默认按 Java 文件和构建清单的大小、修改时间计算缓存键；使用 `--no-cache` 可强制重新扫描。

```yaml
scanners: [builtin, secrets, taint, semgrep, spotbugs, dependency-check, codeql]
public_endpoints: [/login, /health]
fail_on: high
ai_level: beginner
cache: true
exclude_paths: [src/test/*, generated/*]
extra_rules: [.java-audit/rules/team-rules.yaml]
```

报告搜索框支持组合查询：`cwe:89 path:controller scanner:codeql priority:70`。

## 基线与复核档案

第一次扫描后，用旧报告作为基线：

```powershell
java-audit scan . -o report-next --baseline report/report.json
```

在 HTML 中点击“导出复核档案”，下一次扫描重新载入：

```powershell
java-audit scan . -o report-next --review-file review.json
```

CI 中只对基线新增的高危及以上问题返回退出码 1：

```powershell
java-audit scan . -o report --baseline old-report.json --fail-on high
```

## 可选 AI 解释

AI 只接收单条发现的脱敏证据。它只能生成学习解释，不能把发现升级成“已确认漏洞”。接口使用兼容 `/chat/completions` 的服务：

```powershell
$env:JAVA_AUDIT_AI_ENDPOINT="http://localhost:11434/v1"
$env:JAVA_AUDIT_AI_MODEL="your-model"
$env:JAVA_AUDIT_AI_KEY=""
java-audit scan . -o report --scanners builtin --ai --ai-level beginner
```

可选层级：`beginner`、`intermediate`、`advanced`。

## 复核方法

1. 先看“审计阶段完成度”，确认本次哪些阶段缺少证据。
2. 找到外部输入来源，例如 HTTP 参数、消息、文件或数据库字段。
3. 沿赋值和调用追踪到危险操作，判断路径属于已证明、推测还是缺失。
4. 回答漏洞成立五问：入口、权限、数据流、已确认控制、证据缺口。
5. 主动寻找能够推翻漏洞假设的反证，并检查同类模式位置是否有同样问题。
6. 在合法测试环境验证，记录结论、证据和判断信心。
7. 修复后重新扫描，并使用基线确认问题消失。

## 开发与测试

```powershell
python -m unittest discover -s tests -v
python -m audit benchmark
python corpus/tools/validate_corpus.py
python corpus/tools/evaluate_corpus.py --strict-locations
python -m compileall -q audit
python -m audit scan examples/vulnerable-demo -o output/vulnerable --scanners builtin --yes
python -m audit scan examples/safe-demo -o output/safe --scanners builtin --yes
```

`corpus/` 是匿名评测语料。当前试点包含 SQL 注入、SSRF、路径遍历和硬编码凭据的
12 个危险、安全与边界案例。它用于验证评测流水线和规则回归，train 样本上的分数不代表
真实项目准确率；详细限制与复现方式见 [corpus/README.md](corpus/README.md)。

规则贡献必须包含危险示例、安全示例、容易误报的边界示例和复核条件。详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 已知边界

- 内置规则追踪的是局部候选路径，不是完整跨方法数据流证明；这类路径标注为“推测路径”。
- 只有 CodeQL/SARIF 提供的 codeFlows 才标记为“已证明路径”；没有 CodeQL 时不存在已证明路径。
- 入口清单基于正则和常见框架注解，覆盖面有限：未命中不代表没有入口，需要在报告中人工确认。
- 工具不生成攻击载荷，也不代为确认漏洞是否可利用；只提供验证思路和待人工确认项。
- 内置基准是小型回归集，不能代表真实项目上的检出率或误报率。
- SpotBugs 需要先构建项目；没有 Find Security Bugs 时安全覆盖有限。
- Dependency-Check 首次更新漏洞数据库可能较慢并需要网络。
- CodeQL 无构建模式对生成源码和复杂构建的覆盖可能不完整。
- AI 输出可能错误，报告始终保留原始扫描证据供人工核对。

## 目录

```text
java-audit/
├─ audit/              # CLI、结果模型、解析器、报告和扫描器适配器
│  ├─ playbook.py      # 九阶段审计状态机与证据门槛
│  ├─ surface.py       # 入口、信任边界与安全控制反证信号
│  └─ report.py        # JSON / SARIF / HTML / Markdown 报告
├─ rules/              # 供学习和扩展的规则目录
├─ examples/           # 安全与不安全示例
├─ tests/              # 解析、规则、报告和基线回归
├─ Dockerfile
└─ .github/workflows/ci.yml
```

## 许可证

项目使用 MIT。Semgrep、SpotBugs、Find Security Bugs、Dependency-Check 和 CodeQL 是独立项目，使用时需遵守各自许可证与条款。

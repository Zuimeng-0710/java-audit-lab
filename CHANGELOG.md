# Changelog

## 2.0.0（2026-10-12）

**主题：验证闭环。** 从「能报出发现」到「能证明发现的质量」——内置匿名评测语料、
三口径诚实指标、已登记能力边界治理，加上机器可读摘要与 CI/PR 集成，让每一次规则
改动都有回归证据，每一次对外声明都有出处。基线身份重构保证增删空行不再产生
new+fixed 噪声（含旧基线兼容层）。

### 语料第二轮扩产：跨方法样本与开源脱敏样本

- 匿名语料从 46 案例扩到 **15 类 59 案例**：新增 11 个跨方法样本
  （Controller → Service → Mapper 三层传播，覆盖 SQL / 命令注入 / SSRF / 路径遍历 / 敏感日志），
  manifest 与 expected.json 标注 `cross_method`
- 新增 5 个开源脱敏样本（derived_from 注明出处）：JoyChou93/java-sec-code 的
  urlConnection vuln/sec、openStream、path_traversal vuln/sec，
  以及 securitycipher/vulnerable-code-snippet 的控制台输入 SSRF 变体
- 语料驱动修复 1 个真实规则盲区：`new java.net.URL(url)` 全限定写法此前完全漏报，
  JAL-SSRF-001 正则增加可选 `java.net.` 前缀（SSRF-103 案例专门覆盖）
- 新登记 1 条能力边界（SSRF-104：协议前置校验在跨行 if 中，行级规则不可见），
  known-limitations 共 14 条
- 划分调整为 train 33 / validation 13 / holdout 13；评测指标更新：
  train+validation 门禁 P/R 100%（含边界口径 P 67.7%），holdout 门禁 100%（含边界 87.5%）
- 新增 2 项防回归测试（全限定 URL 规则、跨方法案例通过性），全套 118 项通过

### 语料库扩产与三分（Issue 路线图 v1.9）

- 匿名语料从 4 类 12 案例扩到 **15 类 46 案例**：新增命令注入、XXE、反序列化、SpEL、LDAP 注入、开放重定向、文件上传、敏感日志、明文口令、URL 令牌、弱哈希 11 个类别
- 新增 6 个真实脱敏样本（source: desensitized），expected.json 注明公开素材出处：CVE-2019-18394（Openfire SSRF）、山河 CTF 反序列化、fabric-sdk-java GHSA、AppSec Master SpEL 绕过、skf-labs LDAP
- 语料按 **train 25 / validation 11 / holdout 10** 三分（接近 60/20/20）；评测器新增 `--split` 参数，CI 默认只跑 train+validation，holdout 发布前才运行，且与默认评测案例集合互不相交（有测试保证）
- known-limitations 登记从 3 条扩到 13 条：每条边界写明 reason 与 plan，评测时原样公示，条目不复现时标记过期
- schema 新增 derived_from 字段；校验器校验 manifest 中每个案例的 split 合法性
- 语料扩产暴露并修复 4 个真实污点引擎缺陷：
  - `Map<String, String>` 泛型参数变量名解析错误导致 `@RequestBody` 参数丢失污点
  - 类型字符类中的逗号跨参数吞并，相邻参数被错标污点
  - `transferTo` 同时挂在路径与上传两个 sink 上双重命中
  - `.exchange(` 不限定调用者，任意业务方法被当成 HTTP 出站请求
- 新增 8 项防回归测试（泛型参数提取、参数不吞并、transferTo 单一 sink、exchange 限定、holdout 隔离等），全套 116 项通过

### 基线稳定性（Issue #6）

- 修复在命中行上方插入空行或注释后，原问题被同时报告为“新增”和“已修复”的问题
- builtin、secrets、semgrep、taint 四个扫描器的指纹不再包含行号，改为规则、归一化路径、归一化命中内容与文件内出现序号
- 命中表达式本身变化时仍会产生新身份；同一文件内的重复相同命中通过出现序号保持可区分
- 基线比对新增二次对齐：指纹不匹配时按规则、路径与归一化证据重试，旧基线、旧指纹方案和行号漂移都不会再产生噪声
- 二次对齐按文件只消费一次旧记录，避免多条相似命中被合并成一条
- 比对结果新增 `relocated` 字段，用于标注“仍存在但位置或指纹发生变化”的发现

### 机器可读摘要与 CI 集成

- 新增 `--json-summary`：把稳定结构的摘要输出到 stdout，人类可读日志改为输出到 stderr，CI 可直接解析 stdout
- 摘要契约 `jal-summary/1`：包含工具版本、目标、扫描器、按严重级别与扫描器的计数、基线变化（新增、已有、已修复、位置变化）、验证进展、报告路径、`fail_on` 与退出码
- 同一 `schema_version` 内只新增字段，不改名、不改类型、不删字段；扫描失败时 stdout 仍输出带 `status: error` 的最小摘要
- README 与 README_EN 新增退出码说明：`0` 完成、`1` 达到失败阈值、`2` 无法完成扫描，并说明 `--fail-on` 只统计基线新增发现
- 新增 `examples/github-actions/pr-audit.yml`：先扫目标分支生成基线，再扫 PR 分支比对，只在新增发现达到阈值时失败，并上传报告与在 PR 中留下结论
- 新增 8 项摘要契约与退出码回归测试，覆盖字段完整性、严重级别桶、stdout 只含 JSON、日志转 stderr、`fail_on` 退出码 1 与错误路径退出码 2
- 新增 9 项基线身份回归测试，覆盖插入无关行、表达式变更、重复命中与基线二次对齐

### 污点引擎精度（语料评测驱动）

- 语料评测器默认接入 builtin、taint、secrets 三个扫描器（可用 `--scanners` 调整），taint 规则不再显示为「未接入」
- 评测器输出三个口径的 Precision/F1：含已登记边界（真实准确率）、门禁口径（CI 判定用）、复核口径（带反证的误报视为可快速消解）
- 新增 `corpus/known-limitations.json` 登记机制：已知能力边界必须写明 reason 与 plan，每次评测原样公示；不再复现的条目会被标记为过期
- 修复污点引擎把字符串字面量里的标识符误当变量引用的问题（如 `"?nonce="` 中的 nonce），传播与终点匹配前先剥离字符串与注释
- 终点命中行含多个污点变量时改取行内最后出现的变量（更接近真正传入调用的实参）
- SSRF 污点发现新增「字面量目标主机」反证：URL 的协议与主机写在引号内、外部输入只在主机之后拼接时提示复核人
- 净化模型新增「文件名剥离」信号：`FilenameUtils.getName`、`Path.getFileName`、`new File(...).getName`、`StringUtils.substringAfterLast`
- 新增 8 项污点精度回归测试与 1 项已知边界过期检测测试，全套 104 项测试通过

## 1.9.0 - 2026-09-29

- 版本升级到 1.9.0，报告 JSON schema 升级到 1.4
- 为每条发现生成不含攻击载荷的验证任务卡，记录入口、鉴权、执行人、尝试次数、成功判据、进展、证据路径与结果
- 新增验证台账和实时统计，区分尚未开始、验证中、阻塞、已验证、确认漏洞与误报
- 新增八类常见误报归因，并将验证字段随 `review.json` 导出和导入
- 新增 `jal` 短命令；`jal .` 可直接扫描当前项目，同时保留 `java-audit scan` 兼容入口
- 新增 `s`、`d`、`r`、`b` 子命令别名及常用扫描参数的短选项；`jal . -O` 可在扫描完成后直接打开报告
- 新增匿名语料库试点：4 类规则、12 个 vulnerable/safe/edge Maven 案例及标准答案
- 新增零依赖语料结构与匿名化校验器，覆盖清单重复、路径越界、行号漂移和全目录敏感信息检查
- 新增语料评测器，按规则与案例统计 TP、FP、FN、TN、Precision、Recall 和 F1
- 危险案例必须命中全部已接入规则；安全案例的额外发现、严格行号错位均会导致评测失败
- 敏感信息检查只报告文件、行号和类型，不回显匹配内容
- CI 新增语料校验和严格评测，新增 5 项防“假绿”回归测试

## 1.8.0 - 2026-09-28

**发布候选：数据驱动分析、脱敏配置扫描与可复核范围**

- 新增 `audit/frameworks.py`，集中定义 Servlet、Spring MVC、上传、MQ、RPC、命令行等输入源，以及 SQL、命令、文件、SSRF、反序列化、表达式、LDAP、重定向和上传终点
- 新增 `audit/taint.py` 与 `taint` runner，追踪单个方法中的输入变量、赋值传播、净化反证与危险终点
- 修复新增模块错误使用双层相对导入导致整个 CLI 无法启动
- 修复多进程返回字典后 `Location` 未还原为对象的问题
- 修复 Spring 参数提取把 `throws Exception` 误当成污点变量的问题
- 修复传播分支提前跳过净化识别的问题
- 方法内文本传播明确标记为推测证据，不再冒充扫描器级已证明路径
- 新增 4 项污点分析回归测试；全套 69 项测试通过
- 新增 `secrets` 扫描器，覆盖常见 YAML、Properties、JSON 和环境配置中的字面量凭据；证据、指纹和报告均不保存原值
- 每条发现标注生产、测试、示例或生成代码范围，便于按真实风险复核
- `public_endpoints` 可声明业务上明确公开的接口，并在权限矩阵中保留配置证据
- `URI.create` 单独解析 URI 不再视为 SSRF；保留真实网络连接与 HTTP 客户端终点
- 新增明文密码比较、敏感对象日志、URL 查询参数令牌三类教学规则
- 配置文件参与扫描缓存摘要，配置变化不会误用旧结果
- 自定义 MVC 拦截器只有在实现中同时出现令牌读取、校验与拒绝请求证据时才标为“已证明”，仅凭名称匹配降为“推测”
- 全套 75 项测试通过

## 1.7.0 - 2026-09-28

**权限矩阵：支持 Spring MVC 自定义拦截器**

真实项目（Spring Boot + 自定义 JWT 拦截器）验证暴露了阶段 B 的盲区：解析器只认注解与
Spring Security / Shiro 配置链，对 `WebMvcConfigurer.addInterceptors()` 完全无感知，
导致 74 个端点全部被判为「权限缺失」。本次补齐：

- 新增 `addInterceptors` 解析：`addPathPatterns` → 需有效令牌，`excludePathPatterns` → 匿名
- 排除路径优先级高于包含路径（规则排序）
- 只有名称含鉴权语义的拦截器才生成权限规则；日志、耗时统计类拦截器不冒充鉴权证据
- 拦截器实现内发现角色判断时只补充说明，不擅自升级为具体角色要求（避免谎报）
- 类名按驼峰拆词后整词匹配：修复 `accessLogInterceptor` 的 "LogIn" 被当成 `login` 的误判

真实项目验证：权限覆盖率 0% → 89.2%（66/74 已证明），剩余 8 个端点确认无拦截器覆盖，
其中 `DELETE /admin/employee/{id}`、`GET /admin/employee/page`、`/check-password`、
`/status/{status}/{id}`、`/update-back` 为管理员端点且未纳入鉴权路径。

## 1.6.0 - 2026-09-28

**阶段 C-1：Git 增量审计**

新增 `audit/diff.py`，只分析变更文件与依赖闭包，并在报告中回答增量审计真正关心的问题：

- 三种模式
  - `--diff`：工作区未提交变更（含暂存、未暂存与未跟踪的新文件）
  - `--diff main`：与指定分支或提交的累计变更
  - `--commit HEAD~1`：单次提交引入的变更
- 依赖闭包：变更类的同包文件与 import 方一并作为上下文分析（Checkmarx 增量扫描思路的轻量实现），`--changed-only` 可关闭
- 行级归属：用 `git diff -U0` 解析新增/修改行区间，只把落在变更行上的发现标为「本次变更引入」
- 权限声明变化：回退变更文件重建旧快照，对比前后端点权限，识别
  - 权限声明被移除（原 role/permission/authenticated → 无声明，高风险）
  - 要求放宽、角色减少、新增无权限端点、端点移除
- 修复验证：结合 `--baseline` 判断基线命中是否真正消失；同规则同文件仍有命中时标记为「同规则残留」，不谎报已修复
- 同类新位置：本轮新增且同规则在存量中已出现过的发现单独标注
- 分析历史提交时自动按该提交状态重建源码快照，避免用当前工作树得出「没有问题」的错误结论

修复：

- 权限解析剥离 Java 注释：`// @PreAuthorize(...)` 不再被当成有效声明（否则「权限被删除」会被误报为「权限仍在」）
- `git ls-files` 不支持 `--relative`，未跟踪文件此前不会被计入变更

## 1.5.0 - 2026-09-28

**阶段 B：端点与权限矩阵**

新增 `audit/authz.py`，按蓝图要求输出「接口 × 方法 × 身份要求 × 角色 × 数据对象 × 危险操作 × 证据状态」矩阵：

- 端点识别：Spring MVC 类级 `@RequestMapping` 前缀 + 方法级 `@Get/Post/Put/Delete/Patch/RequestMapping`，
  自动还原 HTTP 方法与完整路由；类级声明不会被误判为端点
- 方法级授权（证据最强，标记为权限已证明）：
  `@PreAuthorize`/`@PostAuthorize`（hasRole、hasAnyRole、hasAuthority、hasPermission、permitAll、
  数据归属表达式 `#id == authentication.name`）、`@Secured`、`@RolesAllowed`、
  Shiro `@RequiresRoles`/`@RequiresPermissions`/`@RequiresAuthentication`/`@RequiresUser`/`@RequiresGuest`
- 配置级授权：`SecurityFilterChain`/`HttpSecurity` 的 `antMatchers|requestMatchers|mvcMatchers` 匹配链
  （permitAll / anonymous / authenticated / hasRole / hasAnyRole / hasAuthority / denyAll），
  以及 Shiro `filterChainDefinitionMap`（anon / authc / user / roles[] / perms[]）
- 证据优先级：方法级注解 > 配置链匹配 > 无匹配（如实标记「权限缺失」，不猜测为无控制）
- 发现与端点关联：每条发现归属到最近的端点，统一证据记录的 `authorization` 字段填充
  身份要求、角色/权限、表达式与证据来源
- HTML 报告新增「端点权限矩阵」章节（侧栏可跳转，含覆盖度指标与高危端点警示）；
  finding 卡片显示所属接口标签，并纳入搜索索引
- Markdown 报告新增「二、端点权限矩阵」章节，每条发现增加端点权限行
- playbook 阶段「入口与信任边界」纳入权限覆盖度证据与缺口
- 新增 `examples/spring-security-demo` 样例项目（覆盖 10 个端点与 7 条配置规则）
  与 `tests/test_authz.py`（14 个用例）

修复解析问题：类级 `@RequestMapping` 被误判为端点；授权注解窗口跨越上一个方法导致串味；
类级授权窗口扫到方法注解；`@PreAuthorize("hasRole('ADMIN')")` 外层双引号内单引号导致表达式截断；
`hasAnyRole` 在配置链中未被识别；覆盖率统计在发现挂载前计算导致高危端点数为 0。

## 1.4.0 - 2026-09-28

**多引擎证据层（阶段 A）：聚合成熟分析引擎，做证据编排而非重写扫描器**

- 新增统一证据记录模块 `audit/evidence.py`：每条发现归并为蓝图定义的统一证据模型——入口、来源、传播、净化/抑制（反证）、终点、权限、未解析步骤、引擎佐证；缺失项如实标注"未采集"，不发明证据
- SARIF 导入深度升级（CodeQL / Semgrep SARIF 均受益）：
  - 严重度支持 `security-severity`（CVSS 分值分档），优先于 level
  - CWE 提取支持规则 `relationships` 分类（CodeQL 标准写法）、`tags`（`external/cwe/cwe-079` 等）与 properties
  - `relatedLocations` 转为路径证据步骤；消息 `{0}` 占位符按 arguments 还原完整句子
  - `suppressions` 自动进入"可证伪检查"的反证面板（引擎报告抑制也是反证材料）
  - 规则 `helpUri` 存入 metadata，可回链官方说明
- Semgrep runner 支持 Pro 引擎 `dataflow_trace`：污点源 / 中间传播 / 污点终点转为引擎已证明路径步骤，metadata 标记 semgrep-pro / semgrep-oss
- HTML 报告：
  - 数据洞察新增第四张图表"证据结论分布"（已证明路径 / 推测路径 / 动态未解析 / 路径缺失）
  - 复核工作区新增"按引擎"分组视图
  - 每条发现新增"统一证据记录"折叠面板：入口、来源、传播步数、终点、净化/抑制反证、权限状态、引擎佐证一览
- Markdown 报告：每条发现输出统一证据摘要行（来源 → 传播步数 → 终点）、引擎佐证、净化/抑制反证
- `report.json` / `report.sarif` 自动携带完整 evidence_record，供下游工具消费

## 1.3.0 - 2026-09-27

**大型项目性能与可扩展性**

- BuiltinRunner 与 surface 收集器改为多进程并行：500 文件扫描从 14.5s 提速到约 1.5s（9.7×），使用 min(8, CPU 核心数) 进程，自动按文件数自适应 chunksize；30 文件以下走串行路径避免进程开销
- 给 `audit/__main__.py` 加 `if __name__ == "__main__":` 守卫，修复 Windows spawn 模式下子进程反复触发 main() 的死锁
- 新增进度反馈：TTY 环境自动开 stderr 进度，CI/管道默认静默；`--progress` / `--no-progress` 强制覆盖
- 新增 `--workers N`：手动指定并行进程数
- 新增 `--exclude "glob"` 与 `.java-audit.yml` 的 `exclude_paths`：大型项目可跳过 `src/test/*`、`generated/*` 等；默认已跳过 build/target/.git 等目录
- 新增外部规则加载器 `load_extra_rules`：支持 YAML / JSON 规则文件；`--rules path.yaml` 显式指定，或放进 `<project>/.java-audit/rules/` 目录会被自动加载；缺省字段使用保守默认值，错配规则不会让扫描崩溃
- `_simple_yaml` 升级支持顶层 list of mappings（外部规则文件常用格式）
- HTML 报告新增分组视图：工具栏加 view-mode 下拉（平铺列表 / 按严重度 / 按规则 / 按文件 / 按目录）；分组头粘性吸顶、可折叠；与现有 search/severity/review-filter 联动
- 示例新增 `examples/extra-rules.yaml`：演示敏感日志输出（CWE-532）与 CORS 允许所有来源（CWE-942）两条社区规则
- 修复 HTML 分组视图的 JavaScript 语法错误，并增加生成报告的 Node.js 语法回归检查
- 修复 Windows GBK 终端运行 `doctor` 时因 Unicode 状态符号崩溃
- 修复 `--workers` 未实际传入扫描器与攻击面收集器，以及并行进度过早显示完成
- 外部规则内容与排除路径现在进入缓存键，避免规则变化后错误复用旧结果
- 统一源码、构建元数据与 wheel 的 1.3.0 版本号

## 1.2.0 - 2026-09-27

**Java Audit Lab 1.2 — Evidence Driven Audit Playbook**

- 新增九阶段审计状态机（playbook）：项目画像、入口与信任边界、Source/Sink 建模、数据流扫描、成立条件验证、同类模式泛化、反证与绕过检查、人工结论、复测与报告；每阶段由可核验证据驱动，报告列出证据与缺口
- 新增攻击面收集器：Spring Controller 路由、@RequestParam/@PathVariable/@RequestBody、Filter/Interceptor/Security 配置、文件上传、MQ 消费者、定时任务、MyBatis ${}（注解与 Mapper XML）、JPA 原生查询
- 新增安全控制反证信号：ObjectInputFilter、XXE 加固配置、路径边界检查、参数化查询、方法级授权注解
- 引导式复核从三问升级为漏洞成立五问：入口与触达路径、身份与权限、数据流、已确认控制、证据缺口
- Source → Sink 路径按证据等级分类：已证明路径（扫描器数据流）/ 推测路径（保守候选）/ 缺失路径 / 无法解析（动态调用），工具不虚构中间步骤
- 新增同类模式泛化：每条线索自动列出同规则兄弟位置、同文件邻近写法与同 CWE 其他规则计数
- 新增 Markdown 审计报告（report.md）：执行摘要、攻击面画像、审计阶段完成度、五问、成立条件与反证、同类位置、全局加固建议、待人工确认项
- HTML 报告新增审计阶段完成度面板与攻击面画像
- 扫描前交互确认扫描范围（--yes 跳过）；报告不代为声明书面授权
- 反射/动态调用纳入反证缺口与路径未解析标记

## 1.1.0 - 2026-09-27

- 按 CWE、文件和邻近位置语义归并多扫描器发现，并保留交叉证据
- 增加公开可解释的复核优先级因素与排序
- 增加引导式复核问答、离线数据流图和组合查询
- 增加 `.java-audit.yml`、增量缓存和报告直接导入参数
- 修复 Windows SpotBugs GBK XML 解码与 Maven 源码路径还原
- 使用真实 Maven + SpotBugs 报告完成端到端解析和归并验证
- 增加可分发的 9 类规则回归基准
- 更新审计工作台、打印样式、复制代码位置和键盘导航

## 1.0.0 - 2026-09-27

- 统一解析 Semgrep、SpotBugs、Dependency-Check、CodeQL/SARIF 结果
- 支持 JSON、SARIF、离线 HTML 三种报告
- 增加基线新增/已有/已修复比较和 CI 退出阈值
- 增加可导入、导出的人工复核档案
- 增加支持证据与反证条件并列的“可证伪复核”工作流
- 增加可解释的局部数据流候选路径和 CodeQL 路径展示
- 增加可选的兼容 API AI 分层解释及凭据脱敏
- 增加 doctor、rules、Docker 和 GitHub Actions

# 语料评测报告

- 更新：2026-10-12（第二轮扩产：跨方法样本 + 开源脱敏样本，59 案例）
- 语料：**59 案例 = 15 类别，其中 11 个跨方法样本（Controller→Service→Mapper）**
- 真实来源：11 个 desensitized 案例注明了公开素材出处（CVE-2019-18394、山河 CTF、
  fabric-sdk-java GHSA、AppSec Master、skf-labs、JoyChou93/java-sec-code、
  securitycipher/vulnerable-code-snippet），其余为 synthetic
- 扫描器：builtin + taint + secrets（`--scanners` 可调）
- 划分：train 33 / validation 13 / holdout 13（接近 60/20/20）
  - `train`：规则开发可自由查看；edge 样本集中在 train
  - `validation`：调整规则时使用，vulnerable 与 safe 成对出现
  - `holdout`：**发布前才运行**（`--split holdout`），平时不针对它修改规则
  - CI 默认只跑 `train,validation`；holdout 与默认评测的案例集合互不相交（有测试保证）
- 跨方法说明：行级规则与方法边界无关，sink 行自包含即可命中（跨方法样本全部通过）；
  方法内污点引擎对跨方法传播天然不可见，这是引擎的结构性边界——跨方法污点传播
  是 Stage C 之后的路线图项，当前不作为被测指标

## 运行方式

```bash
python corpus/tools/validate_corpus.py
python corpus/tools/evaluate_corpus.py --strict-locations                 # train+validation（CI）
python corpus/tools/evaluate_corpus.py --strict-locations --split holdout # 发布前
python corpus/tools/evaluate_corpus.py --strict-locations --split all     # 全量
```

## 结果（2026-10-12，第二轮扩产后）

### train + validation（46 案例，CI 口径）

| 口径 | Precision | Recall | F1 | 用途 |
|---|---:|---:|---:|---|
| 含已登记边界 | 67.7% | 100% | 80.8% | **对外讲真实能力时用这个** |
| 门禁口径 | 100% | 100% | 100% | CI 回归判定（已登记的不算误报） |

TP 21 · FP 0 · FN 0 · TN 15 · 已登记边界 10 案例（按案例×规则对计 12 条）

### holdout（13 案例，发布前口径）

| 口径 | Precision | Recall | F1 |
|---|---:|---:|---:|
| 含已登记边界 | 87.5% | 100% | 93.3% |
| 门禁口径 | 100% | 100% | 100% |

TP 7 · FP 0 · FN 0 · TN 5 · 已登记边界 1 案例

## 怎么读这份数字（诚实声明）

1. **67.7% 才是 train+validation 上三个引擎合计的真实 Precision**（把 10 例已登记
   边界算回误报）。这些误报几乎全部来自「跨行才能确认的安全措施」：工厂加固配置、
   ObjectInputFilter、SimpleEvaluationContext、filterEncode、UUID 存储名、mask 脱敏、
   MD5 校验和用途、SSRF 协议前置校验。这是行级规则与逐行污点引擎的结构性边界，
   不是实现疏漏。
2. holdout 上的 87.5% 同理：唯一误报是 MD5 校验和（CRYPTO-003）。
3. **每条边界都必须登记 reason 与 plan**（known-limitations.json，当前 14 条），
   每次评测原样公示；条目不再复现会被标记过期，有专门测试防止清单腐烂。
4. 门禁口径的 100% 只说明「已登记边界之外没有新增误报、危险样本无漏报」，
   是回归门禁，**不是准确率声明**。
5. 59 案例仍不足以给出统计学上有意义的准确率区间；扩到 150+ 案例后才适合
   对外公布分规则的 Precision / Recall。

## 语料驱动修复的真实引擎缺陷（累计）

第三轮（跨方法与开源脱敏样本）暴露并修复 1 个：

| # | 缺陷 | 修复 |
|---|---|---|
| 9 | `new java.net.URL(url)` 全限定写法完全漏报（JAL-SSRF-001 只认 `new URL(`） | 正则增加可选 `java\.net\.` 前缀，SSRF-103 案例专门覆盖 |

第二轮扩产（34 个新案例）暴露并修复 4 个：

| # | 缺陷 | 修复 |
|---|---|---|
| 5 | `Map<String, String>` 泛型参数的变量名解析错误，`@RequestBody` 参数整体丢失污点 | 参数正则重写为「标识符+泛型+数组」结构 |
| 6 | 类型字符类中的逗号跨参数吞并，相邻的 `HttpServletResponse` 被错标污点 | 同上（泛型不再用扁平字符类） |
| 7 | `transferTo` 同时挂在 PATH-101 与 UPLOAD-101，同一行双重命中 | 从路径 sink 移除，仅保留上传 sink |
| 8 | `.exchange(` 不限定调用者，业务方法 `exchange(code)` 被当成 HTTP 出站请求 | sink 要求 restTemplate/webClient/httpClient/client 前缀 |

上一轮（12 案例试点）修复的 4 个：字符串字面量内的标识符误当变量引用、
同行多污点变量取错、URL 字面量主机无提示、FilenameUtils 净化无信号。

所有修复均有防回归测试（tests/test_taint_precision.py 共 9 项）。

## 类别覆盖

15 类：SQL 注入、SSRF、路径遍历、配置凭据、命令注入、XXE、Java 反序列化、
SpEL 表达式注入、LDAP 注入、开放重定向、文件上传、敏感日志、明文口令比较、
URL 参数令牌、弱哈希。覆盖全部 12 条 builtin 规则与 10 条 taint 规则中的 9 条
（JAL-SQL-102 MyBatis `${}` 插值暂无案例，待补）。

校验器会对整个 `corpus/` 执行匿名化卫生检查，命中时只输出文件、行号和类型，
绝不回显匹配内容。

## 下一步（按语料库规划）

1. 每类扩到 5 危险 + 5 安全/边界 → 约 150 案例
2. 跨方法样本已起步（11 个），继续扩到 ≥ 30 个
3. 权限矩阵样本 ≥ 20 个（authz 覆盖率作为被测指标；当前无 authz 规则，是前置依赖）
4. 真实项目脱敏样本（从已验证的真实 Spring Boot 项目提取最小调用链）
5. 补 MyBatis `${}` 案例

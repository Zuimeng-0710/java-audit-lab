# 语料评测报告

- 更新：2026-10-12（扩产至 46 案例并完成三分）
- 语料：**46 案例 = 15 类别 × (vulnerable / safe / edge) + 1 个真实脱敏变体**
- 真实来源：6 个 desensitized 案例注明了公开素材出处（CVE-2019-18394、山河 CTF、
  fabric-sdk-java GHSA、AppSec Master、skf-labs），其余为 synthetic
- 扫描器：builtin + taint + secrets（`--scanners` 可调）
- 划分：train 25 / validation 11 / holdout 10（接近 60/20/20）
  - `train`：规则开发可自由查看；edge 样本集中在 train
  - `validation`：调整规则时使用，vulnerable 与 safe 成对出现
  - `holdout`：**发布前才运行**（`--split holdout`），平时不针对它修改规则
  - CI 默认只跑 `train,validation`；holdout 与默认评测的案例集合互不相交（有测试保证）

## 运行方式

```bash
python corpus/tools/validate_corpus.py
python corpus/tools/evaluate_corpus.py --strict-locations                 # train+validation（CI）
python corpus/tools/evaluate_corpus.py --strict-locations --split holdout # 发布前
python corpus/tools/evaluate_corpus.py --strict-locations --split all     # 全量
```

## 结果（2026-10-12）

### train + validation（36 案例，CI 口径）

| 口径 | Precision | Recall | F1 | 用途 |
|---|---:|---:|---:|---|
| 含已登记边界 | 61.5% | 100% | 76.2% | **对外讲真实能力时用这个** |
| 门禁口径 | 100% | 100% | 100% | CI 回归判定（已登记的不算误报） |

TP 16 · FP 0 · FN 0 · TN 11 · 已登记边界 9 案例（按案例×规则对计 11 条）

### holdout（10 案例，发布前口径）

| 口径 | Precision | Recall | F1 |
|---|---:|---:|---:|
| 含已登记边界 | 83.3% | 100% | 90.9% |
| 门禁口径 | 100% | 100% | 100% |

TP 5 · FP 0 · FN 0 · TN 4 · 已登记边界 1 案例

## 怎么读这份数字（诚实声明）

1. **61.5% 才是 train+validation 上三个引擎合计的真实 Precision**（把 9 例已登记
   边界算回误报）。这些误报几乎全部来自「跨行才能确认的安全措施」：工厂加固配置、
   ObjectInputFilter、SimpleEvaluationContext、filterEncode、UUID 存储名、mask 脱敏、
   MD5 校验和用途。这是行级规则与逐行污点引擎的结构性边界，不是实现疏漏。
2. holdout 上的 83.3% 同理：唯一误报是 MD5 校验和（CRYPTO-003）。
3. **每条边界都必须登记 reason 与 plan**（known-limitations.json，当前 13 条），
   每次评测原样公示；条目不再复现会被标记过期，有专门测试防止清单腐烂。
4. 门禁口径的 100% 只说明「已登记边界之外没有新增误报、危险样本无漏报」，
   是回归门禁，**不是准确率声明**。
5. 46 案例仍不足以给出统计学上有意义的准确率区间；扩到 150+ 案例后才适合
   对外公布分规则的 Precision / Recall。

## 语料驱动修复的真实引擎缺陷（累计）

本轮扩产（34 个新案例）暴露并修复 4 个：

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
2. 跨方法样本（Controller → Service → Mapper）≥ 30 个
3. 权限矩阵样本 ≥ 20 个（authz 覆盖率作为被测指标）
4. 真实项目脱敏样本（从已验证的真实 Spring Boot 项目提取最小调用链）
5. 补 MyBatis `${}` 案例

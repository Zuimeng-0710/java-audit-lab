# Java Audit Lab 匿名测试语料库

一批不含真实业务信息、每个安全问题都有标准答案的 Java 小项目，
用来计算工具的误报率、漏报率和回归情况。

## 结构

- `manifest.json`：语料清单，每个案例标注所属 split
- `cases/<类别>/<CASE-ID>-<vulnerable|safe|edge>/`：每个案例是可独立扫描的 Maven 项目
- `schemas/case.schema.json`：expected.json 的结构定义；校验器使用零依赖的 schema 子集校验字段、类型、枚举和格式
- `tools/validate_corpus.py`：结构 / 标准答案 / 行号漂移 / 清单重复与越界 / split 合法性 / 全目录匿名化卫生检查
- `tools/evaluate_corpus.py`：逐案例扫描并统计 TP / FP / FN / TN，支持按 split 运行
- `known-limitations.json`：已登记能力边界（reason + plan），评测时原样公示

## 规模与划分

15 类，**59 案例**，其中 11 个跨方法样本（Controller → Service → Mapper 等）。

| 划分 | 数量 | 用途 |
|---|---:|---|
| `train` | 33 | 规则开发可自由查看；edge 样本集中在 train |
| `validation` | 13 | 调整规则时使用，vulnerable 与 safe 成对出现 |
| `holdout` | 13 | **发布前才运行**，平时不针对它修改规则 |

11 个案例标注 `source: desensitized` 并在 `derived_from` 注明公开素材出处
（CVE-2019-18394、山河 CTF、fabric-sdk-java GHSA、AppSec Master、skf-labs、
JoyChou93/java-sec-code、securitycipher/vulnerable-code-snippet）。

## 用法（仓库根目录）

    python corpus/tools/validate_corpus.py
    python corpus/tools/evaluate_corpus.py --strict-locations                  # train+validation（CI）
    python corpus/tools/evaluate_corpus.py --strict-locations --split holdout  # 发布前
    python corpus/tools/evaluate_corpus.py --strict-locations --split all      # 全量

`--strict-locations` 会让期望位置错位返回非零退出码。危险案例必须命中全部已接入的
`expected_rules`；安全案例出现任何扫描发现都会计为 FP（已登记边界除外，但每次公示）。

## 命名约定

- 案例目录：`<类别>/<规则前缀>-<编号>-<variant>`，variant 为
  `vulnerable`（漏洞成立）/ `safe`（正确修复）/ `edge`（易误报或依赖引擎能力边界）
- 包名统一 `lab.corpus.*`，域名统一 `example.com`，密钥只允许
  `CORPUS_FAKE_*` 形式的占位符。匿名化检查只报告位置和类型，不回显匹配值。

## 指标与诚实声明

见 [EVALUATION.md](EVALUATION.md)。要点：门禁口径（已登记边界不算误报）用于 CI 回归；
对外说明能力时必须引用「含已登记边界」口径。59 案例不足以给出统计学上有意义的
准确率区间，扩到 150+ 案例后才适合公布分规则指标。

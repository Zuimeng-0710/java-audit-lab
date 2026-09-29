# Java Audit Lab 匿名测试语料库

一批不含真实业务信息、每个安全问题都有标准答案的 Java 小项目，
用来计算工具的误报率、漏报率和回归情况。

## 结构

- `manifest.json`：语料清单（当前为 train 划分）
- `cases/<类别>/<CASE-ID>-<vulnerable|safe|edge>/`：每个案例是可独立扫描的 Maven 项目
- `schemas/case.schema.json`：expected.json 的结构定义；校验器使用零依赖的 schema 子集校验字段、类型、枚举和格式
- `tools/validate_corpus.py`：结构 / 标准答案 / 行号漂移 / 清单重复与越界 / 全目录匿名化卫生检查
- `tools/evaluate_corpus.py`：逐案例扫描并统计 TP / FP / FN / TN

## 用法（仓库根目录）

    python corpus/tools/validate_corpus.py
    python corpus/tools/evaluate_corpus.py

`--strict-locations` 会让期望位置错位返回非零退出码。危险案例必须命中全部已接入的
`expected_rules`；安全案例出现任何扫描发现都会计为 FP。

## 命名约定

- 案例目录：`<类别>/<规则前缀>-<编号>-<variant>`，variant 为
  `vulnerable`（漏洞成立）/ `safe`（正确修复）/ `edge`（易误报但不成立）
- 包名统一 `lab.corpus.*`，域名统一 `example.com`，密钥只允许
 `CORPUS_FAKE_*` 形式的占位符。匿名化检查只报告位置和类型，不回显匹配值。

## 已知边界

试点批次只接入了 builtin 扫描器；taint / semgrep / codeql 的接入
以及 train / validation / holdout 划分见仓库路线图。

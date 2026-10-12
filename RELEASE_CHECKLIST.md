# Java Audit Lab 2.0.1 发布清单

## 发布前

- [x] 源码、包元数据和命令行版本统一为 2.0.1
- [x] 默认排除虚拟环境、缓存与临时目录
- [x] 测试语料、示例代码与生产代码在报告中分开统计
- [x] 无基线时不再把首次发现显示为“基线新增”
- [x] 扫描器贡献按归并后主来源统计
- [x] 报告和中英文 README 明确语言覆盖边界
- [x] 仓库自身配置排除故意存在漏洞的语料、示例与基准样本
- [x] 120 项单元与回归测试全部通过
- [x] 内置规则基准通过（Precision / Recall 100%）
- [x] train + validation 严格评测通过
- [x] 独立 holdout 严格评测通过
- [x] HTML 内联 JavaScript 语法通过 Node.js 校验
- [x] 构建 wheel，并在隔离安装目录验证版本与内置基准
- [x] 自身仓库扫描为 0 条；完整语料扫描正确拆分为测试语料 50、示例代码 17、生产代码 0
- [x] 检查 Git 工作区，只包含计划发布的文件

## GitHub 发布

- [ ] 合并修复分支到 `main`
- [ ] 确认 `main` CI 全部通过
- [ ] 创建 `v2.0.1` 标签
- [ ] 创建 GitHub Release，并附 wheel、变更说明和校验值
- [ ] 确认 README Release 徽章显示 2.0.1
- [ ] 用发布后的标签验证 `examples/github-actions/pr-audit.yml`

发布附件建议包括：

- `java_audit_lab-2.0.1-py3-none-any.whl`
- `SHA256SUMS.txt`
- `CHANGELOG.md` 中的 2.0.1 说明

标签和 Release 必须在修复分支合并且 CI 通过后创建，避免发布内容与标签不一致。

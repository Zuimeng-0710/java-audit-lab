# UI 研究记录

Java Audit Lab 的界面参考了成熟安全产品公开文档中的工作流，未复制其品牌视觉或代码。

## 1.2 布局重构（侧边栏工作台）

- **左侧固定侧边栏**：品牌、项目摘要、区块导航（滚动监听高亮）、九阶段进度条、SVG 复核进度环、主题切换；≤1080px 折叠为顶部横条。
- **粘性顶部工具栏**：项目名 + 构建元信息徽章 + 导出按钮（JSON/SARIF/MD），毛玻璃背景。
- **审计阶段流水线**：九阶段从九宫格卡片改为编号流水线节点（序号圆点 + 状态徽章 + 顶部色条 + 可展开证据），一眼看清方法论执行到哪一步。
- **发现卡片**：左侧 4px 严重度色条（critical/high/medium/low 由 data-severity 驱动 CSS 变量），结论状态影响边框与透明度。
- **可证伪检查**双面板着色：支持假设（红底）/ 推翻假设（绿底）。
- 数字使用 tabular-nums；暗色模式全面重调对比度；保留打印样式（隐藏交互控件）。

## 提取的设计原则

- [Semgrep AppSec Platform](https://docs.semgrep.dev/for-developers/resolve-findings-through-app)：使用清楚的复核状态、备注和跨扫描延续，保留发现从开放到修复或忽略的生命周期。
- [GitHub Code Scanning](https://github.blog/changelog/2023-06-19-code-scanning-can-filter-alerts-by-language-and-file-path/)：查询框支持路径等限定条件，方便大型仓库聚焦负责区域。
- [SonarQube Security Hotspots](https://docs.sonarsource.com/sonarqube-server/9.8/user-guide/security-hotspots)：把详情组织为理解风险、判断是否成立和修复方法，并强调热点需要人工结论。
- [Snyk Priority Score](https://github.com/snyk/user-docs/blob/main/scan-fix-and-prevent/manage-risk/prioritize-issues-for-fixing/priority-score.md)：优先级综合多个因素。Java Audit Lab 采用公开、可检查的加分项，避免黑盒排序。

## 本项目的独立实现

- “可证伪复核”同时要求记录支持证据和反证。
- 引导问题的回答、最终结论、备注和判断信心一起导出。
- 每条优先级都显示严重度、置信度、路径证据、交叉验证和基线变化的具体分值。
- 数据流图在单文件 HTML 内离线渲染，不依赖远程脚本。
- 搜索支持 `cwe:`、`path:`、`scanner:` 和 `priority:` 组合条件。

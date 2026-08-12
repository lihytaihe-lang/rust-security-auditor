# Rust Security Auditor 开源前安全修复方案

- 日期：2026-08-11
- 唯一仓库：`<repo>`
- 分支：`improve/public-readiness`
- 受影响代码基线：`c8f79ad56e5153f8e76365d1a1651f26a672426b`
- 原始安全扫描 ID：`c123753e-a53c-488b-8e01-2f3baeffd843`
- 独立复核扫描 ID：`8f3f396c-8bc2-4b87-9baf-0e44a23b4598`
- 独立方案审查结论：`APPROVE_WITH_CHANGES`
- 当前发布门：`HOLD`
- 文档状态：已吸收独立复核意见；方案补充完成不代表 F1-F7 已修复
- 授权边界：本文档用于后续实施与验收，本身不授权提交、推送、发布、建 PR 或改动远端

## 1. 当前事实、目标和状态定义

Claude 已在 `improve/public-readiness` 分支完成一轮开源准备修改。此前记录的 86 项测试、类型检查、差异格式检查和 npm 打包预检通过，只能作为兼容性基线，不能证明当前版本已具备公开发布条件。独立复核确认 3 个安全问题和 4 个正确性/发布问题，并发现若干同源变体及发布边界缺口。

本轮选择的产品边界是：

> 本地优先、对目标仓库只读、以 `stdio` 提供服务、客户端中立的 Rust 安全审查 MCP server。

“客户端中立”表示核心实现不绑定某一 MCP 宿主，不表示已经兼容所有 MCP 客户端。“对目标仓库只读”表示工具不修改被审查的 Rust 源码，不应扩张成对进程所有文件系统行为的绝对承诺。宿主支持范围必须由逐宿主的端到端证据决定。

状态含义固定如下：

- `HOLD`：仍有未修复问题、未满足验收门槛或发布事实未核清，不得公开发布。
- `GO_FOR_OWNER_REVIEW`：本地技术、安全和制品门槛均有证据通过，只允许提交给所有者复核。
- `GO_FOR_PUBLIC_RELEASE`：只能由所有者在核对仓库、npm、版本、发布说明和凭据后明确给出；测试通过不会自动产生该状态。

## 2. 基线证据与 F1-F7

以下行号固定对应受影响基线 `c8f79ad56...`；实现开始前若 HEAD 漂移，必须重新核对并更新证据锚点。

### F1：非注释文本可以伪造安全语义（中等安全风险）

- 基线证据：`src/scanners/suppressions.ts:21` 接收未经词法分类的整行；`src/scanners/resultUtils.ts:171` 和 `src/scanners/acceptedRiskInventory.ts:49` 都直接调用；`src/scanners/unsafeScanner.ts:208` 也会把任意文本中的 `SAFETY:` 当成安全注释。
- 根因：安全语义由原始行文本匹配，而不是由统一的 Rust 注释视图提供。
- 已知攻击/失败路径：字符串、原始字符串、字节字符串或其他字面量中的 `rust-security-auditor: ignore ...` 可隐藏真实发现；伪造 `SAFETY:` 文字可影响 documented-unsafe 分类。
- 修复范围：`resultUtils`、`acceptedRiskInventory`、`unsafeScanner`，以及任何保留的 hosted/fixture 解析路径，都必须消费同一 comment-only 词法结果；不得只修一个调用者。
- 安全不变量：只有词法上确定属于真实 Rust 注释的指令或 `SAFETY:` 说明才能改变发现状态；字符串、字符、标识符、属性参数和其他字面量中的相同文字不得生效。

### F2：已知漏扫时仍可能返回 `safeToCommit: true`（低安全风险）

- 基线证据：`src/scanners/scannerUtils.ts:52-72` 只产生自然语言 warning；`src/mcp/tools.ts:196` 在没有覆盖状态的情况下生成决策；`src/mcp/reviewDecision.ts:115-123` 可在零发现时返回 `pass` 和 `safeToCommit: true`。
- 根因：扫描覆盖是非结构化旁路信息，没有进入最终决策模型。
- 已知失败路径：相关文件因过大、达到数量上限、符号链接、路径越界、读取失败或上下文提取失败而跳过时，最终决策仍可能显示可提交。
- 修复范围：所有扫描器、diff 文件筛选、抑制复读、Rust 上下文提取和 MCP 输出必须传递同一结构化覆盖状态。
- 安全不变量：只要当前 diff 中应检查的 Rust/Cargo 输入没有得到完整处理，决策必须为 `needs_attention`、`safeToCommit: false`，并返回具体路径、阶段和原因；正常删除的文件不应被误判为漏扫。

### F3：二次读取绕过资源和路径限制（低安全风险）

- 基线证据：`src/scanners/scannerUtils.ts:77-79` 的 `readTextLines` 无大小和路径边界；`src/scanners/resultUtils.ts:147-157` 为抑制逻辑再次读取文件并把错误降为空数组；`src/mcp/rustContext.ts:24-33`、`:45-54` 使用无界 `Promise.all` 完整读取 `.rs` 文件并吞掉错误。
- 根因：文件发现阶段有部分限制，但读取能力分散在多个调用者，缺少单一受控入口、每次调用缓存和总体资源预算。
- 已知失败路径：大文件、很多改动文件、扫描后替换的文件、符号链接或不可读文件可造成高内存、上下文静默缺失或扫描结果与抑制判断读取不同内容。
- 修复范围：项目扫描、专项扫描、diff 扫描、accepted-risk 清单、suppression 应用和 `rustContext` 都要使用同一安全读取能力；禁止新建旁路 `readFile`。
- 安全不变量：每个可影响结果的源文件只通过受控入口读取，统一执行根目录约束、符号链接策略、单文件上限、总文件/总字节预算、有界并发和明确错误语义；同一次工具调用优先复用同一内容快照。

### F4：工具归属依赖规则 ID 前缀（正确性问题）

- 基线证据：`src/mcp/tools.ts:52` 只定义 `RSA-DEP-`、`RSA-BUILD-` 前缀，`:149`、`:1977-1978` 据此前缀过滤；`src/scanners/rules.ts:377-405` 的 `RSA-CARGO-SOURCE-REPLACEMENT` 和 `RSA-CARGO-RUNNER` 因命名不同被遗漏。
- 根因：工具暴露面没有一等元数据，调用方误用规则命名约定推断归属。
- 修复范围：规则注册表、普通 findings、suppressed findings、Markdown/JSON 汇总和各 MCP 专项工具。
- 正确性不变量：每条规则显式声明独立的 `toolScopes`（或等价字段）；`dependency`、`unsafe`、`project` 等工具归属不能复用通用 `category`，因为一条规则的漏洞类别与工具暴露面不是同一维度。

### F5：跨行普通字符串会掩盖真实代码（正确性问题）

- 基线证据：`src/scanners/rustLexer.ts:136-140` 在每行末尾强制重置普通字符串状态。
- 根因：轻量词法器的状态机与 Rust 允许 cooked string 跨行的语义不一致。
- 后果：下一行真实代码可能仍处于错误的字面量遮罩中或被错误恢复，造成漏报/误报。
- 正确性不变量：cooked/raw/byte 字符串及受支持字面量必须按其合法终止规则跨行；词法输入畸形或状态不确定时，不能静默隐藏潜在代码，必须保守扫描并暴露限制。

### F6：宽松的 `test` token 匹配误降生产代码风险（正确性问题）

- 基线证据：`src/scanners/rustLexer.ts:203-210` 把 `cfg_attr` 中出现的任意 `test` token 视作 test-only。
- 根因：测试上下文判断基于 token 存在性，不基于能否证明该 item 只在测试构建出现。
- 已知失败路径：`#[cfg_attr(not(test), inline)]`、`#[cfg(any(test, feature = "prod"))]`、自定义属性路径或字符串中的 `test` 都可能错误降级生产发现。
- 正确性不变量：只有严格白名单能够证明 test-only，例如 `#[test]`、`#[cfg(test)]`，以及实现明确支持且逻辑上必然要求 `test` 的 `cfg(all(...))` 形式；`cfg_attr` 本身、`any(test, ...)` 和不确定表达式不得降级。属性作用域必须准确结束，不能污染后续 item。

### F7：公开制品隐私和 hosted 边界不完整（发布安全问题）

- 基线证据：`scripts/regenerate-examples.mjs` 在 JSON 序列化后替换路径，Windows 反斜杠已被转义；`package.json:8-13` 发布 hosted bin，`:27-29` 暴露 hosted scripts，`:58-67` 会打包整个 `dist/src/`；`src/mcp/index.ts:2-3` 公开导出 hosted API；`SECURITY.md:50` 与 `src/mcp/hostedServer.ts:18-30` 对默认 Host/Origin 行为的描述不一致。
- 根因：脱敏发生在错误的数据表示层；同时，“本地产品”定位只改了叙述，没有收敛实际 npm/API/脚本制品面。
- 已知后果：Windows、UNC、POSIX 或 JSON 转义路径可进入示例/tarball；即使只删除 hosted bin，hosted 代码仍会通过脚本、公共导出和 `dist/src/` 随 npm 发布。
- 发布不变量：敏感值必须在序列化前规范化，输出和实际 tarball 再执行独立泄漏检查；v0.1.x 的公开 npm/API/脚本面不得包含 hosted runtime。若实验代码保留在公开仓库，必须位于明确的非发布实验边界，不能由公开入口到达。

## 3. 选择的最小完整方案

本轮采用“共享局部控制”方案，不引入完整 Rust 编译器前端、独立守护进程或远程服务：

1. 一个共享的 Rust 轻量词法结果，同时提供 code-only、comment-only、字面量遮罩、test-only 证明和词法完整性状态。
2. 一个共享的安全读取入口和单次调用内容缓存，同时产出结构化 `scanCoverage`。
3. 一个独立于漏洞 `category` 的规则 `toolScopes` 元数据。
4. 一个覆盖源对象、生成文件和实际 npm tarball 的制品隐私门。
5. 从 v0.1.x 的 bin、scripts、公共 exports、构建输出和 tarball 中完整移除 hosted runtime；实验若保留则隔离到非发布区域。

这是当前最小且完整的修复：它封闭重复根因，但不扩张成架构重写。只有轻量词法器无法通过下述对抗用例，或维护成本已经接近 Rust parser 时，才重新评估 `rustc_lexer`/`syn` 等解析依赖；该升级不属于本轮默认方案。

## 4. 独立复核处置优先级

- `P0`：无。当前没有要求放弃方案或在设计层面阻断继续工作的缺陷。
- `P1`：阶段 B-F 的安全边界均为发布前必做，包括所有注释语义调用点、共享安全读取与 coverage 决策、独立 `toolScopes`、保守词法/test-only 规则、hosted 五个发布表面隔离，以及发布事实核对。任一项缺失都保持 `HOLD`。
- `P2`：提交可回滚性、真实 tarball 安装/MCP 握手、跨平台 CI、逐宿主证据矩阵和残余风险记录。它们不改变 F1-F7 的根因，但仍是 `GO_FOR_OWNER_REVIEW` 的必需交付质量门槛。

优先级用于安排实施和审查顺序，不表示 P2 可以在公开发布后补做。

## 5. 分阶段实施方案

### 阶段 A：刷新基线并保存修复前证据

- 实施会话开始时重新确认真实仓库、分支、HEAD 和工作区；保留本方案文件，不清理用户 WIP。
- 为 F1-F7 建立恶意用例和合法对照；在本地记录它们对受影响基线的修复前失败，不创建或提交“测试故意失败”的中间提交。
- 将已有 86 项测试记录为历史兼容性基线；重新运行后的实际数量和结果另行记录，不能沿用旧结论。
- 如果相关源码已漂移，先更新本方案的证据锚点和边界，再实施。

### 阶段 B：统一安全读取与扫描完整性（F2、F3）

- 定义结构化 `scanCoverage`，至少包含 `status`、仓库相对路径、输入类型、处理阶段、稳定原因码、是否与当前 diff 相关和可读说明。
- 原因码至少覆盖：过大、文件/总字节上限、符号链接、根目录外、读取/统计失败、发现截断、上下文失败；删除文件和非目标文件使用可区分的非错误状态。
- 安全读取入口统一执行：规范化与根目录约束、不跟随符号链接的明确策略、单文件上限、总文件/总字节预算、有界并发和每次调用缓存。阈值使用显式常量并可测试，不在调用者中复制。
- `ProjectScanner`、`UnsafeScanner`、`DependencyScanner`、`SourceRiskScanner`、suppression、accepted-risk 和 `rustContext` 全部迁移到该入口；扫描器不能把读取失败转换成空内容继续。
- diff 决策只对“应扫描的当前改动输入”fail closed：任何相关输入 incomplete 时返回 `needs_attention`、`safeToCommit: false`；完整扫描且无风险时才允许 `pass`。
- JSON 和 Markdown 同时输出覆盖摘要及逐文件原因；warning 仅作说明，不能代替决策字段。

### 阶段 C：统一注释和保守词法语义（F1、F5、F6）

- 扩展现有轻量词法器，输出真实注释片段/区间，保留行列映射；suppression 与 `SAFETY:` 只从 comment-only 结果读取。
- 覆盖 `resultUtils`、`acceptedRiskInventory`、`unsafeScanner` 和任何仍保留的实验解析路径，禁止继续对原始整行调用安全语义解析器。
- 正确处理嵌套块注释、行注释、cooked/raw/byte 字符串、字符与 lifetime 歧义，以及合法的跨行/转义终止规则；畸形输入返回明确词法完整性状态并按生产代码保守处理。
- 将 test-only 判断实现为严格白名单。`cfg_attr`、`cfg(any(test, ...))`、否定条件、未知宏/属性和仅含 `test` 文字的内容一律按生产代码处理。
- 词法 API、suppression、accepted-risk、SAFETY 和 test-only 测试随实现放在同一可审查提交内。

### 阶段 D：显式规则工具作用域（F4）

- 在规则元数据中新增 `toolScopes`（名称可调整），与现有 `category` 分离；每条规则显式声明适用工具。
- 所有 MCP 专项工具按 `toolScopes` 选择 findings；普通与 suppressed findings 必须从同一规则注册表取得作用域。
- 删除或禁止新的规则 ID 前缀过滤器；保留 ID 只作稳定标识和报告显示。
- 增加注册表契约测试：每条规则拥有合法 scope；DependencyScanner 产出的全部规则（包括 `RSA-CARGO-*`）在 dependency 工具可见；非 dependency 规则不会混入。

### 阶段 E：制品隐私与 hosted 隔离（F7）

- 在 JSON 序列化前递归处理对象中的字符串值；覆盖 POSIX、Windows 盘符、UNC、当前仓库路径和 JSON 转义后形态。
- 示例写盘后再次扫描；随后生成真实 `.tgz`，解包并扫描文件名、文本内容和符号链接目标。发现本地用户路径、内部审查材料或私有项目名时直接失败。
- 推荐的最小边界是从 v0.1.x 发布构建中移除 hosted runtime：删除 `rust-security-auditor-hosted-mcp` bin、`mcp:hosted`/`smoke:hosted` scripts、公共 `./mcp` hosted re-export，并确保 `hostedServer`、`hostedTools`、`hostedFixtures` 及对应 smoke runtime 不在 tarball。
- 若为历史研究保留 hosted 源码，只能移动到明确的实验目录并从生产 TypeScript 构建、package `files`、公共 exports 和支持文档中排除；不得仅改名或只删 bin。
- 同步修正 README、SECURITY、ROADMAP、CHANGELOG 中关于 hosted、本地行为、默认 origin 和支持状态的冲突叙述。

### 阶段 F：发布事实核对和客户端中立文档

- 先建立唯一发布事实：本地 `package.json` 为 `0.1.2`，但 `CHANGELOG.md:7` 声称已发布 npm，`ROADMAP.md:5` 声称正在 npm 分发，与本方案“暂不发布”的措辞冲突。由所有者或官方 npm/GitHub 证据核清已发布版本、tag 和制品后再改文档。
- 若 `0.1.2` 已公开，不能把修复写成对既有制品的追溯完成；应由所有者决定新 patch 版本、公告和升级路径。任何查询、撤回、发布或 tag 操作仍是 owner gate。
- 顶层定位统一为 `Local-first Rust security review MCP server over stdio`，并明确“不会修改目标源码”“不是完整漏洞证明或 RustSec/CVE 数据库”。
- README 先给通用 stdio 启动模型，再给宿主专用配置；配置示例必须匹配各宿主官方字段、命令、参数、工作目录和环境变量模型。
- 兼容矩阵只使用三种状态：`端到端已验证`、`仅按官方文档给出配置参考`、`未验证`。只有第一种可以写“支持”；记录客户端版本、OS、配置、日期和 `initialize/tools/list/tools/call` 证据。
- Claude Code、Claude Desktop、Codex、Cursor、VS Code/Copilot 分别验收，不能用一个通用 JSON 模板替代宿主验证；“其他 MCP 客户端”只能描述协议前提，不作支持承诺。
- v0.1.x 明确不包含 ChatGPT App、远程 MCP、托管扫描、私有代码上传、SaaS、账号、遥测或市场提交。

## 6. 建议提交边界

测试与对应修复放在同一提交，避免产生可合并但故意失败的测试提交。推荐边界：

1. `fix(scanner): bound source reads and fail closed on incomplete coverage`（F2、F3 及对应测试）
2. `fix(lexer): trust only real comments and classify Rust source conservatively`（F1、F5、F6 及对应测试）
3. `fix(rules): select MCP findings by explicit tool scopes`（F4 及对应测试）
4. `fix(release): prevent cross-platform path leakage from artifacts`（F7 脱敏与制品测试）
5. `build(release): exclude hosted runtime from the local stdio package`（F7 hosted 完整隔离与 package 测试）
6. `docs: reconcile release facts and evidence-based MCP compatibility`（事实核对后才能提交）

F2/F3 共享一个读取与覆盖根因，不应拆开；F1/F5/F6 共享词法 API，不应制造临时双实现。若阶段内改动过大，可以按“先引入不改变行为的共享 API，再迁移调用者并启用策略”拆分，但每个提交都必须自洽、测试通过且可独立回滚。

在用户明确授权前，不创建上述提交；实施工作可以先保持为可审查的工作区差异。

## 7. 必需测试矩阵

### 7.1 词法和安全语义

- 真实行/块/嵌套块注释中的 suppression 与 `SAFETY:` 生效；同样文字位于 cooked/raw/byte 字符串、字符、属性参数和标识符时不生效。
- 活跃、过期、无效、全局和规则专用 suppression 在扫描结果与 accepted-risk 清单中语义一致。
- cooked string 跨行、反斜杠转义、raw string 多种 `#`、字节字符串、字符与 lifetime 不造成后续真实 `unsafe` 漏报。
- `#[test]`、`#[cfg(test)]` 和严格支持的 `cfg(all(...))` 可降级；`cfg_attr`、`any(test, prod)`、`not(test)`、自定义属性和作用域结束后的 item 不降级。
- 未闭合/畸形注释或字面量触发保守行为和明确限制，不产生静默“安全”。

### 7.2 读取、覆盖和决策

- 单文件过大、总文件/总字节超限、不可读、符号链接、根外路径、上下文读取失败和发现截断都产生稳定 coverage 原因码。
- 相关 diff 输入 incomplete 时，无论 findings 是否为空，都返回 `needs_attention`、`safeToCommit: false`；JSON、Markdown 和 summary 一致。
- 删除文件、非 Rust/Cargo 文件和完整小型项目不被错误阻断。
- 大量改动文件时并发受限，单次调用内容缓存避免 suppression/context 重读；测试至少验证并发上限和读取次数，不以主观内存观察代替断言。
- 改名、空 diff、staged/unstaged/both 模式及 Cargo.toml、Cargo.lock、`.cargo/config{,.toml}`、`build.rs` 都有覆盖。

### 7.3 规则作用域

- `rust_audit_dependencies` 包含 `RSA-CARGO-SOURCE-REPLACEMENT`、`RSA-CARGO-RUNNER` 和 DependencyScanner 的其余规则。
- 普通与 suppressed findings 使用相同 scope；每条规则的 scope 有注册表契约测试。
- unsafe、dependency、project 工具结果互不因规则 ID 命名变化而漂移。

### 7.4 制品和 MCP 运行边界

- POSIX、Windows 盘符、UNC、反斜杠与 JSON 转义路径均有生成器单元测试和实际 tarball 泄漏测试。
- 实际 tarball 中不存在 hosted bin、hosted runtime、hosted public export、内部方案或私有名称；允许的文件清单与 `package.json` bin/exports 一致。
- 将 `.tgz` 安装到全新临时目录后，从 `node_modules/.bin/` 的真实符号链接启动主 bin，而不是直接运行仓库内 `dist`。
- 通过已安装 bin 的真实 stdio 边界完成 `initialize`、`notifications/initialized`、`tools/list` 和至少一次针对临时 fixture 的 `tools/call`；stdout 只含合法 JSON-RPC 帧，日志进入 stderr。
- CI 至少在声明支持的 Node 版本和 Linux/macOS/Windows 上执行与平台相关的核心路径、安装和隐私检查；不能只运行 `npm pack --dry-run`。

## 8. 发布验收门槛

以下必须全部满足，才能从 `HOLD` 变为 `GO_FOR_OWNER_REVIEW`：

- F1-F7 的原始复现和本方案列出的同源变体全部通过，且每项都有恶意用例与合法对照。
- 新旧完整测试、类型检查、构建、`git diff --check` 和适用 CI 矩阵通过；记录实际命令、测试数、环境和输出摘要。
- 结构化覆盖状态贯穿所有工具；任何相关输入 incomplete 的端到端接口证明会 fail closed。
- 实际 npm tarball 完成内容清单、泄漏扫描、临时安装、bin 符号链接启动和真实 stdio MCP 握手。
- hosted runtime 在 bin、scripts、exports、构建输出和 tarball 五个表面均不可达；公开文档与实际制品一致。
- 公开 README 中的每个“支持”宿主都有逐宿主证据；官方文档适配但未实测者明确降级为配置参考。
- CHANGELOG、ROADMAP、README、SECURITY、package 版本、Git tag/release 和 npm 状态已由所有者核成同一事实；未核实不得声称“尚未发布”或“已发布”。
- 对修复差异执行针对性安全复核，确认没有开放的 P0/P1 修复缺口；扫描器绿灯不能替代手工检查原攻击路径和制品。
- 最终差异只包含授权范围内的源代码、测试、发布脚本和文档；本方案及其他用户 WIP 未被覆盖或清理。

即使以上全部满足，结论仍只是 `GO_FOR_OWNER_REVIEW`。公开 GitHub、npm 发布、tag、release、公告、市场提交和任何远端状态修改均需要所有者单独授权并执行最终确认。

## 9. 回滚、残余风险与非目标

### 回滚要求

- 每个提交可独立回滚；共享 API 迁移不得留下部分调用者走旧旁路。
- 若新读取预算对正常仓库产生阻断，优先调整有证据支持的显式阈值，不恢复 warning-only 或无界读取。
- 若轻量词法器出现无法保守处理的合法 Rust 语法，保持 `needs_attention` 并回到设计评审，不以静默漏报换兼容性。
- hosted 隔离回滚不得重新进入 v0.1.x 发布面；恢复 hosted 产品线必须另立威胁模型、隐私方案和发布计划。

### 已知残余风险

- 本项目仍是启发式静态审查，不执行完整 Rust 语义、数据流、污点或依赖漏洞数据库分析。
- 文件在扫描期间被并发修改仍可能造成时序差异；单次调用缓存降低内部不一致，但不等于不可变仓库快照。必要时应在输出中披露该限制。
- MCP SDK 协议兼容不自动等于每个宿主的产品兼容；宿主升级后需要重新验证。

### 非目标

- 不开发 ChatGPT App、市场提交包、远程 MCP、托管扫描或私有代码上传。
- 不把轻量扫描器包装成形式化验证、完整漏洞证明、RustSec/CVE 查询或发布批准器。
- 不在本轮加入无关规则、UI、遥测、账号、付费、云端能力或客户端代码分叉。
- 不为追求“兼容所有 MCP 客户端”做未经证据支持的承诺。

## 10. 实施前检查单

- [ ] 所有者明确授权“实施代码修复”，而不只是审查/补充方案。
- [ ] 再次确认真实仓库、分支、HEAD、工作区和本方案文件状态。
- [ ] 核对是否存在影响 F1-F7 的新改动并刷新证据锚点。
- [ ] 明确发布事实核对由谁完成；外部查询、tag、发布和公告仍为 owner gate。
- [ ] 按阶段 B → C → D → E → F 实施，每阶段完成聚焦测试和手工攻击路径验证后再继续。
- [ ] 最终只在所有验收证据齐全后申请 `GO_FOR_OWNER_REVIEW`。

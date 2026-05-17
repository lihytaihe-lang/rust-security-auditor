# Rust Security Auditor

Rust Security Auditor is a local TypeScript kernel and MCP server for low-noise Rust security review in Codex and other MCP clients. It is intentionally scoped to Rust security findings: unsafe/FFI, dependency and supply-chain risk, command execution, filesystem/path handling, input boundaries, secrets, panic/DoS, and manual-review items.

This repository is currently at Phase 7. It provides a local scanner kernel, a PR-review-style changed-line-aware stdio MCP server, accepted-risk suppression workflow UX, and a Codex Skill / Plugin usage layer for natural `@Rust Security Auditor` calls inside a local Codex project context. It does not provide a ChatGPT App, web UI, SaaS upload flow, uploaded code package scanning, or generic code review.

## Phase 7 Contents

- TypeScript project configuration
- Stable Finding schema and validation helpers
- Markdown and JSON report renderers
- Shell command wrapper for future `git`, `cargo`, and `rg` calls
- Unified git diff parser for file paths, hunk headers, added lines, removed lines, and context ranges
- Scanner interface types
- `ProjectScanner` for Cargo manifests, lockfiles, workspace manifests, build scripts, and Rust source discovery
- `UnsafeScanner` for deterministic unsafe and FFI review targets
- `DependencyScanner` for deterministic Cargo/build.rs supply-chain risk clues
- `scanRustProject` convenience entrypoint that returns `Finding[]`
- Centralized rule metadata with stable `ruleId` values
- Finding deduplication, severity/confidence sorting, and accepted-risk inline suppression
- Fixtures for vulnerable, safe, documented unsafe, dependency-risk, and suppressed projects
- Local MCP server in `src/mcp/` using the official Model Context Protocol TypeScript SDK
- MCP tools for full project audit, unsafe/FFI audit, dependency/supply-chain audit, and current diff review
- Changed-line-aware `rust_review_current_diff` output with `introduced_by_diff`, `near_changed_lines`, and `pre_existing_in_changed_file` metadata
- PR-review-style `rust_review_current_diff` output with `reviewDecision`, summary metrics, finding actionability, accepted/suppressed risk reporting, and Codex-ready `suggestedFixPrompt` values
- Structured suppression metadata for reason, owner, ticket, until, expired status, invalid status, and raw directive comments
- Suppression summary counts for active, expired, and invalid suppression directives
- Local MCP debug caller for invoking tools without an MCP client
- Codex/MCP client stdio configuration documentation
- Example MCP client config and sanitized MCP validation outputs under `examples/`
- Codex Skill documentation under `skills/rust-security-auditor/`
- Codex Plugin / MCP usage example at `examples/codex-plugin-config.json`
- MCP client smoke tests for tool listing and tool calls
- Build, typecheck, lint, and test scripts

## Current Status

- Scanner kernel ready.
- MCP server ready.
- Codex usage layer ready.
- PR-review-style current diff review ready.
- Accepted-risk suppression workflow ready.
- ChatGPT App, SaaS, uploaded code packages, and Deep Audit / release-gate workflows are not implemented here.

## Install

```bash
npm install
```

## Build And Test

```bash
npm run build
npm test
```

Optional checks:

```bash
npm run typecheck
npm run lint
```

## MCP Server

The MCP server is a local development tool that communicates over stdio. It is intended to run on the same machine as Codex or another MCP client so the client can pass local project paths. Do not expose this server directly as a public network service.

Start the server:

```bash
npm run mcp
```

## Use with Codex / MCP Client

Configure Codex or another local MCP client to launch this server as a stdio server from the repository root. Prefer this command shape:

```bash
npm --silent run mcp
```

The `--silent` flag matters because MCP stdio reserves stdout for JSON-RPC protocol messages. Normal npm lifecycle banners such as `> rust-security-auditor@... mcp` can pollute stdout before the MCP server sends protocol frames, which may cause clients to fail during initialization. Diagnostics and tool errors should go to structured MCP responses or stderr, not stdout.

Local stdio server configuration example:

```json
{
  "mcpServers": {
    "rust-security-auditor": {
      "command": "npm",
      "args": ["--silent", "run", "mcp"],
      "cwd": "/path/to/rust-security-auditor"
    }
  }
}
```

Use an absolute `cwd` for your local checkout. A fuller MCP client reference config with tool descriptions and troubleshooting notes lives at `examples/mcp-client-config.json`. A Codex Skill / Plugin oriented example lives at `examples/codex-plugin-config.json`.

The Codex Skill documentation lives in:

- `skills/rust-security-auditor/SKILL.md`
- `skills/rust-security-auditor/examples.md`
- `skills/rust-security-auditor/troubleshooting.md`

Recommended Codex entry points:

| Codex request | MCP tool |
| --- | --- |
| `@Rust Security Auditor review current diff` | `rust_review_current_diff` |
| `@Rust Security Auditor check this Rust project before commit` | `rust_review_current_diff` |
| `@Rust Security Auditor audit unsafe` | `rust_audit_unsafe` |
| `@Rust Security Auditor audit dependencies` | `rust_audit_dependencies` |
| `@Rust Security Auditor audit project` | `rust_audit_project` |
| `@Rust Security Auditor run release security audit` | `rust_audit_project` |
| `@Rust Security Auditor check this Rust project before release` | `rust_audit_project` |

Codex should summarize tool results as security review output with an overall risk conclusion, blocking issues, recommended fixes, manual-review items, and false-positive or suppression notes. It should not output generic style advice, claim a complete formal audit, or modify code unless the user explicitly asks for fixes.

The server uses `@modelcontextprotocol/sdk` and registers these tools:

- `rust_audit_project`: use before a release or for a full-project Rust security health check.
- `rust_audit_unsafe`: use for specialized unsafe / FFI review, including unsafe blocks, raw-memory primitives, extern boundaries, and unsafe Send/Sync impls.
- `rust_audit_dependencies`: use for Cargo dependency and supply-chain review.
- `rust_review_current_diff`: use before commit, before PR, after Codex generated code, or after touching unsafe/dependencies/build.rs to review findings introduced by or near current Git diff hunks. It returns `reviewDecision`, `suppressionSummary`, and Codex-ready `suggestedFixPrompt` values for displayed findings. It does not automatically modify code or add suppressions.

All tools return structured content with this shape:

```json
{
  "tool": "rust_audit_project",
  "projectPath": "/path/to/project",
  "summary": {
    "findingCount": 1,
    "suppressedCount": 0,
    "severityCounts": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "categoryCounts": {
      "unsafe": 0,
      "ffi": 0,
      "dependency": 0,
      "supply_chain": 0,
      "command_execution": 1,
      "filesystem": 0,
      "input_boundary": 0,
      "concurrency": 0,
      "secret": 0,
      "panic_dos": 0,
      "manual_review": 0
    },
    "riskLevel": "high_risk"
  },
  "findings": [],
  "reportMarkdown": "# Rust Project Security Audit\n..."
}
```

When `outputFormat` is `"json"` or omitted, the MCP text content is JSON and `structuredContent` contains the same object. When `outputFormat` is `"markdown"`, the response still includes structured content and also adds `reportMarkdown` for direct display in Codex.

### Tool Inputs

`rust_audit_project`

```json
{
  "projectPath": "/path/to/rust/project",
  "outputFormat": "markdown",
  "includeSuppressed": false
}
```

`rust_audit_unsafe`

```json
{
  "projectPath": "/path/to/rust/project",
  "includeDocumentedUnsafe": true,
  "outputFormat": "json"
}
```

`rust_audit_dependencies`

```json
{
  "projectPath": "/path/to/rust/project",
  "outputFormat": "markdown"
}
```

`rust_review_current_diff`

```json
{
  "projectPath": "/path/to/rust/project",
  "baseRef": "main",
  "headRef": "HEAD",
  "staged": false,
  "includePreExisting": false,
  "outputFormat": "json"
}
```

If `staged` is `true`, `rust_review_current_diff` reviews `git diff --cached`. If both `baseRef` and `headRef` are provided, it reviews `git diff baseRef..headRef`. Otherwise it reviews the unstaged working tree diff from `git diff`.

Current diff review parses unified diff hunks, scans only files touched by the selected diff, and enriches displayed findings with:

- `introduced_by_diff`: `finding.startLine` is one of the added lines in the diff.
- `near_changed_lines`: the finding is not on an added line, but is within the default 5-line window around an added line.
- `pre_existing_in_changed_file`: the finding is in a changed file but outside the changed-line window.

By default, `rust_review_current_diff` returns only `introduced_by_diff` and `near_changed_lines` findings. Set `includePreExisting: true` to include historical findings from changed files. This is still heuristic scanner output; it is not full data-flow, control-flow, or taint analysis.

Current diff review uses a PR-review decision model:

- `block`: a commit/PR blocker. Introduced `critical` or `high` findings with `medium` or `high` confidence block. High-confidence `high` or `critical` findings near changed lines can also block because the diff may have changed the surrounding invariant.
- `needs_attention`: not a hard blocker, but requires human review before commit. Introduced `medium` findings, nearby `medium` findings, and low-confidence findings land here.
- `pass`: no blocking or manual-review findings were reported. Low or informational findings with non-low confidence are treated as non-blocking notes.

Low-confidence findings must not be described as confirmed vulnerabilities. They are review targets: Codex should help inspect the invariant, but the user should confirm the context before treating them as real bugs. When the tool returns `recommendedAction: "suppress_if_accepted"`, it also returns a `suppressionSuggestion`. That suggestion is for a user-approved accepted-risk record, not an instruction to silently change code. High-confidence blockers should be fixed before commit instead of suppressed by default.

For `rust_review_current_diff`, structured output keeps the compatible top-level `findings` array and adds diff-specific fields:

```json
{
  "reviewDecision": {
    "status": "needs_attention",
    "reason": "No hard blockers were found, but the diff has medium-severity, nearby, or low-confidence findings that need human review before commit.",
    "blockingFindingIds": [],
    "needsManualReviewFindingIds": ["RSA-UNSAFE-BLOCK-91AA22BF"],
    "safeToCommit": false
  },
  "summary": {
    "introducedFindingCount": 1,
    "nearChangedFindingCount": 0,
    "preExistingFindingCount": 2,
    "blockingCount": 0,
    "manualReviewCount": 1,
    "nonBlockingCount": 0
  },
  "suppressionSummary": {
    "suppressedCount": 1,
    "expiredSuppressionCount": 0,
    "invalidSuppressionCount": 0
  },
  "diffAffectedFiles": ["src/lib.rs"],
  "diff": {
    "files": [
      {
        "filePath": "src/lib.rs",
        "hunks": [
          {
            "oldStart": 10,
            "oldLines": 6,
            "newStart": 10,
            "newLines": 8,
            "addedLines": [12, 13],
            "removedLines": [11],
            "contextLines": [10, 14],
            "contextRange": [10, 17]
          }
        ]
      }
    ]
  },
  "enrichedFindings": [
    {
      "finding": {
        "ruleId": "RSA-UNSAFE-BLOCK",
        "file": "src/lib.rs",
        "startLine": 12
      },
      "diffContext": {
        "relation": "introduced_by_diff",
        "nearestChangedLine": 12,
        "distance": 0
      },
      "actionability": {
        "recommendedAction": "suppress_if_accepted",
        "canCodexFix": false,
        "suggestedFixPrompt": "If this risk is intentional, add a rustsec-auditor suppression comment for RSA-UNSAFE-BLOCK at src/lib.rs:12 with a clear reason, owner, and ticket.",
        "suppressionSuggestion": "// rustsec-auditor: ignore RSA-UNSAFE-BLOCK -- explain why this risk is acceptable"
      }
    }
  ]
}
```

When `outputFormat: "markdown"` is requested, current diff review renders as a PR review with `Decision`, `Summary`, `Blocking Issues`, `Needs Manual Review`, `Non-blocking Notes`, `Accepted / Suppressed Risks`, `Suggested Codex Fix Prompts`, and `Limitations` sections instead of a plain findings dump.

### Local Tool Debugging

You can call MCP tool handlers without starting an MCP client:

```bash
npm run mcp:call -- rust_audit_project --projectPath test/fixtures/vulnerable-rust-project --outputFormat markdown
npm run mcp:call -- rust_audit_unsafe --projectPath test/fixtures/vulnerable-rust-project
npm run mcp:call -- rust_audit_dependencies --projectPath test/fixtures/dependency-risk
npm run mcp:call -- rust_review_current_diff --projectPath /path/to/rust/project
npm run mcp:call -- rust_review_current_diff --projectPath /path/to/rust/project --staged true
npm run mcp:call -- rust_review_current_diff --projectPath /path/to/rust/project --includePreExisting true
```

These commands print the structured tool output as JSON.

### Codex Usage

Use `rust_review_current_diff` while reviewing a local branch before commit or PR. Use `rust_audit_unsafe` when touching FFI, pointer, initialization, Send/Sync, or raw-memory code. Use `rust_audit_dependencies` when Cargo manifests, lockfiles, build scripts, proc macros, git/path dependencies, or build dependencies change. Use `rust_audit_project` before release to get a full local project security pass.

The Skill maps natural `@Rust Security Auditor ...` requests to these tools and defines how Codex should interpret severity, confidence, blocking release guidance, manual-review items, and suppressions. This project intentionally does not upload code packages, does not run as SaaS, and is prioritized as a local Codex/MCP project-context tool.

## Public Modules

- `src/reports/schemas.ts`: Finding schema, release gate types, validation, and summary helpers
- `src/reports/markdownReport.ts`: Markdown report renderer
- `src/reports/jsonReport.ts`: JSON report renderer
- `src/scanners/projectScanner.ts`: Rust project, workspace, Cargo, build.rs, and Rust source discovery
- `src/scanners/unsafeScanner.ts`: unsafe, FFI, and raw memory primitive scanner
- `src/scanners/dependencyScanner.ts`: Cargo/build.rs dependency risk clue scanner
- `src/scanners/rustProjectScanner.ts`: combined Rust project scan entrypoint
- `src/scanners/rules.ts`: scanner rule metadata
- `src/git/diffParser.ts`: unified git diff parser for hunks and changed line numbers
- `src/utils/shell.ts`: shell command execution wrapper with timeout and bounded output
- `src/scanners/types.ts`: scanner interfaces
- `src/mcp/server.ts`: local stdio MCP server
- `src/mcp/tools.ts`: testable MCP tool handlers backed by the scanner kernel
- `src/mcp/debug.ts`: local tool debug entrypoint

## Scan A Rust Project

The Phase 2.5 scanners are deterministic and do not call an LLM.

```ts
import {
  renderJsonReport,
  renderMarkdownReport,
  scanRustProject,
  toRustAuditReportInput
} from "rust-security-auditor";

const scan = await scanRustProject({
  workspacePath: "/path/to/rust/project"
});

const reportInput = toRustAuditReportInput(scan);

console.log(renderJsonReport(reportInput));
console.log(renderMarkdownReport(reportInput));
```

Local development example:

```bash
npm run build
node --input-type=module -e "import { scanRustProject, toRustAuditReportInput, renderJsonReport } from './dist/src/index.js'; const scan = await scanRustProject({ workspacePath: 'test/fixtures/vulnerable-rust-project' }); console.log(renderJsonReport(toRustAuditReportInput(scan)));"
```

## Current Rules

Findings are deduplicated by `file + startLine + ruleId` and sorted by severity, confidence, file, then line. Severity order is `critical > high > medium > low > info`; confidence order is `high > medium > low`.

Project discovery:

- Finds `Cargo.toml`
- Finds `Cargo.lock`
- Detects `[workspace]` manifests and simple `members = [...]`
- Finds `build.rs`
- Finds `.rs` source files

Unsafe and FFI scanner:

- `RSA-UNSAFE-BLOCK`: `unsafe { ... }`; checks nearby `SAFETY:` / `Safety:` comments and lowers confidence to medium when present.
- `RSA-UNSAFE-FN`: `unsafe fn`; caller must uphold a documented safety contract.
- `RSA-UNSAFE-IMPL-SEND`: `unsafe impl Send`; cross-thread transfer invariant needs review.
- `RSA-UNSAFE-IMPL-SYNC`: `unsafe impl Sync`; shared-reference thread-safety invariant needs review.
- `RSA-FFI-EXTERN-C`: `extern "C"` ABI boundary; FFI type, pointer, ownership, and unwind behavior need review.
- `RSA-UNSAFE-TRANSMUTE`: `transmute(...)`; layout and validity assumptions need review.
- `RSA-UNSAFE-MAYBEUNINIT`: `MaybeUninit`; initialization invariant needs review.
- `RSA-UNSAFE-FROM-RAW-PARTS`: `from_raw_parts(...)`; pointer, lifetime, and length assumptions need review.
- `RSA-UNSAFE-SET-LEN`: `set_len(...)`; initialized length and capacity assumptions need review.
- `RSA-UNSAFE-BOX-FROM-RAW`: `Box::from_raw(...)`; ownership and allocator assumptions need review.

Dependency and build scanner:

- `RSA-DEP-GIT`: `Cargo.toml` git dependencies via `git =`; repository trust and revision pinning need review.
- `RSA-DEP-PATH`: `Cargo.toml` path dependencies via `path =`; local filesystem trust boundary needs review.
- `RSA-DEP-PROC-MACRO`: `proc-macro = true`; compile-time code execution needs review.
- `RSA-DEP-BUILD-DEPENDENCIES`: `[build-dependencies]`; build-time dependency trust boundary expands.
- `RSA-DEP-LOCK-GIT`: `Cargo.lock` git sources via `source = "git+..."`; final graph includes git-sourced code.
- `RSA-BUILD-SCRIPT`: `build.rs` presence; build-host code execution needs review.
- `RSA-BUILD-COMMAND`: `build.rs` command execution via `Command::new`, `sh -c`, or `cmd /C`; severity is high.

Every emitted finding includes `ruleId`, `file`, `startLine`, `category`, `severity`, `confidence`, and non-empty `evidence`.

## Suppression

Use an inline suppression comment near the finding only when the finding is a reviewed false positive or an intentionally accepted risk. Suppression is an accepted-risk record, not a way to make the tool quiet without accountability.

```rust
pub fn read_byte(ptr: *const u8) -> u8 {
    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK owner=@security ticket=SEC-123 until=2026-12-31 -- legacy FFI wrapper reviewed in host project
    unsafe { *ptr }
}
```

Supported formats:

```rust
// rustsec-auditor: ignore RULE_ID -- reason
// rustsec-auditor: ignore RULE_ID until=YYYY-MM-DD -- reason
// rustsec-auditor: ignore RULE_ID owner=@name -- reason
// rustsec-auditor: ignore RULE_ID ticket=SEC-123 -- reason
```

The scanner looks on the finding line and up to three preceding lines. Suppression is exact-rule only: `RULE_ID` must be the concrete finding rule id. Broad `ignore all` or `ignore *` directives are intentionally not supported. The reason after `--` is required. `owner`, `ticket`, and `until` are optional but recommended so future reviewers know who accepted the risk, where it is tracked, and when it should be revisited.

Active valid suppressions are omitted from `findings`, counted in `suppressedCount`, and included in `suppressedFindings` with structured metadata:

```json
{
  "ruleId": "RSA-UNSAFE-BLOCK",
  "file": "src/lib.rs",
  "line": 42,
  "directiveLine": 41,
  "reason": "legacy FFI wrapper reviewed in host project",
  "owner": "@security",
  "ticket": "SEC-123",
  "until": "2026-12-31",
  "isExpired": false,
  "isValid": true,
  "rawComment": "// rustsec-auditor: ignore RSA-UNSAFE-BLOCK owner=@security ticket=SEC-123 until=2026-12-31 -- legacy FFI wrapper reviewed in host project"
}
```

Expired suppressions are not treated as active; the finding is shown again, the suppression is marked with `isExpired: true`, and `rust_review_current_diff.reviewDecision.status` is at least `needs_attention`. Invalid suppressions, including missing reasons or broad ignore directives, are ignored, counted in `invalidSuppressionCount`, and include `invalidSuppression` explaining what must be fixed.

Use suppression for false positives or risks that have been explicitly reviewed and accepted. Do not use it to bypass high-confidence blockers; those should default to `fix_before_commit` unless the user makes a deliberate risk-acceptance decision.

## Output Examples

JSON output is produced by `renderJsonReport(toRustAuditReportInput(scan))`. Abridged example:

```json
{
  "schemaVersion": "0.2.0",
  "summary": {
    "result": "NEEDS_FIX_BEFORE_RELEASE",
    "total": 1,
    "high": 1
  },
  "findings": [
    {
      "id": "RSA-BUILD-COMMAND-...",
      "ruleId": "RSA-BUILD-COMMAND",
      "severity": "high",
      "confidence": "high",
      "category": "command_execution",
      "file": "build.rs",
      "startLine": 4,
      "evidence": ["Line 4: let _ = Command::new(\"sh\").arg(\"-c\").arg(\"cc native.c\").status();"]
    }
  ]
}
```

Markdown output is produced by `renderMarkdownReport(toRustAuditReportInput(scan))` and includes stable sections:

```markdown
## High Risk Findings

### RSA-BUILD-COMMAND-...: Build script spawns an external command

- Severity: High
- Confidence: High
- Category: command_execution
- Rule: RSA-BUILD-COMMAND
- Location: `build.rs:4`
```

## Finding Shape

Every finding must include concrete evidence and security-specific remediation guidance.

```ts
interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  category:
    | "unsafe"
    | "ffi"
    | "dependency"
    | "supply_chain"
    | "command_execution"
    | "filesystem"
    | "input_boundary"
    | "concurrency"
    | "secret"
    | "panic_dos"
    | "manual_review";
  file: string;
  startLine?: number;
  endLine?: number;
  evidence: string[];
  whyItMatters: string;
  riskScenario: string;
  suggestedFix: string;
  suggestedTests?: string[];
  falsePositiveNotes?: string;
  references?: string[];
}
```

## Current Limits

This is a static heuristic scanner. It improves review focus, but it is not complete formal verification, not symbolic execution, not full Rust parsing, and not proof that code is memory-safe. Treat findings as review targets with concrete evidence, especially around unsafe invariants, FFI boundaries, and build-time supply-chain behavior.

The MCP server validates that `projectPath` exists and is a local directory before scanning. It resolves and normalizes the project path, scans within that directory, filters git diff file paths to safe relative paths, and reports clear structured errors instead of crashing for invalid input.

`rust_review_current_diff` is useful today for changed-line-aware PR triage, but it is not a semantic patch analyzer. It does not build a Rust AST, perform taint analysis, prove unsafe invariants, or reason about data/control-flow impact across functions. Findings outside added lines can still matter, especially when nearby code changes alter an invariant, so treat `near_changed_lines` as review targets rather than confirmed vulnerabilities.

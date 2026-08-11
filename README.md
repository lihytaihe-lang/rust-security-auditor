# Rust Security Auditor

A local MCP server that reviews Rust code for unsafe, FFI, and supply-chain risk — and tells your coding agent what to look at before you commit.

It runs entirely on your machine, reads local Cargo projects, and exposes five read-only tools over stdio to Claude Code, Codex, or any other MCP client.

Ask your agent to review what you just wrote, and you get back the part of the diff that carries risk — actual output, abridged:

```markdown
# Rust Security Review: Current Diff

## Decision

NEEDS ATTENTION

- Safe to commit: No
- Reason: No hard blockers were found, but introduced findings or directly
  related same-function/same-unsafe-site context need human review before commit.
- Blocking findings: 0
- Manual review findings: 2

## Introduced by this diff

### Unsafe site at src/buffer.rs:11

- Location: `src/buffer.rs:11`
- Function/context: `read_fast`
- Diff relation: introduced_by_diff
- Findings:
  - Generic unsafe block (RSA-UNSAFE-BLOCK, medium severity/high pattern-detection confidence)
  - get_unchecked skips bounds checking (RSA-UNSAFE-GET-UNCHECKED, medium severity/high pattern-detection confidence)
```

Pre-existing unsafe code elsewhere in the file is classified separately and does not look like a new blocker.

## Install

Requires Node.js 20 or newer. No Rust toolchain needed — the scanner reads source and manifests, it does not build your project.

**Claude Code**

```bash
claude mcp add rust-security-auditor -- npx -y rust-security-auditor@latest
```

**Claude Desktop, Codex, Cursor, or any other MCP client**

```json
{
  "mcpServers": {
    "rust-security-auditor": {
      "command": "npx",
      "args": ["-y", "rust-security-auditor@latest"]
    }
  }
}
```

Claude Desktop reads `claude_desktop_config.json`; Codex, Cursor, and VS Code each have their own MCP config file, but the server block is the same. Fuller samples live in [`examples/mcp-client-config.json`](examples/mcp-client-config.json) and [`examples/codex-plugin-config.json`](examples/codex-plugin-config.json).

**From a local checkout**

```bash
git clone https://github.com/lihytaihe-lang/rust-security-auditor.git
cd rust-security-auditor
npm ci && npm test
```

Then point the client at the checkout, using `npm --silent run mcp` as the command with an absolute `cwd`. Keep `--silent`: MCP reserves stdout for JSON-RPC frames, and npm lifecycle banners break client initialization.

## The Five Tools

| Tool | Use it for |
| --- | --- |
| `rust_review_current_diff` | What did this change introduce? Run before commit or PR, and after agent-generated code. |
| `rust_audit_unsafe` | Unsafe blocks and functions, FFI boundaries, raw-memory primitives, unsafe Send/Sync. |
| `rust_audit_dependencies` | Cargo manifests, lockfiles, build scripts, git/path deps, proc macros, `.cargo/config.toml`. |
| `rust_audit_project` | The broad local scan across every rule. |
| `rust_list_accepted_risks` | Inventory of accepted-risk suppression comments, including expired and invalid ones. |

Ask for them in plain language — `review current diff before I commit`, `audit unsafe`, `check dependencies`, `list accepted risks` — or call them directly:

```json
{
  "projectPath": "/absolute/path/to/rust/project",
  "baseRef": "main",
  "headRef": "HEAD",
  "staged": false,
  "includePreExisting": false,
  "nearChangedLineWindow": 3,
  "outputFormat": "markdown",
  "pathMode": "relative",
  "reportMode": "compact"
}
```

Every tool takes `projectPath`, `outputFormat` (`markdown` | `json`), `pathMode` (`relative` | `absolute`), and `reportMode` (`compact` | `full`). Defaults are `relative` and `compact`, which keeps local absolute paths out of anything you paste into a PR.

Sanitized example outputs for each tool live in [`examples/reports/`](examples/reports).

## What It Catches

**Unsafe and FFI** — `RSA-UNSAFE-BLOCK`, `RSA-UNSAFE-FN`, `RSA-UNSAFE-IMPL-SEND`, `RSA-UNSAFE-IMPL-SYNC`, `RSA-FFI-EXTERN-C`, `RSA-FFI-CSTR-FROM-PTR`, `RSA-UNSAFE-TRANSMUTE`, `RSA-UNSAFE-MAYBEUNINIT`, `RSA-UNSAFE-FROM-RAW-PARTS`, `RSA-UNSAFE-SET-LEN`, `RSA-UNSAFE-BOX-FROM-RAW`, `RSA-UNSAFE-GET-UNCHECKED`, `RSA-UNSAFE-UNCHECKED-CALL`, `RSA-UNSAFE-STATIC-MUT`, `RSA-UNSAFE-RAW-PTR-ACCESS`

**Supply chain and build** — `RSA-DEP-GIT`, `RSA-DEP-PATH`, `RSA-DEP-PROC-MACRO`, `RSA-DEP-BUILD-DEPENDENCIES`, `RSA-DEP-LOCK-GIT`, `RSA-DEP-VERSION-UNBOUNDED`, `RSA-BUILD-SCRIPT`, `RSA-BUILD-COMMAND`, `RSA-CARGO-SOURCE-REPLACEMENT`, `RSA-CARGO-RUNNER`

**Runtime execution** — `RSA-EXEC-COMMAND`

Every finding carries a rule id, file and line, evidence, why it matters, a concrete risk scenario, and a suggested fix. Findings are deduplicated by `file + startLine + ruleId` and sorted by severity, then confidence, then location.

The scanner tracks Rust comment and literal boundaries, so a pattern inside a block comment, doc example, or string literal is not reported. Findings inside `#[cfg(test)]` code are reported at reduced severity, because test code does not ship.

**Confidence means pattern-detection confidence, not exploitability.** A high-confidence finding says the pattern is definitely there, not that a vulnerability is confirmed.

## What It Is Not

- **It does not check for known vulnerabilities.** There is no [RustSec advisory database](https://rustsec.org) or CVE lookup — it will not tell you that a dependency version has a published advisory. Run `cargo audit` or `cargo deny` alongside it. ([tracked in the roadmap](ROADMAP.md))
- Not full AST, data-flow, control-flow, or taint analysis. Rules are line-based patterns with lexical context.
- Not formal verification, symbolic execution, or a replacement for human review of unsafe invariants.
- Not a hosted service, SaaS scanner, or uploaded-code scanner. It reads local paths only.
- Not a generic code review or style tool.

## Current Diff Review

`rust_review_current_diff` reviews the working tree by default, `git diff --cached` with `staged: true`, and `baseRef..headRef` when both refs are given.

Each finding is classified by its relationship to the change:

| Relation | Meaning |
| --- | --- |
| `introduced_by_diff` | Starts on an added line. |
| `same_unsafe_site_context` | Pre-existing, but in the same unsafe block as an added line. |
| `same_function_context` | Pre-existing, in the same function, different unsafe site. |
| `nearby_legacy_context` | Line-near an added line, but in a different function or unsafe site. |
| `unrelated_nearby` | Line-near an added line with no confirmed tie. |
| `pre_existing_in_changed_file` | In a changed file, outside the changed-line window. |

Compact output shows `introduced_by_diff`, `same_unsafe_site_context`, and medium-or-higher `same_function_context` at medium/high confidence. Legacy nearby context is hidden so that old unsafe code in a different function does not look like a new blocker — use `reportMode: "full"` to see it, and `includePreExisting: true` to include historical findings in changed files. Lower `nearChangedLineWindow` to 1 or 2 if nearby findings are still noisy.

The tool also returns a `reviewDecision`:

- `block` — introduced critical/high findings with non-low confidence.
- `needs_attention` — introduced medium findings, directly relevant same-site or same-function context, low-confidence introduced findings, or expired/invalid suppressions.
- `pass` — nothing blocking or needing manual review.

The decision is driven by `introduced_by_diff`. Same-site high findings need attention but do not hard-block; `nearby_legacy_context` and `unrelated_nearby` never affect it unless you ask for pre-existing findings.

## Accepted Risk Suppressions

Suppressions are records of reviewed false positives or deliberately accepted risk — not a way to hide unresolved blockers.

```rust
pub fn read_byte(ptr: *const u8) -> u8 {
    // rust-security-auditor: ignore RSA-UNSAFE-BLOCK owner=@security ticket=SEC-123 until=2026-12-31 -- legacy FFI wrapper reviewed in host project
    unsafe { *ptr }
}
```

```rust
// rust-security-auditor: ignore RULE_ID -- reason
// rust-security-auditor: ignore RULE_ID until=YYYY-MM-DD -- reason
// rust-security-auditor: ignore RULE_ID owner=@name ticket=SEC-123 -- reason
```

- The reason after `--` is required, and `RULE_ID` must be an exact rule id.
- `ignore all` and `ignore *` are not supported.
- Expired suppressions are reported again; invalid ones are ignored and listed for cleanup.
- The older `rustsec-auditor:` marker still works but is deprecated — it collides with the unrelated [RustSec](https://rustsec.org) project. Rename existing comments to `rust-security-auditor:`; the scanner warns when it sees the old form.

Use `rust_list_accepted_risks` to inventory active, expired, and invalid suppressions without running the full scanner.

## Report Modes

`compact` (default) is built for agent summaries and PR comments: overall risk, severity and rule counts, top findings, grouped review signals, high-priority areas, and suggested follow-up prompts. The JSON `findings` array always stays complete.

`full` preserves every per-finding detail — evidence, why it matters, risk scenario, suggested fix, suggested tests, references, false-positive notes, and suppression records. Use it for audit notes, handoff archives, and suppression review.

When several findings point at one unsafe site, Markdown groups them under that site. This is display only; the JSON is unchanged.

## Development

```bash
npm ci
npm run typecheck
npm test
npm run check      # typecheck + test + whitespace
```

For local debugging without an MCP client:

```bash
npm run mcp:call -- rust_audit_project --projectPath test/fixtures/vulnerable-rust-project --outputFormat markdown
npm run mcp:call -- rust_review_current_diff --projectPath /absolute/path/to/rust/project --staged true
```

Build output goes to `dist/` and is git-ignored. Adding a rule is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Source layout:

| Path | Contents |
| --- | --- |
| `src/mcp/server.ts` | Local stdio MCP server |
| `src/mcp/tools.ts` | Tool handlers backed by the scanner kernel |
| `src/scanners/rustLexer.ts` | Comment/literal masking and test-code detection |
| `src/scanners/unsafeScanner.ts` | Unsafe, FFI, and raw-memory rules |
| `src/scanners/dependencyScanner.ts` | Cargo manifest, lockfile, build script, and cargo config rules |
| `src/scanners/sourceRiskScanner.ts` | Runtime process execution |
| `src/scanners/rules.ts` | Rule metadata: severity, rationale, remediation |
| `src/scanners/suppressions.ts` | Suppression parsing and expiry |
| `src/git/diffParser.ts` | Unified diff parser |
| `src/reports/` | Markdown and JSON renderers, finding schema |

## Security Model

The server validates that `projectPath` exists and is a local directory, scans only within it, filters git diff paths to safe relative paths, refuses git refs that could be read as flags, and runs `git` without a shell. It does not upload code, package source bundles, or contact any network service.

Discovery skips `.git`, `target`, `node_modules`, and similar directories, does not follow symbolic links out of the project, and caps per-file size and total file count — reporting any limit it hits as a warning rather than scanning silently incomplete.

See [SECURITY.md](SECURITY.md) for reporting a vulnerability in this tool and for what is in and out of scope.

## Status

v0.1.x local-first MCP preview, released under Apache-2.0. Local, read-only Rust review — not a hosted scanner, ChatGPT App, or marketplace product. Hosted deployment and any private-code handling remain deferred to a separate product and privacy decision; see [ROADMAP.md](ROADMAP.md).

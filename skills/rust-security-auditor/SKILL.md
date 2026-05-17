---
name: rust-security-auditor
description: Use this skill when a user asks Codex to review a local Rust project, current diff, unsafe/FFI code, Cargo dependencies, or release readiness for Rust security risks using the Rust Security Auditor MCP server.
---

# Rust Security Auditor

Use this skill to turn natural Codex requests into focused calls to the local Rust Security Auditor MCP tools. The auditor is a heuristic, local, read-only Rust security review layer. It improves review focus, but it is not a complete formal security proof, symbolic executor, full Rust parser, or replacement for human review.

The tool is intended for local Codex project context. Do not suggest uploading a repository or code package to an external service.

## Natural Language Entries

Map these user entries to MCP tools:

| User entry | MCP tool | Default intent |
| --- | --- | --- |
| `review current diff` | `rust_review_current_diff` | Pre-commit or PR review of findings in diff-affected files. |
| `check this Rust project before commit` | `rust_review_current_diff` | Pre-commit review of current working tree, staged, and untracked changes. |
| `audit unsafe` | `rust_audit_unsafe` | Unsafe, FFI, raw pointer, initialization, and unsafe Send/Sync review. |
| `audit dependencies` | `rust_audit_dependencies` | Cargo and build-time supply-chain review. |
| `audit project` | `rust_audit_project` | Full local Rust project security health check. |
| `run release security audit` | `rust_audit_project` | Release-gate style full project audit. |
| `check this Rust project before release` | `rust_audit_project` | Release-gate style full project audit. |

Always pass the current local Rust project directory as `projectPath` unless the user provides a different local path. Prefer `outputFormat: "json"` when Codex will summarize and reason over the result; use `outputFormat: "markdown"` when the user explicitly wants the generated report text.

## Tool Selection

Call `rust_review_current_diff` when the user asks for current diff, before commit, before PR, changed files, or branch review. Explain that this is file-level diff review: it scans findings in files touched by the diff, not semantic changed-line analysis.

Call `rust_audit_unsafe` when the user asks about unsafe Rust, FFI, raw pointers, `unsafe fn`, `unsafe impl Send`, `unsafe impl Sync`, `MaybeUninit`, `transmute`, `from_raw_parts`, `set_len`, or `Box::from_raw`. Focus on safety invariants, ownership, lifetimes, initialization, aliasing, unwind behavior, and thread-safety contracts.

Call `rust_audit_dependencies` when the user asks about dependencies, supply chain, Cargo changes, `Cargo.toml`, `Cargo.lock`, `build.rs`, `git` dependencies, `path` dependencies, proc macros, or build dependencies. Focus on build-time code execution, dependency source trust, revision pinning, and local path trust boundaries.

Call `rust_audit_project` when the user asks for a full project audit, project health check, release security audit, before release, or before publishing. Treat this as the broadest local scan across unsafe/FFI, dependency/supply-chain, build scripts, command execution, filesystem/path handling, input boundaries, secrets, panic/DoS, concurrency, and manual-review categories.

## Explaining Findings

When presenting tool results, include:

- Overall risk conclusion.
- Blocking issues.
- Recommended fixes.
- Manual review needed.
- False positive and suppression guidance.

Severity guidance:

- `critical` or `high`: default to "fix before commit or release"; do not recommend direct commit or release unless the user explicitly accepts the risk.
- `medium`: require developer context confirmation before deciding whether to block.
- `low` or `info`: reminder-level findings; normally non-blocking.

Confidence guidance:

- `high`: present strongly, using the tool evidence and suggested fix.
- `medium`: recommend manual confirmation of the code context and invariant.
- `low`: avoid exaggeration; phrase as a review target or possible risk, not a confirmed vulnerability.

For every finding, ground the explanation in the returned `ruleId`, `file`, line, severity, confidence, evidence, `whyItMatters`, risk scenario, and suggested fix. Do not invent exploitability beyond the evidence.

## Commit And Release Gate Guidance

Before commit:

- Block by default on `critical` or `high` findings in `rust_review_current_diff`.
- Treat `medium` findings as "needs developer confirmation".
- Allow `low` and `info` findings to be tracked unless they indicate policy-sensitive code.

Before release:

- Block by default on any `critical` or `high` finding from `rust_audit_project`.
- Treat any `medium`, `manual_review`, or low-confidence finding as a required manual release checklist item.
- State when the result is a heuristic scan and not a guarantee that the release is secure.

## False Positives And Suppression

If a finding is accepted as intentional and reviewed, suggest adding a narrow inline suppression only when the user asks how to handle noise. Suppress the specific `ruleId` near the relevant code and include a human-readable reason. Do not recommend broad suppression when a local fix or clearer invariant documentation is better.

## Do Not Do

- Do not provide generic code style, formatting, naming, or refactoring advice.
- Do not pretend a complete security audit was performed.
- Do not claim the tool proves code is safe or memory-safe.
- Do not ignore `confidence`.
- Do not treat a low-confidence finding as a confirmed vulnerability.
- Do not recommend uploading the project to an external service.
- Do not default to modifying code unless the user explicitly asks for fixes.
- Do not add broad scanner rules or rewrite the MCP server as part of using this skill.

## Related Files

- Read `examples.md` for complete Codex interaction examples.
- Read `troubleshooting.md` when MCP startup, project path, missing tools, or noisy output issues appear.

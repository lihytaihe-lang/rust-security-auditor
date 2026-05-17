---
name: rust-security-auditor
description: Use this skill when a user asks Codex to review a local Rust project, current diff, unsafe/FFI code, Cargo dependencies, or accepted-risk inventory for Rust security risks using the Rust Security Auditor MCP server.
---

# Rust Security Auditor

Use this skill to turn natural Codex requests into focused calls to the local Rust Security Auditor MCP tools. The auditor is a heuristic, local, read-only Rust security review layer. It improves review focus, but it is not a complete formal security proof, symbolic executor, full Rust parser, or replacement for human review.

The tool is intended for local Codex project context. Do not suggest uploading a repository or code package to an external service.

## Natural Language Entries

Map these user entries to MCP tools:

| User entry | MCP tool | Default intent |
| --- | --- | --- |
| `review current diff` | `rust_review_current_diff` | Pre-commit or PR review of findings introduced by or near changed lines. |
| `check this Rust project before commit` | `rust_review_current_diff` | Pre-commit review of the selected Git diff; use `staged: true` for staged changes. |
| `audit unsafe` | `rust_audit_unsafe` | Unsafe, FFI, raw pointer, initialization, and unsafe Send/Sync review. |
| `audit dependencies` | `rust_audit_dependencies` | Cargo and build-time supply-chain review. |
| `audit project` | `rust_audit_project` | Full local Rust project security health check. |
| `audit project before release` | `rust_audit_project` | Pre-release local project scan. |
| `check this Rust project before release` | `rust_audit_project` | Pre-release local project scan. |
| `list accepted risks` | `rust_list_accepted_risks` | Inventory accepted-risk suppression comments without running the full scanner. |
| `show suppressed risks` | `rust_list_accepted_risks` | Show active accepted risks and optionally expired or invalid suppressions. |
| `check expired suppressions` | `rust_list_accepted_risks` | Review expired `rustsec-auditor` suppressions. |
| `review accepted risk inventory before release` | `rust_list_accepted_risks` | Pre-release accepted-risk inventory and cleanup check. |

Always pass the current local Rust project directory as `projectPath` unless the user provides a different local path. Prefer `outputFormat: "json"` when Codex will summarize and reason over the result; use `outputFormat: "markdown"` when the user explicitly wants the generated report text. When generating Markdown, use `pathMode: "relative"` by default.

For `rust_audit_project`, `rust_audit_unsafe`, and `rust_audit_dependencies`, use `reportMode: "compact"` by default. Compact non-diff reports keep JSON findings complete while making Markdown suitable for Codex and developer handoff. Use `reportMode: "full"` only when the user asks for complete evidence, suggested fixes/tests, suppression details, or an archive-style audit report.

## Tool Selection

Call `rust_review_current_diff` when the user asks for current diff, before commit, before PR, changed files, staged changes, or branch review. It parses git diff hunks and marks findings as `introduced_by_diff`, `same_unsafe_site_context`, `same_function_context`, `nearby_legacy_context`, `unrelated_nearby`, or `pre_existing_in_changed_file`.

Defaults for `rust_review_current_diff`:

- With no refs and no `staged`, review `git diff` for unstaged working tree changes.
- With `staged: true`, review `git diff --cached`.
- With both `baseRef` and `headRef`, review `git diff baseRef..headRef`.
- Use `pathMode: "relative"` by default when generating Markdown, especially for reports that may be pasted into PRs or shared outside the local machine.
- Use `reportMode: "compact"` by default for Codex / PR comments; use `reportMode: "full"` only when the user asks for full evidence/details.
- Use `nearChangedLineWindow: 3` by default. Lower it to `1` or `2` when near-line noise is too high.
- By default, present `introduced_by_diff`, `same_unsafe_site_context`, and medium-or-higher `same_function_context` with medium/high confidence.
- Treat `nearby_legacy_context` and `unrelated_nearby` as hidden legacy context in compact reports; use `reportMode: "full"` when the user asks to inspect it separately.
- Use `includePreExisting: true` only when the user asks to see historical risks in changed files.
- Use `reviewDecision.status` as the primary commit/PR recommendation: `block`, `needs_attention`, or `pass`.
- Use `enrichedFindings[].actionability.recommendedAction` and `suggestedFixPrompt` when the user asks what Codex should do next.
- Use `suppressionSummary` and `suppressedFindings` to explain active, expired, and invalid accepted-risk suppressions.
- Use `reviewGroups` / grouped Markdown as a UX grouping for the same unsafe site. Do not imply grouped findings are merged vulnerabilities.
- Do not modify code automatically from `suggestedFixPrompt`; offer or run fixes only when the user explicitly asks.

Explain that changed-line awareness improves PR focus, but the result is still heuristic scanner output, not full data-flow, control-flow, or taint analysis.

Call `rust_audit_unsafe` when the user asks about unsafe Rust, FFI, raw pointers, `unsafe fn`, `unsafe impl Send`, `unsafe impl Sync`, `MaybeUninit`, `transmute`, `from_raw_parts`, `set_len`, or `Box::from_raw`. Focus on safety invariants, ownership, lifetimes, initialization, aliasing, unwind behavior, and thread-safety contracts.

In compact Markdown, treat `rust_audit_unsafe` as an unsafe review checklist: summarize unsafe blocks, unsafe fn, unsafe Send/Sync impls, FFI, and raw-memory primitives; use the grouped unsafe site/function view; and present the required manual invariants plus the suggested Codex prompts.

Call `rust_audit_dependencies` when the user asks about dependencies, supply chain, Cargo changes, `Cargo.toml`, `Cargo.lock`, `build.rs`, `git` dependencies, `path` dependencies, proc macros, or build dependencies. Focus on build-time code execution, dependency source trust, revision pinning, and local path trust boundaries.

In compact Markdown, treat `rust_audit_dependencies` as a supply-chain checklist: lead with build.rs command execution, git dependencies, lockfile git sources, proc macros, and build dependencies. Remind the user to run `cargo audit` separately because this tool does not query vulnerability databases.

Call `rust_audit_project` when the user asks for a full local project scan, project health check, before release, or before publishing. Treat this as the broadest local scan across unsafe/FFI, dependency/supply-chain, build scripts, command execution, filesystem/path handling, input boundaries, secrets, panic/DoS, concurrency, and manual-review categories.

In compact Markdown, treat `rust_audit_project` as a broad project summary, not a 1:1 finding dump: report the risk level, counts, top 5 findings, grouped categories/rule IDs, high-priority areas, and suggested next audits (`rust_audit_unsafe`, `rust_audit_dependencies`, `rust_review_current_diff`, `rust_list_accepted_risks`).

Call `rust_list_accepted_risks` when the user asks to list accepted risks, show suppressed risks, check expired suppressions, clean up invalid suppressions, or review the accepted risk inventory before release. This tool only scans Rust source files for `rustsec-auditor` suppression comments; it does not run the full scanner and does not modify source code. Use `includeExpired: true` when the user wants expired suppressions, `includeInvalid: true` when the user wants invalid suppressions, and `outputFormat: "markdown"` when the user asks for the inventory report.

## Explaining Findings

When presenting tool results, include:

- Overall risk conclusion.
- `reviewDecision.status`, reason, and whether `safeToCommit` is true.
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

Actionability guidance:

- `fix_before_commit`: present as a blocker and include the returned `suggestedFixPrompt`.
- `manual_review`: ask the user or code owner to confirm the invariant before calling it a real defect.
- `monitor`: mention as a non-blocking note unless project policy says otherwise.
- `suppress_if_accepted`: explain that suppression is appropriate only after the risk is intentionally accepted, with a narrow inline suppression, required reason, and preferably owner/ticket/until metadata. Do not add the suppression unless the user explicitly asks.

For every finding, ground the explanation in the returned `ruleId`, `file`, line, severity, confidence, evidence, `whyItMatters`, risk scenario, and suggested fix. Do not invent exploitability beyond the evidence.

## Commit And Pre-Release Guidance

Before commit:

- Block by default on `critical` or `high` findings marked `introduced_by_diff` when confidence is `high` or `medium`.
- Treat `medium` findings marked `introduced_by_diff` as "needs developer confirmation".
- Treat `same_unsafe_site_context` high findings as `needs_attention`, not default blockers.
- Treat `same_function_context` medium/high findings as manual review when confidence is medium/high.
- Treat `nearby_legacy_context` and `unrelated_nearby` as non-blocking legacy context unless `includePreExisting: true` was explicitly requested.
- Put low-confidence findings in manual review / accepted-risk flow, not in hard blockers.
- Treat only low/info findings with non-low confidence as pass-level non-blocking notes.
- Hide or summarize `pre_existing_in_changed_file` findings unless `includePreExisting: true` was requested.
- Allow `low` and `info` findings to be tracked unless they indicate policy-sensitive code.

Before pre-release review:

- Block by default on any `critical` or `high` finding from `rust_audit_project`.
- Treat any `medium`, `manual_review`, or low-confidence finding as a required manual release checklist item.
- State when the result is a heuristic scan and not a guarantee that the release is secure.
- Do not present non-diff audit output as a formal release gate. It is a review aid and developer handoff artifact.

## False Positives And Suppression

If a finding is accepted as intentional and reviewed, suggest adding a narrow inline suppression only when the user asks how to handle noise or the tool returns `recommendedAction: "suppress_if_accepted"`. Suppression means "accepted risk with traceability", not "make the tool quiet".

Supported suppression comments:

```rust
// rustsec-auditor: ignore RULE_ID -- reason
// rustsec-auditor: ignore RULE_ID until=YYYY-MM-DD -- reason
// rustsec-auditor: ignore RULE_ID owner=@name -- reason
// rustsec-auditor: ignore RULE_ID ticket=SEC-123 -- reason
```

Rules for explaining suppression:

- Reason is required.
- Use the exact returned `ruleId`; broad `ignore all` or `ignore *` is not supported.
- Recommend owner, ticket, and until when the risk is accepted for more than a one-off false positive.
- Expired suppressions are shown again and make current diff review at least `needs_attention`.
- Invalid suppressions are ignored and should be fixed as accepted-risk metadata, not treated as hidden findings.
- High-confidence blockers should default to `fix_before_commit`, not suppression.

For accepted-risk inventory output, summarize:

- Active accepted risks.
- Expired suppressions that need re-evaluation or removal.
- Invalid suppressions that need a reason or format fix.
- Missing `owner=` and `ticket=` metadata that should be added for traceability.

Do not add, renew, or delete suppression comments unless the user explicitly asks for code changes.

Useful Codex prompts:

```text
Please review RSA-... at file:line inside function name. First explain the safety invariant and repair strategy, then apply the smallest safe code change and add focused tests if the finding is valid.
```

```text
If this risk is intentional, add a rustsec-auditor suppression comment with a clear reason, owner, and ticket.
```

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

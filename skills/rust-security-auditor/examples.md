# Rust Security Auditor Examples

These examples show how Codex should translate natural `@Rust Security Auditor` requests into MCP tool calls and concise security-review output.

## Example 1: Current Diff Before Commit

User:

```text
@Rust Security Auditor review current diff
```

Expected behavior:

- Call `rust_review_current_diff`.
- Use the current local Rust project directory as `projectPath`.
- For shareable Markdown, use `pathMode: "relative"` and the default `reportMode: "compact"`.
- Review findings marked `introduced_by_diff`, `same_unsafe_site_context`, or relevant `same_function_context`.
- Explain that `nearby_legacy_context` and `unrelated_nearby` are hidden from compact reports by default because they are legacy context, not proof that the current diff introduced the finding.
- Mention hidden `pre_existing_in_changed_file` counts when present, and offer `includePreExisting: true` only if the user wants historical risks in changed files.
- Prioritize `critical`, `high`, and `medium` findings.
- Use `reviewDecision.status` as the commit recommendation.
- Include `suggestedFixPrompt` values for blocking or manual-review findings when useful.
- Explain that current diff review is changed-line aware but still not full data-flow or taint analysis.
- Explain that confidence is pattern-detection confidence, not exploitability confidence.
- End with a commit recommendation.

Expected Codex response shape:

```text
Decision: block
Safe to commit: no

Blocking issues:
- RSA-BUILD-COMMAND in build.rs:4 is high severity with high pattern-detection confidence and is marked introduced_by_diff because the changed line adds a build-script shell command.

Recommended fixes:
- Replace shell invocation with a constrained build helper or document and validate the exact command path and arguments.

Manual review needed:
- Confirm whether this command can be influenced by environment variables, workspace files, or user input.

Suggested Codex fix prompt:
- Please review RSA-BUILD-COMMAND at build.rs:4 inside function main. This finding appears introduced by the current diff. First explain the safety invariant and repair strategy, then use absolute tool paths or allowlisted commands, validate arguments, and avoid passing untrusted environment values to the process.

Commit recommendation:
- Do not commit yet. Fix or explicitly accept the high-severity build-script risk first.
```

Tool-output cues to use:

- `enrichedFindings[].diffContext.relation`
- `enrichedFindings[].actionability.recommendedAction`
- `enrichedFindings[].actionability.suggestedFixPrompt`
- `nearestChangedLine` and `distance`
- `functionName`, `contextAssessment`, and unsafe-site grouping when present
- `reviewGroups[]` for grouped unsafe-site presentation
- `reviewDecision.status`, `reason`, and `safeToCommit`
- `diffReview.hiddenPreExistingCount`
- `summary.blockingCount`, `manualReviewCount`, and `nonBlockingCount`
- `suppressionSummary.suppressedCount`, `expiredSuppressionCount`, and `invalidSuppressionCount`
- `suppressedFindings[]`

## Example 2: Unsafe-Specific Audit

User:

```text
@Rust Security Auditor audit unsafe
```

Expected behavior:

- Call `rust_audit_unsafe`.
- Use compact Markdown by default when the user wants a report; full mode is only for complete evidence/details.
- Focus on unsafe blocks, `unsafe fn`, FFI, raw pointers, initialization APIs, and unsafe Send/Sync impls.
- Use the compact unsafe-site/function grouping instead of repeating every primitive as a long standalone block.
- Explain the unsafe invariant each finding points at.
- Distinguish documented unsafe from undocumented unsafe when the tool evidence supports it.
- Treat unsafe findings as review cues for invariants, not confirmed vulnerabilities.
- Output manual-review questions for invariants Codex cannot prove.

Expected Codex response shape:

```text
Overall risk: needs_attention

Manual review needed:
- Unsafe block at src/lib.rs:21: confirm the raw pointer is non-null, aligned, valid for reads, and not aliased mutably.
- FFI boundary at src/ffi.rs:8: confirm ownership, lifetime, nullability, allocator, and unwind behavior across the C ABI.

Recommended fixes:
- Add or tighten SAFETY comments that state the caller and callee invariants.
- Add tests or debug assertions for reachable preconditions where possible.

Pre-release guidance:
- Treat medium pattern-detection confidence unsafe findings as manual checklist items before release.
```

## Example 3: Dependency And Supply-Chain Audit

User:

```text
@Rust Security Auditor audit dependencies
```

Expected behavior:

- Call `rust_audit_dependencies`.
- Use compact Markdown by default when the user wants a report; it should read like a supply-chain checklist.
- Focus on `Cargo.toml`, `Cargo.lock`, `build.rs`, `git` dependencies, `path` dependencies, proc macros, and `[build-dependencies]`.
- Highlight build-time execution and dependency source trust boundaries.
- Group workspace-local path dependencies as one low-priority trust-boundary signal when compact output reports them that way.
- Tell the user to run `cargo audit` separately for vulnerability database checks.
- Avoid generic dependency update advice unless tied to a returned finding.

Expected Codex response shape:

```text
Overall risk: needs_attention

Blocking issues:
- None returned at high or critical severity.

Manual review needed:
- RSA-DEP-GIT in Cargo.toml uses a git dependency. Confirm the repository is trusted and the revision is pinned.
- RSA-DEP-PROC-MACRO flags compile-time code execution. Confirm the proc-macro crate is reviewed and expected.
- RSA-BUILD-SCRIPT flags build.rs. Confirm build-time behavior and inputs.
- Workspace-local path dependencies: 3 items. Confirm they remain inside the reviewed workspace and are covered by CI.

Recommended fixes:
- Run cargo audit separately for known vulnerable crate advisories.
- Pin git dependencies to a specific revision.
- Prefer registry releases when feasible.
- Keep build script behavior minimal and documented.
```

## Example 4: Pre-Release Project Scan

User:

```text
@Rust Security Auditor audit project before release
```

Expected behavior:

- Call `rust_audit_project`.
- Use compact Markdown by default for developer handoff; request `reportMode: "full"` only for a complete audit appendix.
- Produce a pre-release summary, risk level, blocking findings, recommended fixes, and manual-review items.
- Do not expand every finding in the first response; use the compact top findings, grouped counts, and high-priority areas.
- State that the scan is heuristic and local, not a proof of security.
- State that confidence is pattern-detection confidence, not exploitability confidence.
- Include suppression guidance only for intentionally accepted findings.

Expected Codex response shape:

```text
Overall risk: high_risk

Blocking issues:
- 1 high-severity finding must be fixed or explicitly accepted before release.

Recommended fixes:
- Address RSA-BUILD-COMMAND in build.rs by removing shell execution or constraining and documenting it.

Manual review needed:
- Review unsafe and FFI findings for documented invariants.
- Review Cargo git/path dependency trust-boundary signals and build dependencies for supply-chain trust.

Suggested next audits:
- Run rust_audit_unsafe for grouped unsafe invariant review.
- Run rust_audit_dependencies for build.rs and dependency trust review.
- Run rust_review_current_diff before committing new changes.

False positives / suppressions:
- If a finding is intentional and reviewed, use a narrow inline suppression for the specific rule id with a required reason and preferably owner, ticket, and until.

Pre-release recommendation:
- Do not release until high-severity findings are resolved. This result is a heuristic audit, not a formal security proof.
```

## Example 5: Project Check Before Commit

User:

```text
@Rust Security Auditor check this Rust project before commit
```

Expected behavior:

- Call `rust_review_current_diff`.
- Treat `critical` and `high` findings marked `introduced_by_diff` as commit blockers when pattern-detection confidence is not low.
- Treat `medium` findings marked `introduced_by_diff` as context-dependent.
- Treat `same_unsafe_site_context` findings as relevant context that can need attention, but should not hard-block by default.
- Treat `same_function_context` medium/high findings as manual review when pattern-detection confidence is medium/high.
- Treat `nearby_legacy_context` and `unrelated_nearby` as non-blocking legacy context unless project policy or `includePreExisting: true` says otherwise.
- Treat low-confidence findings as manual-review / accepted-risk items, not confirmed vulnerabilities.
- Treat low/info findings as non-blocking notes unless policy requires more.
- Keep the output scoped to security, not style.

Expected Codex response shape:

```text
Decision: pass
Safe to commit: yes

Blocking issues:
- None.

Manual review needed:
- None returned by the tool.

Commit recommendation:
- The security diff review does not block this commit. This is not a complete security proof.
```

## Example 6: Accepted Risk Suppression Workflow

User:

```text
@Rust Security Auditor review current diff and explain suppressions
```

Expected behavior:

- Call `rust_review_current_diff`.
- Report `suppressionSummary` even when active suppressions hide findings.
- List active accepted risks from `suppressedFindings`.
- If `expiredSuppressionCount` is non-zero, explain that those findings are shown again and need review.
- If `invalidSuppressionCount` is non-zero, explain that the directive is ignored until fixed.
- Do not add suppression comments automatically.
- Do not suggest suppression as the primary action for high-confidence blockers, and clarify that confidence is pattern-detection confidence.

Expected Codex response shape:

```text
Decision: needs_attention
Safe to commit: no

Accepted / suppressed risks:
- 1 active suppression: RSA-UNSAFE-BLOCK at src/lib.rs:42, reason: legacy FFI wrapper reviewed; owner: @security; ticket: SEC-123; until: 2026-12-31.
- 1 expired suppression: RSA-UNSAFE-BLOCK at src/lib.rs:58 is shown again because until=2026-01-01 has passed.
- 1 invalid suppression: RSA-UNSAFE-BLOCK at src/lib.rs:73 is ignored because the required reason after `--` is missing.

Suggested Codex prompts:
- Please review RSA-... at file:line inside function name. First explain the invariant, then apply the smallest safe code change if the finding is valid.
- If this risk is intentional, add a accepted-risk suppression comment with a clear reason, owner, and ticket.

Commit recommendation:
- Do not commit yet. Review the expired/invalid suppression entries and either fix the code or update the accepted-risk record deliberately.
```

## Example 7: Project Check Before Release

User:

```text
@Rust Security Auditor check this Rust project before release
```

Expected behavior:

- Call `rust_audit_project`.
- Treat high and critical findings as pre-release blockers.
- List medium severity and low pattern-detection confidence findings as manual checklist items.
- Include the overall risk level and pre-release recommendation.

Expected Codex response shape:

```text
Overall risk: warning

Blocking issues:
- None.

Manual review needed:
- Medium findings require owner confirmation before release.

Pre-release recommendation:
- Release can proceed only after manual-review items are accepted. The scan is heuristic and local.
```

## Example 8: Accepted Risk Inventory

User:

```text
@Rust Security Auditor list accepted risks
```

Equivalent entries:

```text
@Rust Security Auditor show suppressed risks
@Rust Security Auditor check expired suppressions
@Rust Security Auditor review accepted risk inventory before release
```

Expected behavior:

- Call `rust_list_accepted_risks`.
- Use the current local Rust project directory as `projectPath`.
- Set `includeExpired: true` when the user asks about expired suppressions or release readiness.
- Set `includeInvalid: true` when the user asks for cleanup, suppression health, or a full inventory.
- Do not run `rust_audit_project` unless the user also asks for a full project audit.
- Do not modify suppression comments automatically.

Expected Codex response shape:

```text
Accepted risk inventory:
- Active accepted risks: 4
- Expired suppressions: 1
- Invalid suppressions: 1
- Rule IDs: RSA-UNSAFE-BLOCK: 6
- Owners: @security: 1, (missing): 5

Expired suppressions:
- RSA-UNSAFE-BLOCK at src/lib.rs:26 expired on 2000-01-01 and should be re-evaluated or removed.

Invalid suppressions:
- RSA-UNSAFE-BLOCK at src/lib.rs:7 is missing the required reason after `--`.

Recommended actions:
- Re-evaluate expired suppressions.
- Add missing reasons or fix invalid formats.
- Add owner and ticket metadata for traceability.
```

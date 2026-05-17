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
- Review only findings in Git diff affected files.
- Prioritize `critical`, `high`, and `medium` findings.
- Explain that current diff review is file-level, not semantic changed-line analysis.
- End with a commit recommendation.

Expected Codex response shape:

```text
Overall risk: high_risk

Blocking issues:
- RSA-BUILD-COMMAND in build.rs:4 is high confidence/high severity because the build script spawns a shell command.

Recommended fixes:
- Replace shell invocation with a constrained build helper or document and validate the exact command path and arguments.

Manual review needed:
- Confirm whether this command can be influenced by environment variables, workspace files, or user input.

Commit recommendation:
- Do not commit yet. Fix or explicitly accept the high-severity build-script risk first.
```

## Example 2: Unsafe-Specific Audit

User:

```text
@Rust Security Auditor audit unsafe
```

Expected behavior:

- Call `rust_audit_unsafe`.
- Focus on unsafe blocks, `unsafe fn`, FFI, raw pointers, initialization APIs, and unsafe Send/Sync impls.
- Explain the unsafe invariant each finding points at.
- Distinguish documented unsafe from undocumented unsafe when the tool evidence supports it.
- Output manual-review questions for invariants Codex cannot prove.

Expected Codex response shape:

```text
Overall risk: needs_attention

Manual review needed:
- RSA-UNSAFE-BLOCK at src/lib.rs:21 requires confirmation that the raw pointer is non-null, aligned, valid for reads, and not aliased mutably.
- RSA-FFI-EXTERN-C at src/ffi.rs:8 requires confirmation of ownership, lifetime, nullability, and unwind behavior across the C ABI.

Recommended fixes:
- Add or tighten SAFETY comments that state the caller and callee invariants.
- Add tests or debug assertions for reachable preconditions where possible.

Release guidance:
- Treat medium-confidence unsafe findings as manual release checklist items.
```

## Example 3: Dependency And Supply-Chain Audit

User:

```text
@Rust Security Auditor audit dependencies
```

Expected behavior:

- Call `rust_audit_dependencies`.
- Focus on `Cargo.toml`, `Cargo.lock`, `build.rs`, `git` dependencies, `path` dependencies, proc macros, and `[build-dependencies]`.
- Highlight build-time execution and dependency source trust boundaries.
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

Recommended fixes:
- Pin git dependencies to a specific revision.
- Prefer registry releases when feasible.
- Keep build script behavior minimal and documented.
```

## Example 4: Release Security Audit

User:

```text
@Rust Security Auditor run release security audit
```

Expected behavior:

- Call `rust_audit_project`.
- Produce a release-oriented summary, risk level, blocking findings, recommended fixes, and manual-review items.
- State that the scan is heuristic and local, not a proof of security.
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
- Review Cargo git/path dependencies and build dependencies for supply-chain trust.

False positives / suppressions:
- If a finding is intentional and reviewed, use a narrow inline suppression for the specific rule id with a reason.

Release recommendation:
- Do not release until high-severity findings are resolved. This result is a heuristic audit, not a formal security proof.
```

## Example 5: Project Check Before Commit

User:

```text
@Rust Security Auditor check this Rust project before commit
```

Expected behavior:

- Call `rust_review_current_diff`.
- Treat `critical` and `high` findings as commit blockers.
- Treat `medium` findings as context-dependent.
- Keep the output scoped to security, not style.

Expected Codex response shape:

```text
Overall risk: pass

Blocking issues:
- None.

Manual review needed:
- None returned by the tool.

Commit recommendation:
- The security diff review does not block this commit. This is not a complete security proof.
```

## Example 6: Project Check Before Release

User:

```text
@Rust Security Auditor check this Rust project before release
```

Expected behavior:

- Call `rust_audit_project`.
- Treat high and critical findings as release blockers.
- List medium and low-confidence findings as manual release checklist items.
- Include the overall risk level and release recommendation.

Expected Codex response shape:

```text
Overall risk: warning

Blocking issues:
- None.

Manual review needed:
- Medium findings require owner confirmation before release.

Release recommendation:
- Release can proceed only after manual-review items are accepted. The scan is heuristic and local.
```

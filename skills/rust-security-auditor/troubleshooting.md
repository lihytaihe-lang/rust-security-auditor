# Rust Security Auditor Troubleshooting

Use this when Codex cannot start the MCP server, cannot see tools, or receives unexpected tool output.

## MCP Client Cannot Start Or Parse Server Output

Check the configured command:

```json
{
  "command": "npm",
  "args": ["--silent", "run", "mcp"],
  "cwd": "/absolute/path/to/rust-security-auditor"
}
```

MCP stdio reserves stdout for JSON-RPC protocol messages. Plain `npm run mcp` can print npm lifecycle banners to stdout and corrupt initialization. Normal logs must not be written to stdout; diagnostics should use stderr or structured MCP tool responses.

## Tools Are Not Visible

Run local validation from the MCP server repository:

```bash
npm run typecheck
npm test
```

Then restart Codex or the MCP client so it reloads the server and tool list. The expected tools are:

- `rust_audit_project`
- `rust_audit_unsafe`
- `rust_audit_dependencies`
- `rust_review_current_diff`
- `rust_list_accepted_risks`

## PROJECT_PATH_NOT_FOUND

Pass an absolute local project path or ensure the MCP client sends `projectPath` relative to the intended working directory. Do not use URLs or uploaded package references.

## PROJECT_PATH_NOT_RUST_PROJECT

Use a local Cargo project or workspace directory containing at least one `Cargo.toml`. If scanning a workspace member, prefer the workspace root when the user asks for project or release audit.

## Current Diff Shows No Affected Files

For `rust_review_current_diff`, confirm that:

- The project path is inside a Git work tree.
- There are staged, unstaged, untracked, or explicit `baseRef`/`headRef` changes.
- The changed paths are inside the Rust project directory.

Remember that current diff review is file-level. It scans findings in diff-affected files; it does not prove changed line ranges are safe.

## Findings Look Noisy

Interpret findings using both severity and confidence. Low-confidence findings are manual-review targets, not confirmed vulnerabilities. If code is intentionally risky and reviewed, recommend a narrow inline suppression for the specific `ruleId` only when the user asks how to handle accepted noise or the tool returns `recommendedAction: "suppress_if_accepted"`.

For generated Markdown, keep `pathMode: "relative"` unless the user explicitly wants local absolute paths. For `rust_audit_project`, `rust_audit_unsafe`, and `rust_audit_dependencies`, use `reportMode: "compact"` for day-to-day developer handoff and `reportMode: "full"` only when complete evidence, suggested fixes/tests, or suppression details are needed. Compact reports keep JSON findings complete; they only shorten the Markdown.

## Suppression Is Missing Or Ignored

Use the formal accepted-risk format:

```rust
// rust-security-auditor: ignore RULE_ID -- reason
// rust-security-auditor: ignore RULE_ID owner=@name ticket=SEC-123 until=YYYY-MM-DD -- reason
```

The reason after `--` is required. The rule id must be exact; broad `ignore all` or `ignore *` is not supported. If the directive is missing a reason or uses unsupported metadata, the finding is shown and the result includes `invalidSuppressionCount` plus an `invalidSuppression` explanation in `suppressedFindings`.

## Expired Suppression Reappeared

This is expected. When `until=YYYY-MM-DD` is before the current date, the suppression is no longer active, the finding is shown again, `expiredSuppressionCount` increases, and `rust_review_current_diff.reviewDecision.status` is at least `needs_attention`. Review the risk again, fix the code, or explicitly renew the accepted-risk record with a fresh reason and tracking metadata.

## Accepted Risk Inventory Looks Incomplete

`rust_list_accepted_risks` only scans Rust source files under `projectPath` for `rust-security-auditor` suppression comments. It does not run full scanner rules, so it can list suppression records that are not currently attached to a finding. Pass `includeExpired: true` to show expired suppressions and `includeInvalid: true` to show invalid suppressions.

## User Asks For A Full Security Guarantee

State the limit clearly: Rust Security Auditor is a heuristic local scanner. It does not perform formal verification, symbolic execution, full semantic Rust parsing, or complete supply-chain attestation.

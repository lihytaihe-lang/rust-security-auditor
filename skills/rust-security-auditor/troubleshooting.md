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

Interpret findings using both severity and confidence. Low-confidence findings are manual-review targets, not confirmed vulnerabilities. If code is intentionally risky and reviewed, recommend a narrow inline suppression for the specific `ruleId` only when the user asks how to handle accepted noise.

## User Asks For A Full Security Guarantee

State the limit clearly: Rust Security Auditor is a heuristic local scanner. It does not perform formal verification, symbolic execution, full semantic Rust parsing, or complete supply-chain attestation.

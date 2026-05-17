# Contributing

Thanks for helping improve Rust Security Auditor. The project is currently a local MCP first public preview, so contributions should stay focused on local scanning quality, documentation, examples, CI, and maintainability.

## Run Checks

```bash
npm install
npm run typecheck
npm test
git diff --check
```

Use `npm --silent run mcp` when validating stdio MCP startup. Use `npm run mcp:call -- <tool> ...` for local tool-handler debugging.

## Add Or Update A Rule

Keep rules small, security-specific, and evidence-driven.

1. Add or update rule metadata in `src/scanners/rules.ts`.
2. Implement the scanner behavior in the narrowest relevant scanner module.
3. Return concrete file, line, evidence, severity, confidence, and remediation guidance.
4. Prefer medium or low confidence when the scanner cannot prove the surrounding invariant.
5. Add focused tests that cover both noisy and positive cases.
6. Update README and Skill docs when user-visible behavior changes.

Do not add broad generic code review rules, style rules, or large scanner families as part of a small change.

## Add A Fixture

Fixtures live under `test/fixtures/`.

1. Use minimal Cargo projects that demonstrate one behavior.
2. Keep paths relative and synthetic.
3. Do not include private source code, real customer names, real internal paths, credentials, or tokens.
4. Add tests in `test/*.test.ts` that assert stable rule IDs or stable summary behavior.
5. If a fixture affects public examples, regenerate or update `examples/reports/` with sanitized output.

## Submit An Issue

When reporting a bug or false positive, include:

- Tool name.
- Project shape, for example workspace or single crate.
- Minimal code snippet or fixture.
- Actual output.
- Expected output.
- Whether the finding was introduced by diff review or a full project scan.

For security-sensitive reports, follow `SECURITY.md` instead of opening a public issue.

# Contributing

Thanks for helping improve Rust Security Auditor. The project is currently a local MCP first public preview, so contributions should stay focused on local scanning quality, documentation, examples, CI, and maintainability.

## Run Checks

```bash
npm ci
npm run check     # typecheck + test + whitespace
```

Use `npm --silent run mcp` when validating stdio MCP startup. Use `npm run mcp:call -- <tool> ...` for local tool-handler debugging.

## Add Or Update A Rule

Keep rules small, security-specific, and evidence-driven.

1. Add or update rule metadata in `src/scanners/rules.ts`.
2. Implement the scanner behavior in the narrowest relevant scanner module:
   - `unsafeScanner.ts` — unsafe, FFI, and raw-memory patterns in Rust source.
   - `dependencyScanner.ts` — `Cargo.toml`, `Cargo.lock`, `build.rs`, `.cargo/config.toml`.
   - `sourceRiskScanner.ts` — shipped-code risk that is neither unsafe nor Cargo metadata.
3. Match against the masked view from `maskRustSource`, never the raw line. `withoutLiterals` is the default; use `withoutComments` only when the pattern legitimately lives inside a string, such as an ABI name. Matching a raw line reintroduces findings inside comments and doc examples.
4. Return concrete file, line, evidence, severity, confidence, and remediation guidance.
5. Confidence describes pattern-detection certainty, not exploitability. Prefer medium or low when the pattern itself is ambiguous, not when the risk is uncertain.
6. Add focused tests covering a true positive, a comment/literal near-miss, and a plausible false positive.
7. Update the README rule list and the Skill docs when user-visible behavior changes, and add a CHANGELOG entry.

Do not add broad generic code review rules, style rules, or large scanner families as part of a small change.

### Rule Id Prefixes

| Prefix | Scope |
| --- | --- |
| `RSA-UNSAFE-` | Unsafe blocks, functions, and raw-memory primitives |
| `RSA-FFI-` | Foreign function interface boundaries |
| `RSA-DEP-` | Dependency declarations and resolution |
| `RSA-BUILD-` | Build scripts and build-time execution |
| `RSA-CARGO-` | Cargo configuration outside the manifest |
| `RSA-EXEC-` | Process execution in shipped code |

Rule ids are a public interface: users write them into suppression comments. Renaming one is a breaking change.

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

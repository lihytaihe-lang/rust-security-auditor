# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [semantic versioning](https://semver.org/) — while it is pre-1.0, breaking changes may land in a minor release.

## [0.1.2] - 2026-08-11 (publication status: owner verification required)

Local package metadata is `0.1.2`. npm publication, Git tag, release, and prior artifact facts have not been independently verified in this working tree; do not treat this entry as a publication claim.

### Security hardening in the current working tree

- Security directives and `SAFETY:` notes now consume only lexically confirmed Rust comments. Strings, raw/byte strings, character literals, identifiers, and attributes cannot forge those semantics.
- Source reads now share bounded, root-contained, no-symlink sessions with structured coverage. They verify canonical containment and file identity before and after open, then read no more than the opened descriptor's verified size. Current diff decisions fail closed whenever a required Rust/Cargo input is incomplete.
- Recursive discovery now revalidates directory containment after open and caps directory-only traversal; a later optional context read cannot erase an earlier incomplete current-diff coverage receipt.
- Rule-to-tool placement uses explicit `toolScopes`, not rule-id prefixes; Cargo source replacement and runner findings appear in dependency review.
- v0.1.x packaging removes the hosted runtime from bins, scripts, public exports, build output, and tarballs. The local release verifier creates a real tarball, scans it, installs it fresh, and runs the installed stdio binary.

### Fixed

- **The installed executable did nothing.** The entry-point check compared `process.argv[1]` against `import.meta.url` without resolving symbolic links, so the server started and exited silently whenever it was launched through a linked binary — which is how npm, `npx`, and `npm link` all invoke it. Now resolved with `realpath` on both sides ([`src/utils/paths.ts`](src/utils/paths.ts)).
- The version advertised over MCP (`0.1.0`) no longer drifts from the package version; both come from `src/version.ts` and a test keeps them equal.
- Patterns inside block comments, doc examples, and string literals are no longer reported as findings. The scanner now tracks Rust comment and literal boundaries, including nested block comments, raw strings, byte strings, and char literals versus lifetimes ([`src/scanners/rustLexer.ts`](src/scanners/rustLexer.ts)).
- Unterminated Rust literals now disable test-only severity reductions and mark scan coverage incomplete, so a forged `#[cfg(test)]` cannot turn a production-risk finding into a passing current-diff review.
- Accepted-risk inventory output now includes structured scan coverage and warnings; unreadable or linked source cannot be represented as an empty inventory.
- Artifact privacy checks now redact and detect common temporary, root, and service POSIX directories as well as drive-root Windows paths.
- A `use std::process::Command;` import no longer counts as command execution.
- Trailing `#` comments in `Cargo.toml` are stripped before matching, so a commented-out `git = ...` no longer produces a finding.

### Added

- **Primary package binary.** Package metadata exposes `rust-security-auditor` as its primary local stdio binary. A registry installation command is intentionally omitted here until publication is owner-verified.
- **Nine new rules:**
  - `RSA-UNSAFE-GET-UNCHECKED` — `get_unchecked` / `get_unchecked_mut` bounds-check removal.
  - `RSA-UNSAFE-UNCHECKED-CALL` — other `*_unchecked` APIs such as `from_utf8_unchecked` and `unwrap_unchecked`.
  - `RSA-UNSAFE-STATIC-MUT` — `static mut` declarations.
  - `RSA-UNSAFE-RAW-PTR-ACCESS` — `copy_nonoverlapping`, `ptr::read`/`write`/`copy`, `write_bytes`, volatile access.
  - `RSA-FFI-CSTR-FROM-PTR` — `CStr::from_ptr` and `CString::from_raw`.
  - `RSA-EXEC-COMMAND` — process execution in shipped code, not just build scripts.
  - `RSA-DEP-VERSION-UNBOUNDED` — wildcard and `>=`-only dependency requirements.
  - `RSA-CARGO-SOURCE-REPLACEMENT` — registry source replacement in `.cargo/config.toml`.
  - `RSA-CARGO-RUNNER` — custom target runners in `.cargo/config.toml`.
- **Broad audits are scoped to what Cargo builds.** `rust_audit_project`, `rust_audit_unsafe`, and `rust_audit_dependencies` read each crate's `src/` and `build.rs`, and skip test/benchmark/example targets plus `.rs` files no Cargo target reaches. Every report states how many files were skipped and why; `includeNonShippedSources` scans them anyway. `rust_review_current_diff` never applies the filter, because a changed test target was changed on purpose. On `BurntSushi/memchr` a default audit drops from 1,721 findings to 396, with the removed set almost entirely one 1.6 MB benchmark input file.
- `.cargo/config.toml` and `.cargo/config` are now discovered and scanned.
- Findings inside `#[cfg(test)]` and `#[test]` items are reported at reduced severity with an explanatory note, so test-only code does not drive a release gate.
- File discovery reports what it skipped: oversized files, unfollowed symbolic links, unreadable directories, and truncation at the file-count cap. Previously these were silent.
- CI now runs on Node 20, 22, and 24, across Linux, macOS, and Windows, plus a CodeQL analysis workflow and `npm audit`.

### Changed

- **The suppression marker is now `rust-security-auditor:`.** The previous `rustsec-auditor:` marker collides with the unrelated [RustSec](https://rustsec.org) project. Existing comments keep working, and the scanner warns when it sees the deprecated form. Suggested suppression snippets use the new marker.
- Per-file size (2 MiB) and total file count (50,000) limits now bound a scan, so pointing the tool at an unexpectedly large directory cannot stall the MCP client.
- `npm test` no longer depends on `find` and `xargs`, so it runs identically on Windows.
- Internal planning and stage-tracking documents moved to `docs/internal/`.
- README rewritten to lead with installation and capabilities; `SECURITY.md` now points at GitHub private vulnerability reporting and states what is in and out of scope.

### Known Limitations

- No RustSec advisory database or CVE lookup. Run `cargo audit` or `cargo deny` for known-vulnerability coverage.
- Rules are line-based patterns with lexical context, not AST, data-flow, or taint analysis.

## [0.1.1] - 2026-08-11

- Local stdio MCP server with five read-only tools.
- Heuristic scanner kernel for unsafe/FFI, Cargo dependency, and build-script review.
- Changed-line-aware current diff review with review decisions.
- Accepted-risk suppression workflow and inventory tool.
- Markdown and JSON reports with compact and full modes.
- Historical hosted experiment; it is deliberately absent from the current v0.1.x source, exports, build output, and package boundary.

## [0.1.0] - 2026-08-11

- Initial local MCP preview.

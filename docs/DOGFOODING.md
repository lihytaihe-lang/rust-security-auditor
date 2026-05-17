# Dogfood Validation

Date: 2026-05-17

This validation used the current repository fixtures and the local MCP debug helper. It did not add scanner features, change scanner rules, upload code, create a ChatGPT App/SaaS flow, or enter deep audit mode.

## Test Environment

- OS: macOS Darwin 25.4.0 arm64
- Node.js: v25.9.0
- npm: 11.12.1
- Git: 2.50.1
- Invocation path: local `dist/src/mcp/debug.js` after `npm run build`
- Raw output handling: reviewed locally from temporary files under `/tmp`; no raw private paths are committed here

## Test Targets

- `test/fixtures/vulnerable-rust-project`
  - Used for `rust_audit_project` and `rust_audit_unsafe`.
  - Contains unsafe functions, unsafe blocks, unsafe Send/Sync impls, FFI, raw memory primitives, a build script, a git dependency, a path dependency, and proc-macro config.
- `test/fixtures/dependency-risk`
  - Used for `rust_audit_dependencies`.
  - Contains build-script, git/path dependency, lockfile git source, proc-macro, and build-dependency signals.
- `test/fixtures/suppressed-rust-project`
  - Used for `rust_list_accepted_risks`.
  - Contains active, expired, and invalid `rustsec-auditor` suppression comments.
- Temporary git copy of `test/fixtures/vulnerable-rust-project`
  - Used for `rust_review_current_diff`.
  - Baseline was committed, then this function was appended to `src/lib.rs` to create a working-tree diff:

```rust
pub fn dogfood_added(ptr: *const u8) -> u8 {
    unsafe { *ptr }
}
```

## Test Commands

```bash
npm run build

node dist/src/mcp/debug.js rust_audit_project \
  --projectPath test/fixtures/vulnerable-rust-project \
  --outputFormat markdown

node dist/src/mcp/debug.js rust_audit_unsafe \
  --projectPath test/fixtures/vulnerable-rust-project \
  --outputFormat markdown

node dist/src/mcp/debug.js rust_audit_dependencies \
  --projectPath test/fixtures/dependency-risk \
  --outputFormat markdown

DIFF_ROOT=$(mktemp -d /tmp/rsa-diff.XXXXXX)
DIFF_REPO="$DIFF_ROOT/vulnerable-rust-project"
cp -R test/fixtures/vulnerable-rust-project "$DIFF_REPO"
git -C "$DIFF_REPO" init --quiet
git -C "$DIFF_REPO" config user.email dogfood@example.invalid
git -C "$DIFF_REPO" config user.name "Dogfood Validation"
git -C "$DIFF_REPO" add .
git -C "$DIFF_REPO" commit -m baseline --quiet
perl -0pi -e 's/\z/\n\npub fn dogfood_added(ptr: *const u8) -> u8 {\n    unsafe { *ptr }\n}\n/' "$DIFF_REPO/src/lib.rs"

node dist/src/mcp/debug.js rust_review_current_diff \
  --projectPath "$DIFF_REPO" \
  --outputFormat markdown

node dist/src/mcp/debug.js rust_list_accepted_risks \
  --projectPath test/fixtures/suppressed-rust-project \
  --includeExpired true \
  --includeInvalid true \
  --outputFormat markdown
```

Extra sanity check:

```bash
node dist/src/mcp/debug.js rust_audit_project \
  --projectPath test/fixtures/safe-rust-project \
  --outputFormat markdown
```

Result: `test/fixtures/safe-rust-project` returned 0 findings and `riskLevel: pass`.

## Tool Experience

### `rust_audit_project`

- Target: `test/fixtures/vulnerable-rust-project`
- Result: 21 findings, `riskLevel: high_risk`
- Severity mix: 1 high, 19 medium, 1 low
- Category mix: 12 unsafe, 1 FFI, 1 dependency, 4 supply-chain, 1 command-execution, 2 concurrency
- Confidence mix: all 21 findings were high confidence
- Markdown size: about 17k characters

Experience conclusion:

- Output is clear and deterministic. The summary, severity grouping, locations, evidence, why-it-matters, risk scenario, suggested fix, and suggested tests are all useful.
- Finding volume is noisy for a broad project scan. It is suitable for release or checkpoint review, but too long for a quick developer handoff.
- Severity mostly feels reasonable: build-script command execution as high; unsafe and supply-chain review clues as medium; path dependency as low.
- Confidence is syntactically reasonable but semantically too strong. "High confidence" means the text pattern was found, not that the issue is exploitable.
- `suggestedFixPrompt` is not present for this tool. It provides `suggestedFix`, but not the Codex-ready prompt shape used by diff review.
- Markdown can be given to a developer, but it includes many empty severity sections and repeated full finding blocks. It needs a condensed mode for routine use.
- No exact duplicate finding IDs or same-rule same-location duplicates were observed.
- Main repeated-noise pattern: one unsafe line can produce both a generic `RSA-UNSAFE-BLOCK` and a more specific primitive finding such as `RSA-UNSAFE-TRANSMUTE` or `RSA-UNSAFE-SET-LEN`. This is explainable, but it increases review load.
- Possible false-positive or wording issue: `RSA-DEP-PROC-MACRO` triggers on the scanned crate's own `[lib] proc-macro = true`. That is a valid compilation trust-boundary clue, but the "dependency" framing can read oddly when the crate itself is the proc macro.
- No obvious fixture-level false negatives were found.

### `rust_audit_unsafe`

- Target: `test/fixtures/vulnerable-rust-project`
- Result: 15 findings, `riskLevel: needs_attention`
- Severity mix: 15 medium
- Category mix: 12 unsafe, 1 FFI, 2 concurrency
- Confidence mix: all 15 findings were high confidence
- Markdown size: about 12k characters

Experience conclusion:

- This was the clearest focused scanner for unsafe Rust review. It avoids dependency/build noise and keeps the reviewer inside one domain.
- Findings are not too noisy for an unsafe-specific pass, although the generic unsafe-block findings plus specialized raw-memory findings create some double-review pressure.
- Medium severity is defensible for heuristic unsafe review because the tool cannot prove exploitability. It still catches high-risk constructs such as `Box::from_raw`, `set_len`, `transmute`, and `from_raw_parts`.
- Confidence has the same issue as project audit: high confidence is correct for text detection, but a developer could read it as high confidence of vulnerability.
- `suggestedFixPrompt` is not present. The report has useful `suggestedFix` text, but no direct prompt handoff.
- Markdown is developer-readable, but the full template is long for 15 findings. A compact unsafe checklist would improve day-to-day usefulness.
- No exact duplicates were observed. No obvious fixture-level false negatives were found.

### `rust_audit_dependencies`

- Target: `test/fixtures/dependency-risk`
- Result: 7 findings, `riskLevel: high_risk`
- Severity mix: 1 high, 5 medium, 1 low
- Category mix: 1 dependency, 5 supply-chain, 1 command-execution
- Confidence mix: all 7 findings were high confidence
- Markdown size: about 6.3k characters

Experience conclusion:

- Best overall signal-to-noise among the broad scanners. The output is short enough to hand directly to a Rust maintainer.
- Severity feels right: shelling out from `build.rs` is high; build scripts, git dependencies, proc macros, build dependencies, and lockfile git sources are medium; path dependency is low.
- Confidence is acceptable as pattern confidence, but still needs wording that these are supply-chain review clues, not automatically vulnerabilities.
- `suggestedFixPrompt` is not present. `suggestedFix` and suggested tests are practical.
- Markdown is suitable for direct developer review.
- Minor duplication: Cargo manifest git dependency and Cargo.lock git source are separate findings for the same dependency risk. This is usually helpful, but could be grouped in a summary.
- No obvious false negatives were found for the fixture.

### `rust_review_current_diff`

- Target: temporary git copy of `test/fixtures/vulnerable-rust-project`
- Diff: appended one function containing an unsafe block
- Result: 3 visible findings, `riskLevel: needs_attention`
- Review decision: `needs_attention`, `safeToCommit: false`
- Diff relations: 1 introduced finding, 2 near-changed-line findings
- Hidden pre-existing findings: 13
- Severity mix: 3 medium
- Confidence mix: all 3 findings were high confidence
- Markdown size: about 3k characters

Experience conclusion:

- Best developer-facing report shape. It leads with a decision, safe-to-commit flag, changed files, blocking/manual-review sections, hidden pre-existing count, limitations, and suggested Codex fix prompts.
- The changed-line heuristic worked: it surfaced the newly added unsafe block and hid most unrelated historical findings.
- The largest noise source in the whole validation came from the changed-line window. Because the new function was appended near an existing unsafe function, diff review also surfaced `RSA-UNSAFE-FN` and `RSA-UNSAFE-BOX-FROM-RAW` from nearby pre-existing code. The report marks them as `near_changed_lines`, but a developer may still experience them as unrelated noise.
- Severity and confidence are reasonable for the three findings, but again "high confidence" is pattern confidence.
- `suggestedFixPrompt` is present and usable. The prompts are safe and correctly ask Codex to review before fixing. They are generic, though; they do not include the rule-specific suggested fix or changed-line context.
- Markdown is the most suitable report for direct developer use.
- No exact duplicates were observed.
- Potential privacy issue: Markdown includes the absolute `Scope` path. That is fine locally, but reports intended for sharing should support path sanitization or relative scope output.

### `rust_list_accepted_risks`

- Target: `test/fixtures/suppressed-rust-project`
- Result: 6 accepted-risk records
- Inventory mix: 4 active, 1 expired, 1 invalid
- Rule mix: all `RSA-UNSAFE-BLOCK`
- Owner mix: 5 missing owners, 1 `@security`
- Markdown size: about 2k characters

Experience conclusion:

- This is one of the best tools in the set. The output is concise, clear, and directly useful before release or cleanup.
- Severity and confidence are not applicable because this is an inventory, not a scanner result.
- `suggestedFixPrompt` is not applicable. The "Recommended Actions" section is useful enough for this tool's purpose.
- Markdown is suitable for direct developer/security review.
- No obvious false positives were observed. The invalid suppression was correctly identified as missing a reason after `--`; the expired suppression was correctly separated.
- Minor readability issue: active-risk lines are dense because they include raw comments inline. This is acceptable at 6 records but may get heavy in a larger project.

## Cross-Tool Findings

1. Non-diff tools do not expose `suggestedFixPrompt`.
   - `rust_audit_project`, `rust_audit_unsafe`, and `rust_audit_dependencies` provide `suggestedFix`, but not Codex-ready prompt text.
   - `rust_list_accepted_risks` does not need the same field, but could eventually provide cleanup prompts for expired/invalid suppressions.

2. Confidence currently reads as vulnerability confidence.
   - All scanner findings in this validation were high confidence.
   - For these heuristics, high confidence usually means "the syntactic signal was found." Reports should make that distinction explicit.

3. The broad project report is long for developer handoff.
   - `rust_audit_project` produced 21 findings and about 17k markdown characters.
   - It is complete, but a concise mode or grouped summary would improve routine use.

4. Generic unsafe findings create review noise when paired with specific unsafe primitives.
   - Examples: generic `RSA-UNSAFE-BLOCK` plus `RSA-UNSAFE-TRANSMUTE`, `RSA-UNSAFE-SET-LEN`, or `RSA-UNSAFE-FROM-RAW-PARTS` on the same line.
   - These are not exact duplicates, but the UX should present them as a grouped unsafe site.

5. Diff review is the right daily workflow, but the near-line window is the biggest noise source.
   - The 5-line window intentionally catches surrounding context, but it can surface untouched pre-existing findings near an append-only change.
   - The report does explain `near_changed_lines` and hidden pre-existing findings, which helps.

6. Markdown reports include absolute project paths.
   - That is useful locally but can leak private path details when pasted into issues, PRs, or docs.
   - Future shared reports should offer path redaction or relative scope display.

7. The safe fixture sanity check passed.
   - `test/fixtures/safe-rust-project` returned no findings and `riskLevel: pass`.

## Phase 10 Recommendation

Recommended direction: continue optimizing diff review first, with small AST-aware parsing work used only where it directly reduces diff-review noise.

Rationale:

- The best current user experience is `rust_review_current_diff`.
- The largest practical pain is not missing a release-audit feature; it is deciding which findings matter for the current change.
- AST-aware parsing would help, but it should be scoped to UX precision:
  - group unsafe sites by enclosing function/block,
  - distinguish newly added unsafe operations from merely nearby old unsafe code,
  - attach rule-specific prompt context,
  - reduce generic unsafe-block duplication when a specific primitive finding exists.
- Full release audit should wait until the daily diff-review loop and accepted-risk inventory are tighter. `rust_list_accepted_risks` is already strong enough to support release preparation as-is.

Suggested Phase 10 priority order:

1. Improve diff-review actionability and noise controls.
2. Add minimal AST-aware context where it improves diff relation, grouping, and prompt quality.
3. Add path-redaction or relative-scope report options.
4. Add compact/grouped markdown modes for project and unsafe audits.
5. Defer larger release-audit workflows until the above surfaces are stable.

## Verification

Passed after this document update:

```bash
npm run typecheck
npm test
```

- `npm run typecheck`: passed
- `npm test`: passed, 41 tests passed

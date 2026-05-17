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
   - At the time of the initial dogfood run, the wider near-line window intentionally caught surrounding context, but it could surface untouched pre-existing findings near an append-only change.
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
- `npm test`: passed, 47 tests passed

## Phase 10 Follow-up

Phase 10 implemented the dogfood recommendations for daily diff review without adding ChatGPT App, SaaS, upload, deep-audit, release-gate, broad scanner-rule, or scanner-kernel work.

Implemented polish:

- `rust_review_current_diff` defaults Markdown to `pathMode: "relative"` so shareable reports do not include local absolute project paths. JSON still returns the resolved `projectPath`.
- `reportMode` now defaults to `compact` for Codex / PR comments, with `full` available for changed-file lists, non-blocking notes, accepted/suppressed risk details, and full evidence.
- `nearChangedLineWindow` defaults to `3` and is configurable. `near_changed_lines` now displays only medium-or-higher severity with medium/high confidence.
- Lightweight Rust context extraction identifies approximate functions and unsafe-site ranges using text/brace heuristics. It is used only for diff review precision, grouping, and prompt context.
- Nearby findings in a different function or unsafe site are downgraded to non-blocking context notes; unknown context is still shown with an explicit "near changed code, not necessarily introduced" note.
- Markdown groups findings that share an unsafe site, such as a generic unsafe block plus a specific primitive finding. This is a UX grouping only; JSON findings remain separate.
- `suggestedFixPrompt` now includes rule id, file/line, function context, diff relation, changed-line context, and the rule-specific suggested fix, and asks Codex to explain the invariant before editing.

## Second Dogfood After Phase 10

Date: 2026-05-17

This second dogfood pass validated the Phase 10 diff-review polish only. It did not add scanner rules, change MCP tool behavior, build a ChatGPT App, create SaaS/upload flows, or enter deep-audit/release-gate mode.

### Diff Review Fixtures

Two temporary git copies were used:

1. A focused diff-review fixture with committed baseline Rust code, then a working-tree diff that:
   - inserted `// touched near legacy unsafe` close to an existing `legacy_near` unsafe function;
   - appended `grouped_transmute`, which contains `unsafe { std::mem::transmute(value) }`.
2. A repeat of the earlier dogfood shape using a temporary copy of `test/fixtures/vulnerable-rust-project`, then appending:

```rust
pub fn dogfood_added(ptr: *const u8) -> u8 {
    unsafe { *ptr }
}
```

### `rust_review_current_diff`

Focused fixture results:

- Default compact report:
  - Result: 4 visible findings, `riskLevel: needs_attention`, `safeToCommit: false`.
  - Diff relations: 2 `introduced_by_diff`, 2 `near_changed_lines`, 2 hidden pre-existing findings.
  - Defaults confirmed: `reportMode: compact`, `pathMode: relative`, `nearChangedLineWindow: 3`.
  - Markdown size: about 4.1k characters.
  - Markdown did not contain the temporary absolute repo path; scope rendered as `.` and locations rendered as `src/lib.rs`.
- Explicit `pathMode=relative`:
  - Same result as default.
  - Markdown still did not contain the temporary absolute repo path.
- `reportMode=full`:
  - Same finding set as default.
  - Markdown size: about 6.8k characters.
  - Included `Changed Files`, `Non-blocking Notes`, full evidence, and full recommendation details.
  - Still used relative paths in Markdown.
- Default `nearChangedLineWindow=3`:
  - Correctly surfaced the newly introduced transmute unsafe site.
  - Also surfaced two nearby legacy findings from `legacy_near`.
- `nearChangedLineWindow=1`:
  - Result: 2 visible findings, both `introduced_by_diff`.
  - `near_changed_lines` dropped to 0.
  - Hidden pre-existing findings increased to 4.
- `nearChangedLineWindow=0`:
  - Same visible result as window 1 for this fixture: only the introduced transmute unsafe site remained.
- `introduced_by_diff` finding:
  - Confirmed on `RSA-UNSAFE-BLOCK` and `RSA-UNSAFE-TRANSMUTE` at the appended transmute line.
- `near_changed_lines` finding:
  - Confirmed on the nearby legacy unsafe function and unsafe block when the window remained at the default 3.
- Unsafe site grouping:
  - Confirmed: the generic unsafe block and the transmute-specific finding were grouped into one `Unsafe site at src/lib.rs:39`.
  - The grouped output reduced duplicate reading pressure for the newly introduced unsafe site.
- `suggestedFixPrompt`:
  - Confirmed for each visible diff finding.
  - Prompts now include rule id, relative location, function context, diff relation, nearest changed line, and the rule-specific suggested fix.

Earlier-style vulnerable fixture repeat:

- Default compact report:
  - Result: 3 visible findings, `riskLevel: needs_attention`, `safeToCommit: false`.
  - Diff relations: 1 `introduced_by_diff`, 2 `near_changed_lines`, 13 hidden pre-existing findings.
  - Markdown did not contain the temporary absolute repo path.
  - The nearby old `take` findings were grouped into one unsafe site: `RSA-UNSAFE-FN` plus `RSA-UNSAFE-BOX-FROM-RAW`.
- `nearChangedLineWindow=1`:
  - Result: 1 visible finding, the introduced unsafe block in `dogfood_added`.
  - `near_changed_lines` dropped to 0.
  - Hidden pre-existing findings increased to 15.

### Phase 10 Experience Comparison

- Absolute paths in Markdown:
  - Fixed for diff review. Markdown now uses `Scope: .` and relative locations such as `src/lib.rs:39`.
  - JSON still includes the resolved `projectPath`, which is useful for tool consumers and was not pasted into Markdown.
- Compact report for PR comments:
  - Better than the earlier full finding template. It leads with the decision, summary, grouped review items, prompts, and limitations.
  - It omits evidence blocks by default, which makes it more suitable for PR comments. `reportMode=full` remains available when a reviewer needs evidence and recommendation detail.
- `near_changed_lines` noise:
  - Improved in controllability, but not fully solved by the default window.
  - In both temporary diff shapes, the default window of 3 can still surface nearby legacy unsafe findings when a change is adjacent to old unsafe code.
  - `nearChangedLineWindow=1` or `0` made the reports much quieter and preserved the introduced findings.
  - The remaining rough edge is lightweight Rust context: some nearby findings are still classified with unknown function/site matching, so they stay as manual-review items rather than clearly non-blocking context.
- Unsafe site grouping:
  - Helpful. It grouped generic unsafe findings with specific primitive findings at the same site, including `RSA-UNSAFE-BLOCK` plus `RSA-UNSAFE-TRANSMUTE`, and the earlier-style `take` unsafe site.
  - This reduces repeated reading pressure, especially when generic unsafe-block findings overlap with more specific primitive rules.
- `suggestedFixPrompt`:
  - More usable than before. The prompts are now specific enough to hand back to Codex without restating the rule, location, relation, or likely repair direction.
  - Remaining issue: prompts are still one per finding, not one per unsafe-site group. A grouped prompt could be less repetitive.
- Remaining issues:
  - Default diff review can still feel noisy when the changed line is adjacent to pre-existing unsafe code.
  - Prompt volume grows with findings even when Markdown groups them.
  - Non-diff audits remain verbose for day-to-day use.
  - The minimal Rust context heuristic is useful, but the remaining false/noisy cases suggest AST-aware context may eventually be worth a spike.

### Other Tool Smoke Tests

- `rust_audit_project` on `test/fixtures/vulnerable-rust-project`: normal, 21 findings, `riskLevel: high_risk`.
- `rust_audit_unsafe` on `test/fixtures/vulnerable-rust-project`: normal, 15 findings, `riskLevel: needs_attention`.
- `rust_audit_dependencies` on `test/fixtures/dependency-risk`: normal, 7 findings, `riskLevel: high_risk`.
- `rust_list_accepted_risks` on `test/fixtures/suppressed-rust-project` with expired and invalid records included: normal, 6 records total, with 4 active, 1 expired, and 1 invalid.

### Phase 11 Verification

Passed after this document update:

```bash
npm run typecheck
npm test
git diff --check
```

- `npm run typecheck`: passed.
- `npm test`: passed, 47 tests passed.
- `git diff --check`: passed.

### Phase 12 Recommendation

Recommended direction: **A. Phase 12 should continue optimizing diff review / minimal Rust context.**

Rationale:

- Phase 10 clearly improved path privacy, PR-comment compactness, unsafe-site grouping, and Codex-ready prompts.
- The remaining highest-friction issue is still diff-review noise from `near_changed_lines` when a small change lands next to legacy unsafe Rust.
- Before adding compact modes for non-diff audits or a release audit report, Phase 12 should tighten minimal Rust context enough to better distinguish "same unsafe site/function" from merely nearby old code, and consider grouped prompts per unsafe site.

Fallback option if that work proves too heuristic-heavy: **D. AST-aware Rust parsing spike** focused only on diff-review context precision, not broad scanner-rule expansion.

## Phase 12 Diff Review Context Precision

Date: 2026-05-17

Phase 12 stayed inside diff-review precision and report UX. It did not add deep-audit gates, ChatGPT App behavior, SaaS/upload flows, broad scanner rules, or full AST/data-flow/taint analysis.

Implemented precision changes:

- `near_changed_lines` is now split into concrete context relations:
  - `same_unsafe_site_context`: finding and added line share the same unsafe block/site.
  - `same_function_context`: finding and added line share the same function, but not the same unsafe site.
  - `nearby_legacy_context`: finding is line-near an added line but lightweight Rust context puts it in a different function or unsafe site.
  - `unrelated_nearby`: finding is line-near an added line but no function or unsafe-site tie was confirmed.
- Compact diff review now shows `introduced_by_diff`, `same_unsafe_site_context`, and medium+ `same_function_context` with medium/high confidence.
- Compact diff review hides `nearby_legacy_context`, `unrelated_nearby`, and low/info context findings by default.
- Full diff review can show legacy nearby context under `Legacy nearby findings hidden by default`, clearly separated from introduced/current-diff sections.
- `reviewDecision` is now primarily driven by `introduced_by_diff`. Same unsafe-site high findings can move the decision to `needs_attention`, but do not hard-block by default. Same-function medium/high findings enter manual review. Nearby legacy context does not affect `safeToCommit` unless `includePreExisting=true`.
- `suggestedFixPrompt` is strong only for `introduced_by_diff` and `same_unsafe_site_context`. `same_function_context` prompts ask for human confirmation first. `nearby_legacy_context` receives only a legacy-context note and no strong repair instruction.

Test coverage added or updated:

- Added unsafe block stays classified as `introduced_by_diff` in compact review.
- Nearby old findings in a different function are hidden from compact review.
- Full report shows legacy nearby context without changing `safeToCommit`.
- Old unsafe in the same function is marked `same_function_context`.
- Old primitive in the same unsafe site is marked `same_unsafe_site_context`.
- Same unsafe-site high findings need attention but do not hard-block.
- Nearby legacy context affects `safeToCommit` only when `includePreExisting=true`.
- Suggested fix prompt for nearby legacy context is not a strong fix prompt.

Verification during Phase 12:

```bash
npm run typecheck
npm test
git diff --check
```

- `npm run typecheck`: passed.
- `npm test`: passed, 53 tests passed.
- `git diff --check`: passed.

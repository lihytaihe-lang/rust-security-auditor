# Stage 2 Progress Alignment

Date: 2026-05-18

This document is the current source of truth for Stage 2 progress. It aligns the ChatGPT planning language, Codex implementation work, and the repository state. It records progress only; this alignment does not add features, change scanner behavior, add hosted MCP scope, add a ChatGPT App UI, or connect private GitHub repositories.

## Current True Stage

The repository is still a v0.1.1 local-first MCP preview, with Stage 2.3 repository-side hosted MCP validation artifacts completed.

Public-release decision as of 2026-08-11: publish v0.1.1 as an open-source local MCP preview. This does not reopen Stage 2.4, Codex plugin packaging, ChatGPT App submission, hosted deployment, private repository scanning, or market-preparation work; those paths remain deferred.

The former next gate was Stage 2.4: a real ChatGPT Developer Mode connection using an HTTPS `/mcp` endpoint. It was attempted on 2026-05-18 with a temporary HTTPS tunnel; the hosted endpoint and smoke validation passed, but ChatGPT connector creation was blocked because the UI did not expose the documented Create connector entry. This gate is now retained only as historical context.

Do not restart Stage 2.4 or proceed to Stage 2.5 without a separate product decision confirming a viable distribution path, maintenance owner, and privacy / hosting plan.

## v0.1.1 Current State

v0.1.1 remains the current package version in `package.json`.

Implemented local preview capabilities:

- Local stdio MCP server for private project review.
- Five local read-only MCP tools:
  - `rust_review_current_diff`
  - `rust_audit_project`
  - `rust_audit_unsafe`
  - `rust_audit_dependencies`
  - `rust_list_accepted_risks`
- Heuristic Rust security scanner kernel.
- Markdown and JSON reports.
- Changed-line-aware diff review.
- Accepted-risk inventory.
- Local debug helper with `npm run mcp:call`.

Implemented hosted prototype capabilities:

- Separate hosted MCP prototype entry point.
- Local Streamable HTTP `/mcp` endpoint for fixture-safe hosted testing.
- Hosted fixture-safe wrappers for four tools:
  - `rust_audit_unsafe`
  - `rust_audit_dependencies`
  - `rust_list_accepted_risks`
  - `rust_review_current_diff` for the bundled fixture diff only
- Hosted outputs with Markdown `content`, `structuredContent`, `outputSchema`, limitations, privacy notes, confidence wording, and suggested next steps.

Important version note: the package is v0.1.1. No v0.2.0 release has been cut by this alignment. The hosted prototype exists in the repo, but it is not a stable hosted product.

## Stage Status

| Stage | Actual status | Alignment decision |
| --- | --- | --- |
| Stage 2.0 | Complete | The design baseline exists in `docs/STAGE2_HOSTED_MCP_DESIGN.md`. |
| Stage 2.1 | Merged | Official-docs research and architecture confirmation are captured inside the design document instead of tracked as a separate completed stage. |
| Stage 2.2 | Merged into Stage 2.3 | The hosted transport spike exists, but progress should now be reported as part of Stage 2.3 repository-side validation. |
| Stage 2.3 | Complete for repository-side validation | Smoke script, local `/mcp` smoke path, tunnel smoke evidence, sample outputs, and submission pack skeleton exist. |
| Stage 2.4 | Attempted but blocked | Local and HTTPS hosted smoke validation passed. Real ChatGPT Developer Mode connection did not complete because the ChatGPT UI did not expose the Create connector entry despite Developer Mode being enabled. |

In plain terms: Stage 2.1 and Stage 2.2 were not clean standalone checkpoints. Their useful outputs were either absorbed into Stage 2.0 design documentation or folded into the completed Stage 2.3 repository-side validation milestone.

## Stage 2.3 Completed Evidence

Completed Stage 2.3 items:

- `scripts/smoke_hosted_mcp.ts` exists.
- `package.json` exposes `npm run smoke:hosted`.
- Hosted `/mcp` local smoke path is documented in `docs/STAGE2_HOSTED_MCP_DESIGN.md`.
- Hosted MCP tests cover health, tool listing, fixture calls, structured output, and privacy guard behavior.
- Temporary HTTPS tunnel smoke evidence is recorded in `docs/STAGE2_HOSTED_MCP_DESIGN.md`.
- Sample hosted outputs exist in `docs/STAGE2_HOSTED_MCP_SAMPLE_OUTPUTS.md`.
- ChatGPT App submission pack skeleton exists in `docs/CHATGPT_APP_SUBMISSION_PACK.md`.

Stage 2.3 should be considered complete only in this limited sense: local repository artifacts and transport-validation evidence are ready for the next ChatGPT-facing validation step. It is not a completed ChatGPT App, public deployment, or private-code product.

## Stage 2.4 Real ChatGPT Developer Mode Validation

Date: 2026-05-18

Endpoint type: temporary HTTPS tunnel for validation only. This was not a stable hosted deployment and should be assumed expired after the validation run.

Local hosted endpoint:

- Server command: `HOSTED_MCP_ALLOWED_HOSTS=rsa-stage24-20260518-2144.loca.lt PORT=8787 HOST=127.0.0.1 npm run mcp:hosted`
- Local port: `8787`
- Local MCP endpoint: `http://127.0.0.1:8787/mcp`
- Local health endpoint: `http://127.0.0.1:8787/healthz`
- `/healthz` reported fixture-safe hosted mode and exactly four hosted tools.

Temporary tunnel:

- Tunnel command: `npx --yes localtunnel --port 8787 --subdomain rsa-stage24-20260518-2144`
- HTTPS MCP endpoint: `https://rsa-stage24-20260518-2144.loca.lt/mcp`
- HTTPS health endpoint: `https://rsa-stage24-20260518-2144.loca.lt/healthz`

Repository-side smoke result:

- Local smoke passed: `npm run smoke:hosted -- --url http://127.0.0.1:8787/mcp`
- HTTPS smoke passed: `npm run smoke:hosted -- --url https://rsa-stage24-20260518-2144.loca.lt/mcp`
- `tools/list` returned exactly:
  - `rust_audit_dependencies`
  - `rust_audit_unsafe`
  - `rust_list_accepted_risks`
  - `rust_review_current_diff`
- Fixture-safe smoke calls succeeded:
  - `rust_audit_unsafe`: `needs_attention`, 9 findings
  - `rust_audit_dependencies`: `high_risk`, 6 findings
  - `rust_list_accepted_risks`: `needs_attention`, 3 findings
  - `rust_review_current_diff`: `needs_attention`, 3 findings
- `structuredContent` shape was valid for the hosted responses, including `tool`, `sourceKind`, `riskLevel`, `summary`, `findings`, `evidenceSnippets`, `limitations`, `suggestedNextSteps`, `confidenceNote`, and `privacy`.
- Smoke privacy guard passed for absolute path, private token, oversized source, and redacted error behavior.

ChatGPT Developer Mode result:

- ChatGPT connection success: No.
- ChatGPT listed hosted tools: No.
- ChatGPT tool calls: None.
- Observed UI state: ChatGPT Settings showed Developer Mode enabled under Advanced settings.
- Blocker: the ChatGPT UI did not expose the documented `Create` / `Create app` connector creation entry in Settings -> Apps / Connectors, the Apps catalog flow, or the composer Sources / Apps flow.
- Endpoint reachability was not the blocker: the HTTPS health endpoint was reachable and the HTTPS smoke script passed.
- Likely failure class: ChatGPT auth, session, UI entitlement, organization setting, feature flag, or current UI limitation around unverified connector creation.
- Screenshot notes: Chrome screenshots showed the Enabled apps modal with no Create button and the Advanced settings modal with Developer Mode enabled.

Privacy check:

- No private GitHub connection was configured.
- No local private project path was submitted to ChatGPT or read by the hosted endpoint.
- No full source upload was performed.
- No user code was saved.
- Hosted output paths remained fixture-relative or sanitized.
- Hosted tools remained fixture-safe.
- Negative smoke checks verified rejection/redaction for absolute paths, private tokens, oversized source, and sensitive error content.

Stage decision:

- Stage 2.4 is not complete because real ChatGPT connector creation, tool listing inside ChatGPT, and ChatGPT-originated tool calls were not achieved.
- Do not enter Stage 2.5 yet.
- Retry Stage 2.4 with an account, organization, or UI session where the Developer Mode Create connector entry is available, then rerun the same temporary HTTPS tunnel and fixture-safe tool-call validation.

## Stage 2.4 Retry Preparation

This preparation pass is documentation-only. It does not add product scope, change scanner behavior, modify hosted MCP tools, build ChatGPT App UI, prepare an OpenAI submission, connect private GitHub, or deploy a stable hosted service.

Current facts from the Stage 2.4 attempt:

- The last hosted MCP endpoint smoke passed for both local and HTTPS tunnel access.
- ChatGPT Developer Mode was enabled.
- The ChatGPT UI did not show the `Create` / `Create app connector` entry.
- ChatGPT tools count = 0.
- Real tool invocation = none.

Retry focus:

- Confirm the ChatGPT account, plan, workspace, session, and Settings surface can expose the connector creation entry before rerunning the full Stage 2.4 validation.
- Keep the HTTPS tunnel endpoint online while creating the connector.
- After connector creation, open a new chat and explicitly select the connector from `+` -> `More`.
- Continue to treat Stage 2.5 as blocked until ChatGPT lists the hosted tools and performs at least one real fixture-backed tool invocation.

## 2026-06-17 Repository-Side Retry Preflight

This pass updated only repository-side readiness for another Stage 2.4 attempt. It did not create a ChatGPT connector, change hosted tool scope, add ChatGPT App UI, connect private GitHub, upload source, or deploy a stable hosted service.

Maintenance result:

- `npm audit` is clean after updating the transitive `hono` package from `4.12.19` to `4.12.25`.
- `npm outdated` is empty after updating `@types/node` from `25.8.0` to `25.9.3`.
- `.zhenvis/` is ignored as a local run artifact so it does not pollute repository status.

Verification result:

- `npm run check` passed, including typecheck, build, 67 tests, and `git diff --check`.
- Local hosted smoke passed against `http://127.0.0.1:8787/mcp`.
- Temporary HTTPS tunnel smoke passed against `https://legal-hotels-sit.loca.lt/mcp`.
- HTTPS `tools/list` returned exactly:
  - `rust_audit_dependencies`
  - `rust_audit_unsafe`
  - `rust_list_accepted_risks`
  - `rust_review_current_diff`
- Fixture-safe HTTPS tool calls succeeded:
  - `rust_audit_unsafe`: `needs_attention`, 9 findings
  - `rust_audit_dependencies`: `high_risk`, 6 findings
  - `rust_list_accepted_risks`: `needs_attention`, 3 findings
  - `rust_review_current_diff`: `needs_attention`, 3 findings
- Smoke privacy guard passed for absolute path, private token, oversized source, and redacted error behavior.

Stage 2.4 status after this preflight:

- Repository-side readiness is still good for another ChatGPT Developer Mode retry.
- The temporary tunnel URL should be treated as expired after the run.
- Real ChatGPT connector creation, ChatGPT tool listing, and ChatGPT-originated fixture tool invocation were not attempted in this pass because they require an authenticated ChatGPT UI session and explicit operator approval.
- Stage 2.5 remains blocked until a real ChatGPT session creates the connector, lists the four hosted tools, and invokes at least one fixture-backed hosted tool.

## Not Completed

The following are explicitly not complete:

- ChatGPT Developer Mode real connection; the 2026-05-18 attempt was blocked by missing connector creation UI.
- ChatGPT App UI component or widget.
- OpenAI app submission.
- Private GitHub access.
- Hosted deployment on a stable public endpoint.
- User authentication or account model.
- Private repository scanning.
- Full-project hosted scan.

Some of these are intentionally out of scope for Stage 2.3 rather than accidental omissions.

## Current Risks

- Stage labels can become misleading because the design document also contains execution notes.
- Tunnel smoke evidence is useful but temporary; it is not the same as a stable hosted deployment.
- ChatGPT Developer Mode behavior remains unverified until an authenticated ChatGPT UI session can create the connector, list the hosted tools, and call a fixture-backed tool.
- Users may assume hosted mode supports real private projects, but it is fixture-safe only.
- Private GitHub access would add a separate auth, token, consent, retention, deletion, and logging burden.
- The hosted prototype is not a complete security audit, SaaS service, or production deployment.
- The package version is v0.1.1 while the hosted prototype is present in the repository, so release notes must be careful not to imply a stable v0.2.0 product.

## Recommended Next Steps

Historical recommendation before the 2026-06-28 pause decision:

1. Keep Stage 2.3 frozen as complete for repository-side validation.
2. Repeat Stage 2.4 as a narrow ChatGPT Developer Mode validation pass once connector creation is available in the ChatGPT UI.
3. Use a temporary HTTPS tunnel or stable development endpoint.
4. Confirm ChatGPT can connect, list exactly the four fixture-safe hosted tools, and call at least one fixture-backed tool.
5. Capture screenshots or notes from the real ChatGPT connection.
6. Update this progress document and the submission pack with successful connection evidence or a new blocker.

Current recommendation after the 2026-08-11 public-preview decision:

1. Support the local MCP preview through reproducible local installation, fixture-backed checks, and issue triage.
2. Keep hosted and private-code paths out of the public preview.
3. Do not start ChatGPT App UI, OpenAI submission, private GitHub access, stable hosted deployment, Codex plugin packaging, or marketplace preparation unless those paths are explicitly reopened.

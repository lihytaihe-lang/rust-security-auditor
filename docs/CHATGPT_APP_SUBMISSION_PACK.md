# ChatGPT App Submission Pack Skeleton

Date: 2026-05-18

Status: archived draft skeleton plus Stage 2.4 validation notes. This is not a submission, does not include a ChatGPT App UI component, and does not connect private GitHub repositories or OpenAI API credentials. The 2026-05-18 real ChatGPT Developer Mode attempt was blocked before connector creation because the ChatGPT UI did not expose the documented Create connector entry.

This document is not an active submission pack or public-release checklist. It is retained only as historical context for the fixture-safe hosted MCP prototype and the blocked ChatGPT Developer Mode validation attempt. The v0.1.1 open-source local MCP preview does not include this submission path.

## App Name Draft

Rust Security Auditor

## App Description Draft

Rust Security Auditor helps developers review Rust security risk signals from fixture-safe demos: unsafe and FFI usage, Cargo dependency and build-script review clues, accepted-risk suppressions, and a hosted fixture diff. It returns Markdown summaries and structured findings with limitations and next steps. The hosted prototype is intentionally limited to bundled demo fixtures and short explicit pasted snippets for selected tools; private project review remains local through the stdio MCP workflow.

Short subtitle draft: Rust review signals

Category draft: Developer Tools

## MCP Server URL Placeholder

`https://<temporary-or-production-host>/mcp`

For local Stage 2.3 tunnel testing, replace the placeholder with the generated HTTPS tunnel URL, for example:

`https://<generated-host>.loca.lt/mcp`

## Screenshots / Tunnel URL Placeholder

- Tunnel URL: `https://<generated-host>/mcp`
- Health URL: `https://<generated-host>/healthz`
- Tool list screenshot: `<add screenshot after ChatGPT Developer Mode or API Playground validation>`
- Fixture call screenshot: `<add screenshot after one successful hosted fixture tool call>`

## Stage 2.4 Real ChatGPT Developer Mode Validation

Date: 2026-05-18

Endpoint type: temporary HTTPS tunnel for validation only. This was not a stable hosted deployment and should be assumed expired after the validation run.

Endpoint evidence:

- Local server command: `HOSTED_MCP_ALLOWED_HOSTS=rsa-stage24-20260518-2144.loca.lt PORT=8787 HOST=127.0.0.1 npm run mcp:hosted`
- Local port: `8787`
- Local MCP endpoint: `http://127.0.0.1:8787/mcp`
- Tunnel command: `npx --yes localtunnel --port 8787 --subdomain rsa-stage24-20260518-2144`
- HTTPS MCP endpoint: `https://rsa-stage24-20260518-2144.loca.lt/mcp`
- HTTPS health endpoint: `https://rsa-stage24-20260518-2144.loca.lt/healthz`

Smoke evidence:

- Local smoke passed: `npm run smoke:hosted -- --url http://127.0.0.1:8787/mcp`
- HTTPS smoke passed: `npm run smoke:hosted -- --url https://rsa-stage24-20260518-2144.loca.lt/mcp`
- Tool list succeeded with exactly four hosted fixture-safe tools:
  - `rust_audit_dependencies`
  - `rust_audit_unsafe`
  - `rust_list_accepted_risks`
  - `rust_review_current_diff`
- Fixture-safe hosted calls succeeded:
  - `rust_audit_unsafe`: `needs_attention`, 9 findings
  - `rust_audit_dependencies`: `high_risk`, 6 findings
  - `rust_list_accepted_risks`: `needs_attention`, 3 findings
  - `rust_review_current_diff`: `needs_attention`, 3 findings
- `structuredContent` shape was normal: `tool`, `sourceKind`, `riskLevel`, `summary`, `findings`, `evidenceSnippets`, `limitations`, `suggestedNextSteps`, `confidenceNote`, and `privacy`.
- Output and negative checks did not reveal host absolute paths, private repositories, tokens, stack traces, or full source.

ChatGPT Developer Mode result:

- Connection success: No.
- ChatGPT listed tools: No.
- ChatGPT tool calls: None.
- Developer Mode was enabled in ChatGPT Advanced settings.
- Blocker: the ChatGPT UI did not expose the documented `Create` / `Create app` connector entry in Settings -> Apps / Connectors, the Apps catalog flow, or the composer Sources / Apps flow.
- Endpoint reachability was separately confirmed by HTTPS health and smoke validation.
- Possible failure reason: account, organization, entitlement, session, feature flag, or current UI limitation around unverified Developer Mode connector creation.
- Screenshot notes: Chrome screenshots showed an Enabled apps modal with no Create button and Advanced settings with Developer Mode enabled.

Privacy check:

- No private GitHub repository was connected.
- No local private project path was read by the hosted endpoint or submitted to ChatGPT.
- No full source was uploaded.
- No user code was saved.
- Output paths were fixture-relative or sanitized.
- Hosted tools remained fixture-safe.
- The smoke privacy guard verified absolute path, private token, oversized source, and redacted error behavior.

Next recommendation:

- Do not move to Stage 2.5 yet.
- Retry Stage 2.4 in a ChatGPT account, organization, or session where the Developer Mode Create connector entry is visible.
- Keep v0.1.1 positioned as a local-first MCP preview with a fixture-safe hosted prototype until real ChatGPT connector creation, tool listing, and tool call validation succeed.

## 2026-06-17 Repository-Side Retry Preflight

This was a repository-side readiness pass only. It did not create a ChatGPT connector, submit an app, deploy a stable endpoint, connect private GitHub, or upload private source.

Maintenance evidence:

- `npm audit` passed with 0 vulnerabilities after updating transitive `hono` to `4.12.25`.
- `npm outdated` returned no outdated packages after updating `@types/node` to `25.9.3`.
- `.zhenvis/` is ignored as a local run artifact.

Smoke evidence:

- `npm run check` passed.
- Local hosted smoke passed against `http://127.0.0.1:8787/mcp`.
- Temporary HTTPS smoke passed against `https://legal-hotels-sit.loca.lt/mcp`.
- Tool list over HTTPS returned exactly:
  - `rust_audit_dependencies`
  - `rust_audit_unsafe`
  - `rust_list_accepted_risks`
  - `rust_review_current_diff`
- Fixture-safe HTTPS tool calls succeeded:
  - `rust_audit_unsafe`: `needs_attention`, 9 findings
  - `rust_audit_dependencies`: `high_risk`, 6 findings
  - `rust_list_accepted_risks`: `needs_attention`, 3 findings
  - `rust_review_current_diff`: `needs_attention`, 3 findings
- Privacy guard passed for absolute path, private token, oversized source, and redacted error behavior.

Remaining Stage 2.4 evidence gap:

- No real ChatGPT connector was created in this pass.
- ChatGPT did not list tools in this pass.
- No ChatGPT-originated tool call occurred in this pass.
- The temporary tunnel URL should be assumed expired.

## Tool List

| Tool | Hosted scope | Read-only | Open world | Destructive |
| --- | --- | --- | --- | --- |
| `rust_audit_unsafe` | `unsafe_usage` fixture or short pasted Rust snippet | Yes | No | No |
| `rust_audit_dependencies` | `dependency_manifest` fixture or short pasted Cargo/build snippets | Yes | No | No |
| `rust_list_accepted_risks` | `accepted_risk_suppression` fixture or short pasted suppression snippet | Yes | No | No |
| `rust_review_current_diff` | `fixture_diff` only | Yes | No | No |

## Tool Descriptions

`rust_audit_unsafe`

Fixture-safe hosted demo tool. Audits the `unsafe_usage` fixture or a short pasted Rust snippet for unsafe blocks, unsafe functions, FFI boundaries, raw-memory primitives, and unsafe Send/Sync impls. It does not accept project paths, private repository tokens, repository URLs, or full private repositories.

`rust_audit_dependencies`

Fixture-safe hosted demo tool. Audits the `dependency_manifest` fixture or short pasted `Cargo.toml`, `Cargo.lock`, and `build.rs` snippets for supply-chain review signals. It does not query vulnerability databases and does not accept private repository tokens or private repository metadata.

`rust_list_accepted_risks`

Fixture-safe hosted demo tool. Lists `rustsec-auditor` accepted-risk suppressions from the `accepted_risk_suppression` fixture or a short pasted suppression snippet. It does not read local project files.

`rust_review_current_diff`

Fixture-only hosted demo tool. Reviews the `fixture_diff` demo diff and refuses pasted diffs, local paths, and private repository data. Real private working-tree review remains on the local stdio MCP server.

## Test Prompts

| Prompt | Expected tool | Expected response |
| --- | --- | --- |
| `Run the hosted unsafe Rust demo fixture.` | `rust_audit_unsafe` | Returns a Markdown summary for `fixture_id=unsafe_usage`, `riskLevel=needs_attention`, unsafe/FFI findings, limitations, and next steps. |
| `Check the hosted dependency manifest fixture for supply-chain review signals.` | `rust_audit_dependencies` | Returns `riskLevel=high_risk`, build-script and dependency findings, plus a note that vulnerability database lookup is out of scope. |
| `Show the accepted-risk suppressions in the hosted demo fixture.` | `rust_list_accepted_risks` | Returns active, expired, and invalid suppression counts with public demo metadata only. |
| `Review the hosted current diff fixture.` | `rust_review_current_diff` | Returns `riskLevel=needs_attention`, introduced FFI/unsafe findings, and a `reviewDecision` that requires manual review. |
| `Can you scan my private GitHub repository if I give you a token?` | None or rejection from a hosted tool | The app should explain that private GitHub access and tokens are not supported in Stage 2.3 and suggest using local stdio MCP for private work. |
| `Use /Users/alice/project as the projectPath for hosted review.` | Rejection from hosted tool if invoked | The tool rejects local/absolute paths and does not echo the path back in the error output. |
| `Audit this entire pasted private repository archive.` | None or rejection from a hosted tool | The app should refuse or ask for a short, non-sensitive snippet only; full source uploads are out of scope. |

## Expected Responses

Positive fixture calls should include:

- A concise Markdown report.
- `structuredContent.tool` matching the invoked tool.
- `structuredContent.riskLevel`.
- `structuredContent.summary`.
- `structuredContent.findings`.
- `structuredContent.limitations`.
- `structuredContent.suggestedNextSteps`.
- `structuredContent.confidenceNote` saying confidence is pattern-detection confidence, not exploitability confidence.
- `structuredContent.privacy` confirming no local project reads, no private repo tokens, and no source persistence.

Negative or rejected calls should include:

- A clear rejection message.
- A stable error code such as `ABSOLUTE_PATH_NOT_ACCEPTED`, `PRIVATE_TOKEN_NOT_ACCEPTED`, `PRIVATE_REPOSITORY_NOT_SUPPORTED`, `OVERSIZED_SOURCE_INPUT`, or `FIXTURE_DIFF_ONLY`.
- No echoed token, absolute path, private repository URL, source archive, or stack trace.
- A suggestion to use local stdio MCP for real private project review.

## Privacy Notes

- The hosted prototype is fixture-safe by design.
- Private GitHub repositories are not connected.
- Private repository tokens, API keys, bearer tokens, and secrets are rejected.
- Local absolute paths and `projectPath` inputs are rejected.
- Hosted `rust_review_current_diff` is fixture-only.
- Short pasted snippets are accepted only by selected tools and are bounded by size limits.
- The hosted tools do not persist source.
- Logs should not include snippets, diffs, absolute paths, repository metadata, auth headers, tokens, secrets, stack traces, or raw prompts.
- Output paths are fixture-relative or sanitized.

## Permission Notes

- No GitHub OAuth or GitHub App permissions are requested in Stage 2.3.
- No OpenAI API key is required by this server.
- No write permissions are requested.
- No public internet state is modified.
- No destructive operation is exposed.
- If future private repository support is added, it needs a separate least-privilege auth, retention, deletion, and review design before submission.

## Known Limitations

- Hosted mode is a demo transport and fixture scanner, not a SaaS product.
- No ChatGPT App UI component or widget is included.
- No authentication or user account model exists.
- No vulnerability database lookup is performed.
- No full private project scan is supported.
- The scanner is heuristic static pattern detection, not exploitability analysis or a complete security audit.
- Reports can contain public fixture evidence snippets.
- ChatGPT Developer Mode and API Playground validation still require an authenticated OpenAI UI session that is outside this repository.

## Data Retention Statement Draft

The hosted prototype processes bundled public demo fixtures and short explicit pasted snippets only. It does not read local project paths, connect to private repositories, accept repository tokens, or persist source code. Operational logs should be limited to timestamp, tool name, duration, status, fixture ID, and coarse error category. Logs should not store source snippets, diffs, absolute paths, repository metadata, tokens, secrets, or raw prompts. Private project review should use the local stdio MCP workflow where code remains on the user's machine.

## Review Checklist

- [ ] Stable HTTPS `/mcp` endpoint is available.
- [ ] `/healthz` reports hosted fixture-safe mode.
- [ ] MCP tool list contains only the four hosted tools.
- [ ] `rust_audit_project` is not exposed in hosted mode.
- [ ] Tool input schemas do not expose `projectPath`, repository URL fields, or token fields.
- [ ] Every tool has `outputSchema`.
- [ ] Every tool has explicit read-only, non-destructive, non-open-world annotations.
- [ ] Every tool returns Markdown `content` and `structuredContent`.
- [ ] Smoke script passes against local HTTP.
- [ ] Smoke script passes against temporary HTTPS tunnel.
- [ ] Absolute path, token, private repository, and oversized source guards are verified.
- [ ] Error outputs do not echo sensitive input.
- [ ] Sample output document is current.
- [ ] Privacy and data retention statements are reviewed before any public submission.
- [ ] Screenshots are captured after real ChatGPT Developer Mode or API Playground validation.

## Current Stage 2.3 Evidence Placeholders

- Local smoke command: `npm run smoke:hosted -- --url http://127.0.0.1:8787/mcp`
- HTTPS tunnel smoke command: `npm run smoke:hosted -- --url https://<generated-host>/mcp`
- Sample outputs: `docs/STAGE2_HOSTED_MCP_SAMPLE_OUTPUTS.md`
- Connection notes: `docs/STAGE2_HOSTED_MCP_DESIGN.md`

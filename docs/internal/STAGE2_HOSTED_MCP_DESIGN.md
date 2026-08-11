# Stage 2 Hosted MCP / ChatGPT App Prototype Design

Date: 2026-05-18

This document began as the design and migration plan for Stage 2. As of Phase 2.2, it also records the minimal hosted MCP transport spike implemented in this repository. The spike does not change the local stdio MCP behavior, does not add private repository access, and does not implement a ChatGPT App UI component.

## 1. Current State

Rust Security Auditor v0.1.1 is a local-first Rust security review preview.

Completed capabilities:

- A local TypeScript scanner kernel for heuristic Rust security review.
- A stdio MCP server built with `@modelcontextprotocol/sdk` and `StdioServerTransport`.
- Five read-only MCP tools:
  - `rust_review_current_diff`
  - `rust_audit_project`
  - `rust_audit_unsafe`
  - `rust_audit_dependencies`
  - `rust_list_accepted_risks`
- Tool outputs include text content for MCP clients and `structuredContent` for structured result handling.
- Markdown and JSON report output.
- Compact and full Markdown report modes for non-diff audit tools.
- Relative path display by default in Markdown reports to reduce local path leakage.
- Changed-line-aware current diff review with `reviewDecision`, suppression summaries, hidden legacy-context handling, and suggested Codex fix prompts.
- Accepted-risk suppression inventory for `rustsec-auditor` comments.
- Public preview docs, examples, CI, tag validation, fresh clone validation, and real-project dogfood.
- A separate hosted MCP prototype entry point at `src/mcp/hostedServer.ts`.
- `npm run mcp:hosted` starts a local Streamable HTTP `/mcp` endpoint for fixture-safe hosted testing.
- Hosted demo wrappers expose only:
  - `rust_audit_unsafe`
  - `rust_audit_dependencies`
  - `rust_list_accepted_risks`
  - `rust_review_current_diff` for the bundled fixture diff only
- Hosted demo tool outputs include Markdown `content`, `structuredContent`, explicit `outputSchema`, risk level, findings, evidence snippets, limitations, suggested next steps, and privacy/confidence notes.

Current local stdio MCP limits:

- The MCP transport is stdio only. The client launches the server as a local subprocess.
- Tool inputs are local filesystem paths. The implementation rejects URL-shaped `projectPath` values and requires a local Cargo project or workspace.
- `rust_review_current_diff` depends on local Git commands and local file access.
- The stdio server is still not exposed as a public network service. Hosted HTTP is a separate prototype entry point, not a change to local stdio behavior.
- There is no hosted auth, user account model, remote repository authorization, or ChatGPT App UI.
- The scanner is heuristic static review, not AST-complete analysis, data-flow, taint analysis, formal verification, supply-chain attestation, or a complete security audit.
- Dependency audit does not query vulnerability databases.
- The package version is v0.1.1. The current server metadata in `src/mcp/server.ts` still reports `version: "0.1.0"`; Stage 2 design does not change code.

Official context:

- MCP defines stdio as a client-launched subprocess transport and Streamable HTTP as the remote-server transport. See the MCP transports specification: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP architecture distinguishes local stdio servers, which usually serve one client, from remote Streamable HTTP servers, which usually serve many clients: https://modelcontextprotocol.io/docs/learn/architecture
- OpenAI Apps SDK builds ChatGPT apps on top of MCP servers and app components: https://developers.openai.com/apps-sdk

## 2. Goal

Stage 2 moves from a local stdio MCP preview toward a hosted MCP prototype without changing the scanner kernel.

Goals:

- Confirm the official hosted MCP / ChatGPT App development model.
- Design a hosted Streamable HTTP MCP prototype path.
- Let ChatGPT Developer Mode connect to a prototype `/mcp` endpoint.
- Validate tool discovery, tool calling, and report rendering in ChatGPT.
- Prepare future ChatGPT App submission assets and review boundaries.
- Keep real private project review on the existing local MCP / Codex workflow until privacy, auth, and access control are deliberately designed.

## 3. Non-goals

Stage 2 explicitly does not do the following:

- No uploading user code by default.
- No SaaS product.
- No code hosting service.
- No user account system.
- No first-version ChatGPT App UI.
- No automatic code modification.
- No promise of complete security audit coverage.
- No Deep Audit mode.
- No release gate.
- No complex cloud architecture.
- No private repository ingestion.
- No scanner kernel rewrite.
- No MCP tool rewrite.
- No online deployment in this design stage.

## 4. Architecture Options

### A. Local-only stdio MCP continued

Continue using the current local MCP server exactly as v0.1.x does today.

How it works:

- Codex or another MCP client launches the server with `npm --silent run mcp`.
- The server reads local project paths and local Git state.
- Tools return Markdown or structured JSON to the local client.

Pros:

- Strongest privacy posture because source stays on the user machine.
- Best fit for Codex local project workflows.
- Minimal operational complexity.
- Existing tools are already designed for this model.
- No hosted auth, storage, or repository permission surface.

Cons:

- Not sufficient for ChatGPT hosted App submission.
- ChatGPT web Developer Mode needs an HTTPS-reachable `/mcp` endpoint.
- No public hosted demo surface for non-local users.
- Distribution remains tied to local setup, Codex config, or plugin/skill packaging.

Fit:

- Keep as the primary route for private project review.
- Continue using it for serious local security triage.

### B. Hosted MCP with local project adapter

Run a hosted MCP endpoint for ChatGPT, but keep project access local through a helper or adapter controlled by the user.

How it could work:

- Hosted server exposes app metadata and limited tools.
- A local helper reads the project and sends sanitized summaries, reports, or temporary responses to the hosted endpoint.
- The hosted endpoint never directly reads the local filesystem.

Pros:

- Better privacy than direct hosted repo ingestion.
- Preserves local project access for private code.
- Could eventually bridge ChatGPT conversations with local scanner results.

Cons:

- More moving parts than Stage 2 needs.
- Requires careful pairing, auth, session lifecycle, timeout handling, and error UX.
- Harder to explain during review.
- Risk of accidentally creating a private-code upload path.
- Still not the same shape as a simple ChatGPT App submission.

Fit:

- Interesting later, but not the first hosted prototype.
- Should be postponed until the hosted transport and report compatibility are proven.

### C. Hosted MCP with GitHub repo access

Users authorize repository access, and the hosted service reads repository contents or pull request diffs.

How it could work:

- User links a GitHub account or installs a GitHub App.
- The hosted service reads public repos, selected private repos, or PR diffs.
- Scanner runs in hosted infrastructure against checked-out or downloaded code.

Pros:

- Closest to a conventional ChatGPT App product.
- Supports review of PR diffs without local setup.
- Can be tested against public repositories.

Cons:

- Highest privacy, permissions, and review burden.
- Requires least-privilege GitHub auth design, token handling, secret redaction, repository caching policy, and deletion policy.
- Increases hosting cost and operational complexity.
- Private code scanning could be misunderstood as a full security service.
- Requires much more submission evidence and user-facing privacy documentation.

Fit:

- Suitable only after the hosted transport, privacy model, and demo UX are validated.
- Private GitHub access should be deferred for Stage 2.

### Recommendation across options

Use a constrained hosted prototype as the Stage 2 path while keeping local stdio MCP as the primary real-work route.

The recommended Stage 2 shape is not full Option B or C. It is a limited hosted MCP prototype that supports demo fixtures, selected public repository fixtures, or explicitly pasted diff metadata with strong privacy warnings. It should validate ChatGPT Developer Mode connection, MCP tool discovery, tool calling, and Markdown / structured report rendering. It should not accept full private repository uploads.

## 5. Recommended Architecture

The proposed Stage 2 prototype is reasonable based on the official docs.

Official constraints and implications:

- ChatGPT Developer Mode connector setup requires a public HTTPS `/mcp` endpoint, either from a tunnel or deployment. OpenAI documents adding the connector under Settings -> Apps & Connectors / Connectors and using an HTTPS URL with `/mcp`: https://developers.openai.com/apps-sdk/deploy/connect-chatgpt
- OpenAI's Apps SDK quickstart exposes a `/mcp` endpoint and uses a public HTTPS tunnel for ChatGPT development: https://developers.openai.com/apps-sdk/quickstart
- Production hosting should provide a stable HTTPS endpoint with low-latency streaming responses on `/mcp`, dependable TLS, logs, and metrics: https://developers.openai.com/apps-sdk/deploy
- MCP Streamable HTTP requires a single endpoint path that supports POST and GET and uses JSON-RPC messages over HTTP: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

Recommended Stage 2 prototype:

- Hosted MCP server exposes a minimal Streamable HTTP `/mcp` endpoint.
- No private code upload.
- No local filesystem access from the hosted service.
- No user account system.
- No GitHub private repository authorization.
- Tool calls operate only on:
  - bundled demo fixtures,
  - explicitly allowlisted public repo snapshots or examples,
  - manually pasted diff metadata or short snippets only when the user knowingly provides them.
- Real private project review remains local MCP / Codex workflow.
- First ChatGPT output is Markdown plus structured report data. No custom widget is required for the first prototype.

This architecture lets Stage 2 validate the riskiest unknowns first: hosted MCP transport compatibility, ChatGPT Developer Mode behavior, tool schema discoverability, and report output quality. It avoids the privacy and permission surface of private repository scanning.

## 6. Tool Migration Plan

### `rust_review_current_diff`

Local MCP status:

- Reads local Git diff from `projectPath`.
- Supports working tree, staged, and base/head diff modes.
- Scans changed project files and classifies findings as introduced, same unsafe site, same function, nearby legacy, unrelated nearby, or pre-existing.
- Returns `reviewDecision`, `diffReview`, enriched findings, grouped findings, suppression summary, and optional Markdown.

Hosted direct migration:

- Not suitable as-is because it depends on local Git and local filesystem reads.
- A hosted server cannot read the user's local working tree.

Needed hosted input:

- Stage 2 demo: `fixtureId`, `demoDiffId`, or selected public repo fixture.
- Later public repo mode: repo URL or GitHub repo reference, base ref, head ref, and explicit authorization for non-public repositories.
- Pasted diff mode would require the diff text plus enough file context to scan accurately; this can leak code and should be opt-in only.

Code privacy:

- High risk if used with private diffs.
- Even a small diff can contain proprietary code, secrets, paths, issue IDs, or dependency names.

ChatGPT App demo fit:

- Strong demo fit when backed by fixtures or public examples.
- Best first demo story: "Review this Rust diff" against a bundled fixture.

Stage 2 status:

- Do not directly migrate the current local tool.
- Use a demo-only hosted wrapper later, or keep as local-only until an explicit public repo / GitHub access model exists.

### `rust_audit_project`

Local MCP status:

- Runs the broad local project scan over a Cargo project or workspace.
- Covers unsafe/FFI, dependency/supply-chain, build scripts, command execution, filesystem/path handling, input boundaries, secrets, panic/DoS, concurrency, and manual-review categories.
- Returns summary counts, findings, optional compact/full Markdown, warnings, and suppression data.

Hosted direct migration:

- Not suitable as-is for private projects because it needs full project files.

Needed hosted input:

- Stage 2 demo: `fixtureId` or selected public repo snapshot.
- Future GitHub mode: explicit repo reference plus least-privilege read access.

Code privacy:

- Highest risk because full-project scanning requires broad source access.

ChatGPT App demo fit:

- Useful for a demo fixture but easy to overstate.
- The app must frame this as heuristic review, not full audit coverage.

Stage 2 status:

- Suitable only for demo fixtures or public sample repositories.
- Private project hosted scanning should be deferred.

### `rust_audit_unsafe`

Local MCP status:

- Reads local Rust source and reports unsafe blocks, unsafe functions, unsafe Send/Sync impls, FFI boundaries, and raw-memory primitives.
- Compact Markdown groups findings by unsafe site or function and includes manual invariant prompts.

Hosted direct migration:

- Not suitable for private projects as-is because it needs source files.

Needed hosted input:

- Stage 2 demo: unsafe-focused fixture or public repo snapshot.
- Future limited-input mode: explicit short snippet or file excerpt, clearly labeled as user-provided code.

Code privacy:

- High risk. Unsafe code often sits near low-level product logic and sensitive integration boundaries.

ChatGPT App demo fit:

- Strong demo fit with curated fixtures.
- Good first tool for "Audit unsafe usage" because the output is checklist-like and conversational.

Stage 2 status:

- Suitable for fixture-backed hosted prototype.
- Defer private source handling.

### `rust_audit_dependencies`

Local MCP status:

- Reads local Cargo manifests, lockfiles, build scripts, git/path dependencies, proc macros, and build dependencies.
- Does not query vulnerability databases.
- Compact Markdown presents a supply-chain checklist and groups workspace-local path dependencies.

Hosted direct migration:

- Partially suitable only if the input is public or explicitly provided.
- The current implementation still expects a local project layout, so a hosted prototype would need a fixture workspace or a public repo checkout.

Needed hosted input:

- Stage 2 demo: fixture ID or public sample Cargo files.
- Future mode: explicit `Cargo.toml`, `Cargo.lock`, and `build.rs` text, or public repo reference.

Code privacy:

- Medium to high risk. Dependency manifests can reveal private crate names, internal architecture, private git URLs, and build-time secrets.

ChatGPT App demo fit:

- Good demo fit with public fixtures.
- The output is compact and useful, especially when framed as "review signals" plus "run cargo audit separately."

Stage 2 status:

- Suitable for fixture/public-repo prototype.
- Defer private dependency upload and private GitHub access.

### `rust_list_accepted_risks`

Local MCP status:

- Scans local Rust source for `rustsec-auditor` accepted-risk suppression comments.
- Does not run the full scanner and does not modify code.
- Returns active, expired, and invalid accepted-risk inventory.

Hosted direct migration:

- Not suitable as-is because it reads local source files.
- Conceptually easier than full audit, but it still requires source comments.

Needed hosted input:

- Stage 2 demo: suppression fixture ID.
- Future limited mode: pasted suppression comments or public repo source.

Code privacy:

- Medium risk. Suppression comments can expose internal risk decisions, owners, tickets, filenames, or security rationale.

ChatGPT App demo fit:

- Good secondary demo: "Show accepted risks" against a fixture.
- Less compelling as the first public demo unless paired with a broader report.

Stage 2 status:

- Suitable for demo fixtures.
- Defer private source scanning.

## 7. Privacy & Security Design

Privacy defaults:

- Do not upload code by default.
- Hosted prototype must not require users to upload full private repositories.
- Hosted prototype must not read local files.
- Private project review remains local MCP / Codex until a future access model is reviewed.
- If a user manually pastes diff text or snippets, the UI and tool description must make clear that pasted content is being sent to the hosted MCP server through ChatGPT.

Storage:

- Do not save source code.
- Do not save complete reports unless the user explicitly exports them.
- Prefer ephemeral request handling for demo calls.
- Store only minimal operational telemetry such as timestamp, tool name, duration, status code, fixture ID, and coarse error category.
- Avoid storing raw prompts unless there is a documented retention reason and user-visible policy.

Logging:

- Do not log source snippets.
- Do not log full diffs.
- Do not log absolute local paths.
- Do not log tokens, repo secrets, environment variables, SSH URLs, private registry URLs, or auth headers.
- Redact PII and sensitive project identifiers from errors.
- Use correlation IDs for debugging instead of raw user data.

Output:

- Default to relative or sanitized paths.
- Avoid echoing absolute host paths from the server.
- Avoid returning full report archives unless requested.
- Keep `confidence` wording explicit: confidence means pattern-detection confidence, not exploitability confidence.
- Every report must repeat that the output is heuristic static review, not a proof of safety or a complete security audit.

Future GitHub access:

- Use a GitHub App or OAuth flow with the smallest feasible permissions.
- Prefer read-only selected-repository access.
- Prefer PR diff / contents read over broad account-level repo access.
- Never request write permissions for Stage 2.
- Do not read secrets, actions variables, deployment keys, or unrelated organization metadata.
- Do not retain cloned private repositories.
- Define retention, deletion, and access-review policy before enabling private repositories.

Stage 2.3 hosted boundary:

- Private repositories are not supported because even read-only private repo access introduces token handling, selected-repository authorization, clone/cache retention, deletion policy, secret redaction, audit logging, and user-consent obligations that are outside this transport validation stage.
- The hosted prototype does not save source code. It should process bundled fixtures or explicitly pasted short snippets in memory and return only the response.
- Logs must not record source snippets, full diffs, absolute paths, repository URLs, dependency names that identify private systems, tokens, secrets, auth headers, raw prompts, or stack traces containing sensitive values.
- `confidence` means pattern-detection confidence: how strongly a heuristic matched a review signal. It is not exploitability confidence, not proof of vulnerability, and not a severity override.
- User-pasted content is limited to short, intentional snippets for the tools that support pasted snippets. It is not a route for uploading an entire private repository, archive, full diff, lockfile corpus, or proprietary codebase.
- Fixture demos exercise public bundled examples and report-shape compatibility. Real project review is different: it needs local filesystem/Git context, full workspace layout, feature and dependency context, and human review, so it remains on local stdio MCP / Codex unless a separate hosted access design is approved.

Hosted MCP security:

- Use HTTPS for ChatGPT Developer Mode and future hosted endpoints.
- Validate `Origin` on Streamable HTTP connections as required by the MCP transport spec.
- Bind local development servers to localhost when exposing through a tunnel.
- Validate all tool inputs server-side.
- Treat tool annotations as useful hints, not security boundaries.
- Keep tools read-only and mark them with read-only annotations.
- Follow OpenAI Apps SDK security guidance on least privilege, explicit consent, redacted logging, and server-side validation: https://developers.openai.com/apps-sdk/guides/security-privacy

## 8. ChatGPT App UX Concept

No UI is implemented in Stage 2 design.

Possible user interactions:

- "Review this Rust diff"
- "Audit unsafe usage"
- "Check dependencies"
- "Show accepted risks"
- "Explain this finding"
- "Generate a Codex fix prompt"

First-version behavior:

- The app returns Markdown and structured report data.
- The model summarizes the report conversationally.
- Findings include severity, pattern-detection confidence, file path, line, evidence, risk scenario, suggested fix, and suggested next prompts when available.
- The app does not auto-modify code.
- The app does not claim complete audit coverage.

Later behavior:

- A report widget or iframe UI can be considered after the transport and report schema are stable.
- A widget could show grouped findings, filters, and expandable evidence.
- A dashboard should not be the first prototype. The first prototype should prove tool calling and report rendering.

Apps SDK implications:

- Tools are the contract between the MCP server and the model; OpenAI recommends focused tools with explicit inputs: https://developers.openai.com/apps-sdk/plan/tools
- Apps SDK tool results can return `structuredContent`, `content`, and `_meta`; `structuredContent` should be concise data the model can read, while `_meta` is for widget-only data: https://developers.openai.com/apps-sdk/build/mcp-server
- For Stage 2, no widget means no need to use `_meta` for private rich data. Markdown plus structured content is enough.

## 9. Stage 2 Task Breakdown

### Phase 2.1: Official docs research and architecture confirmation

Goal:

- Confirm current OpenAI Apps SDK, ChatGPT Developer Mode, hosted MCP, MCP transport, security, and submission requirements.

Input:

- Current v0.1.1 repository.
- Official OpenAI Apps SDK, Codex, and MCP documentation.
- Official MCP specification and architecture docs.

Output:

- This design document.
- Updated roadmap.

Acceptance criteria:

- Official links are captured.
- Hosted endpoint requirements are documented.
- Privacy boundaries are explicit.
- Tool migration decisions are recorded.

Does not do:

- No code changes.
- No hosted server implementation.
- No deployment.

### Phase 2.2: Hosted MCP transport spike

Goal:

- Prove the minimum Streamable HTTP transport shape for this project.

Status:

- Implemented as a minimal fixture-safe spike.

Input:

- Existing MCP server registration patterns.
- MCP Streamable HTTP SDK examples.
- A simple no-source demo fixture or health-like read-only tool.

Output:

- `src/mcp/hostedServer.ts`: local HTTP server with `/mcp`, `/healthz`, CORS preflight, host validation, and Origin validation.
- `src/mcp/hostedTools.ts`: hosted-only tool registration and privacy guard.
- `src/mcp/hostedFixtures.ts`: bundled demo fixtures for unsafe usage, dependency manifest/build metadata, accepted-risk suppressions, and fixture diff review.
- `test/hostedMcp.test.ts`: Streamable HTTP health, tool list, fixture calls, structured output, and privacy guard coverage.
- Stateless Streamable HTTP handling with JSON responses for the spike. No resumability/event store is implemented yet.

Acceptance criteria:

- MCP Inspector or the SDK Streamable HTTP client can list tools over HTTP in a local/tunneled environment.
- No local stdio MCP behavior changes.
- No private source upload path.
- Hosted input guard rejects local absolute paths, private tokens/secrets, repository URL inputs, and oversized pasted source.
- Tool output keeps confidence wording explicit: pattern-detection confidence, not exploitability confidence.

Does not do:

- No production deployment.
- No GitHub access.
- No ChatGPT App UI.
- No migration of all tools.

### Phase 2.3: Hosted MCP real connection smoke and submission pack

Goal:

- Verify the hosted `/mcp` endpoint through local HTTP and a temporary HTTPS tunnel, then prepare review-facing submission materials without expanding the privacy surface.

Input:

- Implemented Stage 2 hosted MCP transport spike.
- Existing hosted tool registration metadata.
- Fixture-only data policy and privacy guard behavior.

Output:

- `scripts/smoke_hosted_mcp.ts`: MCP protocol smoke test for local and tunneled hosted endpoints.
- Local and HTTPS tunnel run commands.
- Stage 2 hosted sample outputs for the four fixture-safe tools.
- ChatGPT App submission pack skeleton with test prompts, expected responses, privacy notes, and placeholders.
- Connection notes for ChatGPT Developer Mode or API Playground validation.

Acceptance criteria:

- `/mcp` is reachable locally.
- `/mcp` is reachable through a temporary HTTPS tunnel.
- Tool list contains only the four fixture-safe hosted tools.
- Every hosted tool returns Markdown content and valid `structuredContent`.
- Privacy guard rejects absolute paths, private tokens, private repository metadata, and oversized source input.
- Rejection outputs do not echo sensitive input.
- Local stdio MCP / Codex workflow remains unchanged.

Does not do:

- No private repo upload.
- No private GitHub connection.
- No OpenAI API connection.
- No ChatGPT App UI component.
- No source upload or complete-source submission.

### Phase 2.4: Demo fixture tool call through ChatGPT Developer Mode

Goal:

- Validate ChatGPT can connect, list tools, and call one or more fixture-backed Rust Security Auditor tools.

Input:

- Public HTTPS tunnel or temporary HTTPS development endpoint.
- Minimal `/mcp` server.
- Demo fixture IDs.

Output:

- Developer Mode connector configured in ChatGPT.
- Captured test prompts and expected outputs.
- Notes on tool naming, descriptions, and report rendering.

Acceptance criteria:

- ChatGPT connector creation succeeds.
- Tool list appears in ChatGPT settings.
- At least one fixture-backed call returns a readable Markdown/structured report.
- No private code is used.

Does not do:

- No public submission.
- No persistent service commitment.
- No dashboard UI.

### Phase 2.5: Report output compatibility polish

Goal:

- Tune output for ChatGPT readability without changing scanner semantics.

Input:

- ChatGPT Developer Mode test results.
- Existing compact Markdown reports.
- Existing structured result types.

Output:

- Proposed report field / wording adjustments.
- Optional future `outputSchema` design.
- Tool description improvements if needed.

Acceptance criteria:

- Reports render cleanly in ChatGPT.
- Confidence language remains accurate.
- Structured content remains small enough for model use.
- No private paths or source snippets appear in fixture outputs unless intentionally part of a public fixture.

Does not do:

- No new scanner rules.
- No release gate.
- No auto-fix behavior.

### Phase 2.6: Privacy/security review

Goal:

- Review the hosted prototype before any wider demo.

Input:

- Hosted skeleton design.
- Tool schemas.
- Logs.
- Fixture data.
- Privacy policy draft if public testing is planned.

Output:

- Privacy checklist.
- Logging redaction checklist.
- Tool data-flow notes.
- Decision on whether the prototype is safe for limited external testing.

Acceptance criteria:

- No code upload by default.
- No private repo support.
- No sensitive data in logs.
- HTTPS and origin validation are accounted for.
- Reports use relative/sanitized paths.

Does not do:

- No compliance claim.
- No enterprise security review claim.
- No private beta with customer code.

### Phase 2.7: ChatGPT App submission asset checklist

Goal:

- Prepare for future submission without submitting yet.

Input:

- OpenAI app submission docs.
- Prototype behavior and screenshots if a widget later exists.
- Test prompts and expected outputs.

Output:

- Submission asset checklist:
  - app name and description,
  - MCP endpoint URL,
  - privacy policy URL,
  - terms URL if needed,
  - logo and screenshots if required,
  - test credentials if authentication is added later,
  - test prompts and expected outputs,
  - disclosure of data types handled,
  - support contact,
  - known limitations.

Acceptance criteria:

- Materials are mapped to official submission guidance.
- Gaps are clearly marked.
- No submission is attempted.

Does not do:

- No public publishing.
- No app store submission.
- No monetization.

## 10. Risks

Primary risks:

- ChatGPT App submission requirements may change while Apps SDK and app directory flows are in beta.
- Hosted MCP cannot access local projects, so private real-work review must remain local unless a new access design is created.
- Private code privacy issues could become severe if pasted diffs, snippets, GitHub access, or uploads are added without strict consent and retention controls.
- Users may misunderstand the tool as a complete security audit rather than heuristic static review.
- Hosted runtime cost can grow if scanning public repositories or large fixtures.
- GitHub repository permissions are complex and require careful least-privilege design.
- Codex plugin distribution is related but not identical to ChatGPT App submission; self-serve plugin publishing is still evolving.
- Report output may need `outputSchema` tightening for robust ChatGPT and widget behavior.
- Tool descriptions may need additional wording to prevent destructive or privacy-sensitive misuse.
- Public fixture demos may underrepresent real private project behavior.

## 11. Recommendation

Stage 2 should begin.

Recommended decisions:

- Start with Phase 2.2 Hosted MCP transport spike.
- Keep local stdio MCP as the main route for real private Rust project review.
- Use a hosted prototype only for demo fixtures, public examples, or explicit limited pasted metadata.
- Do not support private GitHub repository access in Stage 2.
- Do not implement ChatGPT App UI in Stage 2.
- Do not upload private code packages.
- Do not market the hosted prototype as SaaS or a full security audit.
- Treat ChatGPT Developer Mode validation as the near-term success milestone.

The best next step is a narrow hosted MCP transport spike that proves `/mcp` connectivity and tool-call shape without expanding the scanner or privacy surface.

## 12. Phase 2.3 Hosted Prototype Runbook

### Local run

Build and start the hosted prototype:

```bash
PORT=8787 HOST=127.0.0.1 npm run mcp:hosted
```

Health check:

```bash
curl http://127.0.0.1:8787/healthz
```

MCP protocol smoke:

```bash
npm run smoke:hosted -- --url http://127.0.0.1:8787/mcp
```

MCP Inspector:

```bash
npx @modelcontextprotocol/inspector@latest --server-url http://127.0.0.1:8787/mcp --transport http
```

Expected hosted tool list:

- `rust_audit_unsafe`
- `rust_audit_dependencies`
- `rust_list_accepted_risks`
- `rust_review_current_diff`

The hosted tool list must not include `rust_audit_project` and must not expose `projectPath`.

### Tunnel testing

The server binds to localhost by default, matching the MCP transport security recommendation for local servers. For ChatGPT Developer Mode, expose it through HTTPS with a tunnel.

Example with ngrok:

```bash
ngrok http 8787
```

Copy the generated hostname, for example `abc123.ngrok.app`, then start or restart the hosted MCP server with that host allowlisted:

```bash
HOSTED_MCP_ALLOWED_HOSTS=abc123.ngrok.app PORT=8787 HOST=127.0.0.1 npm run mcp:hosted
```

Example with Cloudflare Tunnel:

```bash
cloudflared tunnel --url http://127.0.0.1:8787
```

Then allowlist the generated tunnel hostname:

```bash
HOSTED_MCP_ALLOWED_HOSTS=<generated-host>.trycloudflare.com PORT=8787 HOST=127.0.0.1 npm run mcp:hosted
```

Example with localtunnel through `npx`:

```bash
npx --yes localtunnel --port 8787
```

Then allowlist the generated tunnel hostname, for example:

```bash
HOSTED_MCP_ALLOWED_HOSTS=<generated-host>.loca.lt PORT=8787 HOST=127.0.0.1 npm run mcp:hosted
```

Run the smoke test against the HTTPS tunnel:

```bash
npm run smoke:hosted -- --url https://<generated-host>.loca.lt/mcp
```

`HOSTED_MCP_ALLOWED_ORIGINS` can be set as a comma-separated list when a client sends an Origin header. The default allows local origins plus ChatGPT origins (`https://chatgpt.com` and `https://chat.openai.com`).

Stage 2.3 local tool availability on this machine:

- `npx` is available, so localtunnel can be run without adding a dependency to this package.
- `ngrok`, `cloudflared`, and the `lt` binary were not installed in the local shell at the time of validation.

Observed Stage 2.3 tunnel validation:

- Started local server with `HOSTED_MCP_ALLOWED_HOSTS=rsa-stage23-20260518-1840.loca.lt PORT=8787 HOST=127.0.0.1 npm run mcp:hosted`.
- Started tunnel with `npx --yes localtunnel --port 8787 --subdomain rsa-stage23-20260518-1840`.
- Verified `https://rsa-stage23-20260518-1840.loca.lt/healthz` returned `status=ok` and the four hosted fixture-safe tools.
- Verified `npm run smoke:hosted -- --url https://rsa-stage23-20260518-1840.loca.lt/mcp` passed tool list, fixture calls, structured content, and privacy guard checks.

### ChatGPT Developer Mode connection

1. Start the hosted MCP server locally and expose it through an HTTPS tunnel.
2. Use the public tunnel URL with `/mcp`, for example `https://abc123.ngrok.app/mcp`.
3. In ChatGPT, enable Developer Mode under Settings -> Apps & Connectors -> Advanced settings, if the organization allows it.
4. Go to Settings -> Connectors -> Create.
5. Enter a connector name, a short fixture-demo description, and the public HTTPS `/mcp` URL.
6. Create the connector and verify ChatGPT shows only the four hosted fixture-safe tools.
7. In a new chat, add the connector from the composer tool menu and ask for one fixture call, for example: "Run the unsafe usage demo fixture."

This follows the OpenAI Apps SDK connection flow documented in "Connect from ChatGPT": https://developers.openai.com/apps-sdk/deploy/connect-chatgpt

### API Playground / Developer Mode validation notes

If an MCP Server tester is available in API Playground or an authenticated ChatGPT Developer Mode session:

1. Use the HTTPS tunnel URL with `/mcp`.
2. Confirm the server health URL is reachable: `https://<generated-host>/healthz`.
3. Connect the MCP server.
4. List tools and verify exactly:
   - `rust_audit_unsafe`
   - `rust_audit_dependencies`
   - `rust_list_accepted_risks`
   - `rust_review_current_diff`
5. Run one positive fixture prompt, such as `Run rust_audit_unsafe with fixture_id unsafe_usage`.
6. Run one negative privacy prompt using a fake token or absolute path and verify the rejection does not echo sensitive input.

Stage 2.3 result for this local validation run:

- ChatGPT Developer Mode was not used because this repository session does not include an authenticated ChatGPT UI session, and the task explicitly disallows connecting OpenAI API credentials.
- API Playground MCP Server testing was not used for the same reason: it requires an authenticated OpenAI surface outside this local repository workflow.
- Alternative validation used by Stage 2.3 is the official MCP SDK Streamable HTTP client, local `/healthz` and `/mcp` checks, optional MCP Inspector command, and the HTTPS tunnel smoke script.

## Stage 2.4 Real ChatGPT Developer Mode Validation

Date: 2026-05-18

Endpoint type: temporary HTTPS tunnel. This validation used a local hosted MCP process exposed through localtunnel for ChatGPT Developer Mode testing only. It was not a stable hosted deployment, SaaS service, or production endpoint.

Local hosted endpoint:

- Server command: `HOSTED_MCP_ALLOWED_HOSTS=rsa-stage24-20260518-2144.loca.lt PORT=8787 HOST=127.0.0.1 npm run mcp:hosted`
- Local port: `8787`
- Local MCP endpoint: `http://127.0.0.1:8787/mcp`
- Local health endpoint: `http://127.0.0.1:8787/healthz`
- Health response advertised fixture-safe stateless mode and the four hosted tools only.

Temporary HTTPS tunnel:

- Tunnel command: `npx --yes localtunnel --port 8787 --subdomain rsa-stage24-20260518-2144`
- HTTPS MCP endpoint: `https://rsa-stage24-20260518-2144.loca.lt/mcp`
- HTTPS health endpoint: `https://rsa-stage24-20260518-2144.loca.lt/healthz`
- The tunnel was used as a temporary development tunnel only and must not be treated as stable hosting.

Smoke validation:

- Local smoke command passed: `npm run smoke:hosted -- --url http://127.0.0.1:8787/mcp`
- HTTPS smoke command passed: `npm run smoke:hosted -- --url https://rsa-stage24-20260518-2144.loca.lt/mcp`
- `tools/list` returned exactly:
  - `rust_audit_dependencies`
  - `rust_audit_unsafe`
  - `rust_list_accepted_risks`
  - `rust_review_current_diff`
- Fixture-safe calls succeeded:
  - `rust_audit_unsafe`: `needs_attention`, 9 findings
  - `rust_audit_dependencies`: `high_risk`, 6 findings
  - `rust_list_accepted_risks`: `needs_attention`, 3 findings
  - `rust_review_current_diff`: `needs_attention`, 3 findings
- Hosted `structuredContent` shape was normal, including `tool`, `sourceKind`, `riskLevel`, `summary`, `findings`, `evidenceSnippets`, `limitations`, `suggestedNextSteps`, `confidenceNote`, and `privacy`.
- The smoke privacy guard passed for absolute path rejection, private token rejection, oversized source rejection, and redacted error behavior.
- Smoke output did not include host absolute paths, private repository references, tokens, or full source.

ChatGPT Developer Mode result:

- ChatGPT connection success: No.
- ChatGPT listed tools: No.
- ChatGPT-originated tool calls: None.
- Developer Mode was enabled in ChatGPT Advanced settings.
- The endpoint was reachable independently through HTTPS health and smoke checks.
- Blocker: the ChatGPT UI did not expose the documented `Create` / `Create app` connector entry in Settings -> Apps / Connectors, the Apps catalog flow, or the composer Sources / Apps flow.
- Likely cause: ChatGPT account, organization, entitlement, session, feature flag, or current UI limitation around creating unverified Developer Mode connectors.
- Screenshot notes: Chrome screenshots showed an Enabled apps modal with no Create button and Advanced settings with Developer Mode enabled.

Privacy check:

- No private GitHub repository was connected.
- No local private project path was read by the hosted server or submitted to ChatGPT.
- No complete source upload was performed.
- No user code was saved.
- Hosted output paths stayed fixture-relative or sanitized.
- Hosted tools remained fixture-safe.
- Negative smoke checks verified sensitive inputs are rejected or redacted.

Stage 2.4 decision:

- Stage 2.4 is blocked, not complete.
- The hosted prototype is ready for another real ChatGPT Developer Mode attempt from the repository side, but the ChatGPT UI must expose connector creation before the real connection gate can pass.
- Do not start Stage 2.5 output polish based on ChatGPT rendering until ChatGPT can create the connector, list the four tools, and call at least one hosted fixture-safe tool.

### Stage 2.4 minimum validation checklist

Use this checklist for the next retry in a ChatGPT account, organization, or session where the Developer Mode connector creation entry is visible:

- [ ] Start the hosted MCP server with the intended `HOSTED_MCP_ALLOWED_HOSTS`, `HOST`, and `PORT`.
- [ ] Expose the local hosted server through a temporary HTTPS tunnel.
- [ ] Verify MCP endpoint health through `/healthz` and run the hosted smoke script against the HTTPS `/mcp` URL.
- [ ] Add the connector in ChatGPT Developer Mode with the public HTTPS `/mcp` URL.
- [ ] Confirm ChatGPT lists only the four fixture-safe hosted tools.
- [ ] Call at least one fixture-safe tool from ChatGPT.
- [ ] Record the returned structured result, including `tool`, `riskLevel`, `summary`, `findings`, `limitations`, `suggestedNextSteps`, `confidenceNote`, and `privacy`.
- [ ] Document screenshots and observations for connector setup, tool listing, and the fixture-safe tool call.
- [ ] Update the final Stage 2.4 status as passed or blocked, with the exact ChatGPT account/session blocker if it remains blocked.

### Current limitations

- No ChatGPT App UI component or widget.
- No GitHub integration.
- No private repository access.
- No OpenAI API calls.
- No database or persistent storage.
- No auth/account system.
- No vulnerability database lookup for dependencies.
- No full-project hosted scan.
- `rust_review_current_diff` is fixture-only in hosted mode.
- Pasted snippets are limited to short, explicit snippets and are not a private-project upload path.
- The hosted prototype uses stateless Streamable HTTP JSON responses. It does not implement SSE notifications, resumability, or event replay.
- Reports are heuristic static pattern detection, not exploitability analysis or a complete security audit.

### Why private repos are out of scope

Private repository handling would require a separate product/security design: least-privilege GitHub authorization, selected-repository scoping, token handling, repository checkout policy, source retention/deletion policy, secret redaction, operational audit logs, user consent copy, and submission review evidence. Phase 2.2 is only proving hosted MCP transport compatibility and ChatGPT tool-call shape, so private project review remains on the local stdio MCP/Codex path.

### Submission checklist draft

- Stable HTTPS `/mcp` endpoint.
- Streamable HTTP POST/GET behavior verified with MCP Inspector or SDK client.
- Origin validation and local-host binding documented.
- Hosted tool list limited to fixture-safe read-only tools.
- No `projectPath`, absolute path, private token, private repo, or full source upload tool schema.
- Every tool has explicit input schema and output schema.
- Every tool returns Markdown `content` plus `structuredContent`.
- Outputs include risk level, findings, evidence snippets, limitations, suggested next steps, and confidence wording.
- Privacy policy draft covers data types, no private repo support, no source persistence, and log redaction.
- Terms/support contact prepared if moving beyond local demo.
- Test prompts and expected outputs captured for each fixture.
- Authentication story documented before any user-specific or private data is introduced.
- No public submission until the fixture-only behavior and privacy copy are reviewed.

## 13. Official Documentation Research Notes

OpenAI Apps SDK / MCP App development:

- Apps SDK is the framework for building apps for ChatGPT on top of MCP: https://developers.openai.com/apps-sdk
- The quickstart uses an MCP server with a `/mcp` endpoint and documents testing with MCP Inspector and ChatGPT Developer Mode: https://developers.openai.com/apps-sdk/quickstart
- OpenAI recommends planning focused tools with explicit inputs because tools are the contract between the MCP server and the model: https://developers.openai.com/apps-sdk/plan/tools
- Apps SDK tool responses may include `structuredContent`, `content`, and `_meta`; `structuredContent` is read by the model and should be concise, while `_meta` is for widget data: https://developers.openai.com/apps-sdk/build/mcp-server
- Tool descriptors should declare `outputSchema` when returning `structuredContent`: https://developers.openai.com/apps-sdk/reference

ChatGPT Developer Mode connection:

- Developer Mode can be enabled under Settings -> Apps & Connectors -> Advanced settings, if allowed by the organization.
- After enabling Developer Mode, use Settings -> Connectors -> Create and provide connector name, description, and public HTTPS `/mcp` URL.
- ChatGPT shows advertised tools after successful connection and can call the connector in a new conversation: https://developers.openai.com/apps-sdk/deploy/connect-chatgpt

Hosted MCP endpoint requirements:

- OpenAI docs call for stable HTTPS hosting, low-latency streaming responses on `/mcp`, dependable TLS, and logs/metrics: https://developers.openai.com/apps-sdk/deploy
- MCP Streamable HTTP requires one MCP endpoint supporting POST and GET, e.g. `https://example.com/mcp`: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- HTTP clients send JSON-RPC messages with POST and support JSON or SSE responses. GET may be used for server-to-client SSE streams, or the server may return 405 when it does not offer that stream.

HTTPS:

- ChatGPT Developer Mode connector setup expects an HTTPS-reachable MCP server URL.
- Local development can use tunnels such as ngrok or Cloudflare Tunnel to expose a local `/mcp` endpoint as HTTPS.

stdio vs hosted/HTTP MCP:

- stdio: the client launches the server as a subprocess, messages flow over stdin/stdout, and stdout must contain only valid MCP messages.
- Streamable HTTP: the server runs independently, can handle multiple clients, and communicates through HTTP POST/GET with optional SSE streaming.
- MCP architecture docs describe stdio as local process communication and Streamable HTTP as remote communication with standard HTTP auth methods: https://modelcontextprotocol.io/docs/learn/architecture

App submission materials:

- Submission is available through the OpenAI dashboard flow and review can include automated scans or manual review.
- Common rejection reasons include unreachable MCP URL, invalid test credentials, failing test cases, irrelevant output, mobile/web issues, and undisclosed user-related data types.
- Approved apps can be published, and OpenAI creates a plugin for Codex distribution after publishing: https://developers.openai.com/apps-sdk/deploy/submission
- Submission guidelines require predictable, auditable tool behavior and transparent, least-necessary permissions for authenticated apps: https://developers.openai.com/apps-sdk/app-submission-guidelines

ChatGPT App and Codex plugin / skill distribution:

- OpenAI Apps SDK home says approved published apps are available in the ChatGPT apps store and OpenAI creates a plugin for Codex distribution; self-serve plugin publishing is coming soon: https://developers.openai.com/apps-sdk
- Codex plugins can package skills, app mappings, MCP server configuration, hooks, and assets: https://developers.openai.com/codex/plugins/build
- Codex skills are local/repo/user/admin/system instructions, and reusable distribution should use plugins: https://developers.openai.com/codex/skills
- Codex MCP support includes stdio servers and Streamable HTTP servers: https://developers.openai.com/codex/mcp

Tool schema / description / output adjustments:

- Current tool names fit MCP naming guidance: lowercase ASCII words with underscores, unique within the server.
- Tool descriptions are already strong for local MCP but should be revised for hosted demo mode to avoid implying access to local private projects.
- Hosted demo tools should add explicit input names such as `fixtureId`, `demoDiffId`, or `publicRepoRef`; local `projectPath` should not be exposed in a hosted tool unless the hosted server actually has that path.
- Current `structuredContent` output is useful. A future hosted prototype should consider explicit `outputSchema` for stable validation.
- Markdown can remain the first display format. Widgets and `_meta` should wait until a later UI phase.

## 14. Source Links

- OpenAI Apps SDK: https://developers.openai.com/apps-sdk
- Apps SDK quickstart: https://developers.openai.com/apps-sdk/quickstart
- Define tools: https://developers.openai.com/apps-sdk/plan/tools
- Build your MCP server: https://developers.openai.com/apps-sdk/build/mcp-server
- Deploy your app: https://developers.openai.com/apps-sdk/deploy
- Connect from ChatGPT: https://developers.openai.com/apps-sdk/deploy/connect-chatgpt
- Test your integration: https://developers.openai.com/apps-sdk/deploy/testing
- Submit and maintain your app: https://developers.openai.com/apps-sdk/deploy/submission
- App submission guidelines: https://developers.openai.com/apps-sdk/app-submission-guidelines
- Security and privacy: https://developers.openai.com/apps-sdk/guides/security-privacy
- Apps SDK reference: https://developers.openai.com/apps-sdk/reference
- Codex MCP: https://developers.openai.com/codex/mcp
- Codex plugins: https://developers.openai.com/codex/plugins
- Build Codex plugins: https://developers.openai.com/codex/plugins/build
- Codex skills: https://developers.openai.com/codex/skills
- MCP transports specification: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP tools specification: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- MCP architecture overview: https://modelcontextprotocol.io/docs/learn/architecture

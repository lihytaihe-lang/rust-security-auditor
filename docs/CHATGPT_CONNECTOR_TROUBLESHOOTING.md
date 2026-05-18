# ChatGPT Connector Troubleshooting

Date: 2026-05-18

This checklist is for the next Stage 2.4 retry only. It is documentation and operator preparation, not new product scope. Do not modify the scanner kernel, hosted MCP tools, ChatGPT App UI, OpenAI submission materials, private GitHub access, or stable hosted deployment as part of this checklist.

## Expected ChatGPT Path

Official expected settings path:

- Enable Developer Mode at `Settings` -> `Apps & Connectors` -> `Advanced settings` -> `Developer mode`.
- Create the connector at `Settings` -> `Connectors` -> `Create`.

The connector URL must be an HTTPS MCP endpoint ending in `/mcp`, for example:

- `https://<temporary-or-dev-host>/mcp`

The tunnel endpoint must still be online while creating the connector. If the tunnel expires, restarts with a different hostname, or stops forwarding before connector creation finishes, ChatGPT may fail to connect even if the repository-side smoke script passed earlier.

## After Connector Creation

- Open a new ChatGPT chat after the connector is created.
- Select the connector from `+` -> `More`.
- Confirm ChatGPT lists the expected hosted tools before treating Stage 2.4 as complete.
- Trigger at least one fixture-backed tool invocation from ChatGPT and record the result.

## If Create Is Missing

If the ChatGPT UI does not show `Create` or `Create app connector`:

- Refresh ChatGPT.
- Try a new browser window.
- Toggle Developer Mode off and on again.
- Check whether the current account, plan, and workspace support developer connector creation.
- Check that the session is on the correct Settings page, especially `Apps & Connectors`, `Advanced settings`, and `Connectors`.
- Record UI screenshots showing Developer Mode status and the missing Create entry.
- Pause Stage 2.4 validation and keep Stage 2.5 blocked.

## Retry Checklist

1. Start the hosted MCP server locally.
2. Start an HTTPS tunnel to the hosted MCP port.
3. Run local smoke against `http://127.0.0.1:<port>/mcp`.
4. Run HTTPS smoke against `https://<tunnel-host>/mcp`.
5. Verify `/healthz` reports fixture-safe hosted mode and four hosted tools.
6. In ChatGPT, enable Developer Mode through the expected settings path.
7. Confirm the `Create` connector entry is visible before proceeding.
8. Create the connector with the live HTTPS `/mcp` endpoint.
9. Open a new chat and select the connector from `+` -> `More`.
10. Confirm ChatGPT hosted tools count is 4.
11. Invoke at least one fixture-backed hosted tool from ChatGPT.
12. Update `docs/STAGE2_PROGRESS.md` with either successful evidence or the new blocker.

## Current Blocker To Preserve

The 2026-05-18 Stage 2.4 attempt remains blocked because the ChatGPT UI showed Developer Mode enabled but did not expose the `Create` / `Create app connector` entry. ChatGPT tools count stayed at 0, and no real ChatGPT-originated tool invocation occurred.

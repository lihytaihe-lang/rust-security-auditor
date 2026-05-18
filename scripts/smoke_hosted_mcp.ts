#!/usr/bin/env node
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  hostedMcpToolNames,
  type HostedMcpToolName,
  type HostedMcpToolOutput
} from "../src/mcp/hostedTools.js";

type UnknownRecord = Record<string, unknown>;

interface SmokeOptions {
  url: URL;
}

interface ToolCallFixture {
  name: HostedMcpToolName;
  fixture_id: string;
}

const expectedCalls: readonly ToolCallFixture[] = [
  { name: "rust_audit_unsafe", fixture_id: "unsafe_usage" },
  { name: "rust_audit_dependencies", fixture_id: "dependency_manifest" },
  { name: "rust_list_accepted_risks", fixture_id: "accepted_risk_suppression" },
  { name: "rust_review_current_diff", fixture_id: "fixture_diff" }
];

const sensitiveNeedles = [
  "/Users/alice/private-rust-project/src/lib.rs",
  "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
  "OVERSIZED_PRIVATE_SOURCE_MARKER"
] as const;

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const healthUrl = toHealthUrl(options.url);

  await assertEndpointReachable(healthUrl, options.url);

  const client = new Client({
    name: "rust-security-auditor-hosted-smoke",
    version: "0.0.0"
  });
  const transport = new StreamableHTTPClientTransport(options.url);
  const callSummaries: string[] = [];

  try {
    await client.connect(transport as unknown as Transport);

    const toolsResult = await client.listTools();
    const toolNames = toolsResult.tools.map((tool) => tool.name).sort();
    assertDeepEqual(toolNames, [...hostedMcpToolNames].sort(), "Hosted tool list should contain only fixture-safe tools.");

    for (const tool of toolsResult.tools) {
      assertCondition(!JSON.stringify(tool.inputSchema).includes("projectPath"), `${tool.name} must not expose projectPath.`);
      assertCondition(tool.outputSchema !== undefined, `${tool.name} must advertise outputSchema.`);
      assertJsonSerializable(tool.outputSchema, `${tool.name} outputSchema`);
      assertCondition(isRecord(tool.annotations), `${tool.name} must advertise tool annotations.`);
      assertCondition(tool.annotations.readOnlyHint === true, `${tool.name} should be read-only.`);
      assertCondition(tool.annotations.destructiveHint === false, `${tool.name} should not be destructive.`);
      assertCondition(tool.annotations.openWorldHint === false, `${tool.name} should not write to external systems.`);
    }

    for (const call of expectedCalls) {
      const result = await client.callTool({
        name: call.name,
        arguments: {
          fixture_id: call.fixture_id
        }
      });
      const output = assertHostedStructuredContent(result.structuredContent, call.name);

      assertCondition(result.isError === false, `${call.name} should not return an error for fixture input.`);
      assertCondition(output.fixture_id === call.fixture_id, `${call.name} should echo the fixture id.`);
      assertCondition(output.findings.length > 0, `${call.name} should return fixture findings.`);
      assertNoSensitiveLeak(result, `${call.name} success output`);

      callSummaries.push(`${call.name}:${output.riskLevel}/${output.findings.length}`);
    }

    await assertPrivacyGuard(client, "rust_audit_unsafe", {
      snippet: sensitiveNeedles[0]
    }, "ABSOLUTE_PATH_NOT_ACCEPTED", "absolute path rejection");
    await assertPrivacyGuard(client, "rust_audit_dependencies", {
      fixture_id: "dependency_manifest",
      github_token: sensitiveNeedles[1]
    }, "PRIVATE_TOKEN_NOT_ACCEPTED", "private token rejection");
    await assertPrivacyGuard(client, "rust_audit_unsafe", {
      snippet: `${sensitiveNeedles[2]}\n${"unsafe { core::ptr::read(0 as *const u8); }\n".repeat(400)}`
    }, "OVERSIZED_SOURCE_INPUT", "oversized source rejection");

    console.log("Hosted MCP smoke passed");
    console.log(`Endpoint: ${options.url.toString()}`);
    console.log(`Health: ${healthUrl.toString()}`);
    console.log(`Tools: ${toolNames.join(", ")}`);
    console.log(`Fixture calls: ${callSummaries.join(", ")}`);
    console.log("Privacy guard: absolute path, private token, oversized source, and redacted errors passed");
  } finally {
    await client.close();
  }
}

function parseArgs(args: readonly string[]): SmokeOptions {
  let rawUrl = process.env.HOSTED_MCP_URL ?? "http://127.0.0.1:8787/mcp";

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--url") {
      const next = args[index + 1];
      assertCondition(next !== undefined, "--url requires a value.");
      rawUrl = next;
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return {
    url: normalizeMcpUrl(rawUrl)
  };
}

function printUsage(): void {
  console.log([
    "Usage: npm run smoke:hosted -- --url http://127.0.0.1:8787/mcp",
    "",
    "Environment:",
    "  HOSTED_MCP_URL  Optional MCP endpoint URL. Defaults to http://127.0.0.1:8787/mcp."
  ].join("\n"));
}

function normalizeMcpUrl(value: string): URL {
  const url = new URL(value);
  const pathname = url.pathname.replace(/\/+$/, "");
  if (pathname.length === 0) {
    url.pathname = "/mcp";
  } else if (!pathname.endsWith("/mcp")) {
    url.pathname = `${pathname}/mcp`;
  } else {
    url.pathname = pathname;
  }
  url.search = "";
  return url;
}

function toHealthUrl(mcpUrl: URL): URL {
  const healthUrl = new URL(mcpUrl.toString());
  healthUrl.pathname = "/healthz";
  healthUrl.search = "";
  return healthUrl;
}

async function assertEndpointReachable(healthUrl: URL, mcpUrl: URL): Promise<void> {
  const healthResponse = await fetch(healthUrl);
  assertCondition(healthResponse.ok, `Health endpoint should be reachable: ${healthResponse.status}`);
  const health = await healthResponse.json() as UnknownRecord;
  assertCondition(health.status === "ok", "Health endpoint should report status=ok.");
  assertCondition(health.mcpEndpoint === "/mcp", "Health endpoint should report /mcp.");

  const optionsResponse = await fetch(mcpUrl, { method: "OPTIONS" });
  assertCondition(optionsResponse.status === 204, `/mcp OPTIONS should return 204, got ${optionsResponse.status}.`);
}

async function assertPrivacyGuard(
  client: Client,
  toolName: HostedMcpToolName,
  input: UnknownRecord,
  expectedCode: string,
  label: string
): Promise<void> {
  const result = await client.callTool({
    name: toolName,
    arguments: input
  });
  const output = assertHostedStructuredContent(result.structuredContent, toolName);

  assertCondition(result.isError === true, `${label} should return isError=true.`);
  assertCondition(output.error?.code === expectedCode, `${label} should return ${expectedCode}.`);
  assertCondition(output.findings.length === 0, `${label} should not return findings.`);
  assertNoSensitiveLeak(result, label);
}

function assertHostedStructuredContent(value: unknown, tool: HostedMcpToolName): HostedMcpToolOutput {
  assertCondition(isRecord(value), `${tool} structuredContent should be an object.`);
  const output = value as unknown as HostedMcpToolOutput;

  assertCondition(output.tool === tool, `${tool} structuredContent should identify the tool.`);
  assertCondition(["fixture", "pasted_snippet", "public_demo_metadata"].includes(output.sourceKind), `${tool} sourceKind should be valid.`);
  assertCondition(["pass", "warning", "needs_attention", "high_risk"].includes(output.riskLevel), `${tool} riskLevel should be valid.`);
  assertCondition(typeof output.markdownSummary === "string" && output.markdownSummary.startsWith("# "), `${tool} should include markdownSummary.`);
  assertCondition(isRecord(output.summary), `${tool} should include summary object.`);
  assertCondition(Array.isArray(output.findings), `${tool} should include findings array.`);
  assertCondition(Array.isArray(output.evidenceSnippets), `${tool} should include evidenceSnippets array.`);
  assertCondition(Array.isArray(output.limitations), `${tool} should include limitations array.`);
  assertCondition(Array.isArray(output.suggestedNextSteps), `${tool} should include suggestedNextSteps array.`);
  assertCondition(output.confidenceNote.includes("pattern-detection confidence"), `${tool} should include confidence note.`);
  assertCondition(output.privacy?.doesNotReadLocalProjects === true, `${tool} should confirm it does not read local projects.`);
  assertCondition(output.privacy?.doesNotAcceptPrivateRepoTokens === true, `${tool} should confirm it rejects private tokens.`);
  assertCondition(output.privacy?.doesNotPersistSource === true, `${tool} should confirm it does not persist source.`);
  assertJsonSerializable(value, `${tool} structuredContent`);

  return output;
}

function assertNoSensitiveLeak(value: unknown, label: string): void {
  const serialized = JSON.stringify(value);
  assertCondition(serialized !== undefined, `${label} should be JSON serializable.`);

  for (const needle of sensitiveNeedles) {
    assertCondition(!serialized.includes(needle), `${label} leaked sensitive input.`);
  }

  assertCondition(!serialized.includes(process.cwd()), `${label} leaked current working directory.`);
}

function assertJsonSerializable(value: unknown, label: string): void {
  try {
    JSON.parse(JSON.stringify(value));
  } catch (error) {
    throw new Error(`${label} is not JSON serializable: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function assertDeepEqual(left: readonly string[], right: readonly string[], message: string): void {
  assertCondition(JSON.stringify(left) === JSON.stringify(right), `${message} got ${JSON.stringify(left)}`);
}

function assertCondition(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

main().catch((error: unknown) => {
  console.error(`Hosted MCP smoke failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});

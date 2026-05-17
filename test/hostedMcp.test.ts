import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  createHostedMcpHttpServer,
  hostedMcpToolNames,
  type HostedMcpToolName,
  type HostedMcpToolOutput
} from "../src/mcp/index.js";

describe("hosted MCP Streamable HTTP prototype", () => {
  it("serves endpoint health and CORS preflight", async () => {
    const { server, url } = await startHostedServer();

    try {
      const healthResponse = await fetch(`${url}/healthz`);
      const health = (await healthResponse.json()) as Record<string, unknown>;

      assert.equal(healthResponse.status, 200);
      assert.equal(health.status, "ok");
      assert.equal(health.mcpEndpoint, "/mcp");
      assert.equal(health.transport, "streamable_http");
      assert.deepEqual(health.tools, hostedMcpToolNames);

      const preflightResponse = await fetch(`${url}/mcp`, {
        method: "OPTIONS",
        headers: {
          Origin: "http://localhost:3000"
        }
      });

      assert.equal(preflightResponse.status, 204);
      assert.equal(preflightResponse.headers.get("access-control-allow-methods"), "POST, GET, DELETE, OPTIONS");
      assert.match(preflightResponse.headers.get("access-control-allow-headers") ?? "", /Mcp-Session-Id/);
    } finally {
      await closeServer(server);
    }
  });

  it("lists only fixture-safe hosted tools over Streamable HTTP", async () => {
    await withHostedClient(async (client) => {
      const result = await client.listTools();
      const toolNames = result.tools.map((tool) => tool.name).sort();

      assert.deepEqual(toolNames, [...hostedMcpToolNames].sort());
      assert.equal((toolNames as string[]).includes("rust_audit_project"), false);

      for (const tool of result.tools) {
        assert.ok(tool.outputSchema, `${tool.name} should advertise structuredContent outputSchema`);
        assert.doesNotMatch(JSON.stringify(tool.inputSchema), /projectPath|project_path|repo_url|github_token/);
      }
    });
  });

  it("calls each hosted fixture tool and returns the hosted structuredContent schema", async () => {
    await withHostedClient(async (client) => {
      const calls: Array<{ name: HostedMcpToolName; fixture_id: string }> = [
        { name: "rust_audit_unsafe", fixture_id: "unsafe_usage" },
        { name: "rust_audit_dependencies", fixture_id: "dependency_manifest" },
        { name: "rust_list_accepted_risks", fixture_id: "accepted_risk_suppression" },
        { name: "rust_review_current_diff", fixture_id: "fixture_diff" }
      ];

      for (const call of calls) {
        const result = await client.callTool({
          name: call.name,
          arguments: {
            fixture_id: call.fixture_id
          }
        });

        assert.equal(result.isError, false, `${call.name} should succeed`);
        const output = result.structuredContent as unknown as HostedMcpToolOutput;
        assertHostedOutputSchema(output, call.name);
        assert.equal(output.fixture_id, call.fixture_id);
        assert.ok(output.findings.length > 0, `${call.name} should return fixture findings`);
        assert.match(output.markdownSummary, /^# /);
        assert.match(output.confidenceNote, /pattern-detection confidence, not exploitability confidence/);
      }
    });
  });

  it("rejects absolute paths, private tokens, and oversized source input", async () => {
    await withHostedClient(async (client) => {
      const absolutePath = await client.callTool({
        name: "rust_audit_unsafe",
        arguments: {
          fixture_id: "unsafe_usage",
          projectPath: "/Users/alice/private-rust-project"
        }
      });

      assertRejected(absolutePath.structuredContent, "LOCAL_PATH_INPUT_NOT_ACCEPTED");
      assert.equal(absolutePath.isError, true);

      const privateToken = await client.callTool({
        name: "rust_audit_dependencies",
        arguments: {
          fixture_id: "dependency_manifest",
          github_token: "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        }
      });

      assertRejected(privateToken.structuredContent, "PRIVATE_TOKEN_NOT_ACCEPTED");
      assert.equal(privateToken.isError, true);

      const oversized = await client.callTool({
        name: "rust_audit_unsafe",
        arguments: {
          snippet: "unsafe { core::ptr::read(0 as *const u8); }\n".repeat(400)
        }
      });

      assertRejected(oversized.structuredContent, "OVERSIZED_SOURCE_INPUT");
      assert.equal(oversized.isError, true);
    });
  });
});

async function withHostedClient(action: (client: Client) => Promise<void>): Promise<void> {
  const { server, url } = await startHostedServer();
  const client = new Client({
    name: "rust-security-auditor-hosted-test",
    version: "0.0.0"
  });
  const transport = new StreamableHTTPClientTransport(new URL(`${url}/mcp`));

  try {
    await client.connect(transport as unknown as Transport);
    await action(client);
  } finally {
    await client.close();
    await closeServer(server);
  }
}

async function startHostedServer(): Promise<{ server: ReturnType<typeof createHostedMcpHttpServer>; url: string }> {
  const server = createHostedMcpHttpServer();

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address() as AddressInfo;
  return {
    server,
    url: `http://127.0.0.1:${address.port}`
  };
}

async function closeServer(server: ReturnType<typeof createHostedMcpHttpServer>): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
}

function assertHostedOutputSchema(output: HostedMcpToolOutput, tool: HostedMcpToolName): void {
  assert.equal(output.tool, tool);
  assert.ok(["fixture", "pasted_snippet", "public_demo_metadata"].includes(output.sourceKind));
  assert.ok(["pass", "warning", "needs_attention", "high_risk"].includes(output.riskLevel));
  assert.equal(typeof output.markdownSummary, "string");
  assert.equal(typeof output.summary, "object");
  assert.ok(Array.isArray(output.findings));
  assert.ok(Array.isArray(output.evidenceSnippets));
  assert.ok(Array.isArray(output.limitations));
  assert.ok(Array.isArray(output.suggestedNextSteps));
  assert.ok(output.limitations.some((item) => /heuristic static pattern detection/.test(item)));
  assert.ok(output.suggestedNextSteps.length > 0);
  assert.equal(output.privacy.doesNotReadLocalProjects, true);
  assert.equal(output.privacy.doesNotAcceptPrivateRepoTokens, true);
  assert.equal(output.privacy.doesNotPersistSource, true);

  for (const finding of output.findings) {
    assert.equal(typeof finding.ruleId, "string");
    assert.equal(typeof finding.title, "string");
    assert.ok(Array.isArray(finding.evidenceSnippets));
    assert.ok(Array.isArray(finding.limitations));
    assert.ok(Array.isArray(finding.suggestedNextSteps));
  }
}

function assertRejected(structuredContent: unknown, code: string): void {
  const output = structuredContent as HostedMcpToolOutput;
  assert.equal(output.error?.code, code);
  assert.equal(output.findings.length, 0);
  assert.ok(output.markdownSummary.includes("request rejected"));
}

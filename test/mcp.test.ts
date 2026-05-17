import assert from "node:assert/strict";
import { appendFile, cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  createRustSecurityAuditorMcpServer,
  mcpToolNames,
  type McpAuditToolOutput,
  rustAuditDependencies,
  rustAuditProject,
  rustAuditUnsafe,
  rustReviewCurrentDiff
} from "../src/mcp/index.js";
import { runShellCommandOrThrow } from "../src/utils/shell.js";

const vulnerableFixturePath = resolve("test/fixtures/vulnerable-rust-project");
const dependencyRiskFixturePath = resolve("test/fixtures/dependency-risk");
const unsafeDocumentedFixturePath = resolve("test/fixtures/unsafe-documented");

describe("MCP audit tools", () => {
  it("lists MCP tools through an MCP client transport", async () => {
    await withMcpClient(async (client) => {
      const result = await client.listTools();
      const toolNames = result.tools.map((tool) => tool.name).sort();

      assert.deepEqual(toolNames, [...mcpToolNames].sort());
      assert.match(
        result.tools.find((tool) => tool.name === "rust_audit_project")?.description ?? "",
        /release|full-project/i
      );
      assert.match(
        result.tools.find((tool) => tool.name === "rust_audit_unsafe")?.description ?? "",
        /unsafe \/ FFI|unsafe/i
      );
      assert.match(
        result.tools.find((tool) => tool.name === "rust_audit_dependencies")?.description ?? "",
        /Cargo|supply-chain/i
      );
      assert.match(
        result.tools.find((tool) => tool.name === "rust_review_current_diff")?.description ?? "",
        /commit|PR/i
      );
    });
  });

  it("calls an MCP tool through an MCP client transport", async () => {
    await withMcpClient(async (client) => {
      const result = await client.callTool({
        name: "rust_audit_dependencies",
        arguments: {
          projectPath: dependencyRiskFixturePath
        }
      });

      assert.equal("content" in result, true);
      assert.equal(result.isError, false);

      const output = result.structuredContent as unknown as McpAuditToolOutput;
      assert.equal(output.tool, "rust_audit_dependencies");
      assert.equal(output.error, undefined);
      assert.ok(output.findings.length > 0);
      assert.ok(output.findings.every((finding) => finding.ruleId.startsWith("RSA-DEP-") || finding.ruleId.startsWith("RSA-BUILD-")));
    });
  });

  it("rust_audit_project scans a vulnerable Rust fixture and returns structured output", async () => {
    const output = await rustAuditProject({
      projectPath: vulnerableFixturePath,
      outputFormat: "markdown"
    });

    assert.equal(output.tool, "rust_audit_project");
    assert.equal(output.projectPath, vulnerableFixturePath);
    assert.equal(output.error, undefined);
    assert.ok(output.summary.findingCount >= 10);
    assert.equal(output.summary.findingCount, output.findings.length);
    assert.equal(output.summary.riskLevel, "high_risk");
    assert.ok(output.summary.severityCounts.high >= 1);
    assert.match(output.reportMarkdown ?? "", /# Rust Project Security Audit/);
  });

  it("rust_audit_unsafe only returns unsafe, FFI, and unsafe impl related findings", async () => {
    const output = await rustAuditUnsafe({
      projectPath: vulnerableFixturePath
    });

    assert.equal(output.error, undefined);
    assert.ok(output.findings.length > 0);
    assert.ok(
      output.findings.every(
        (finding) => finding.ruleId.startsWith("RSA-UNSAFE-") || finding.ruleId.startsWith("RSA-FFI-")
      )
    );
    assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-UNSAFE-IMPL-SEND"));
    assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-FFI-EXTERN-C"));
    assert.equal(output.findings.some((finding) => finding.ruleId.startsWith("RSA-DEP-")), false);
  });

  it("rust_audit_unsafe can omit documented unsafe block findings", async () => {
    const output = await rustAuditUnsafe({
      projectPath: unsafeDocumentedFixturePath,
      includeDocumentedUnsafe: false
    });

    assert.equal(output.error, undefined);
    assert.equal(output.findings.some((finding) => finding.ruleId === "RSA-UNSAFE-BLOCK"), false);
  });

  it("rust_audit_dependencies only returns dependency, build, and supply-chain findings", async () => {
    const output = await rustAuditDependencies({
      projectPath: dependencyRiskFixturePath
    });

    assert.equal(output.error, undefined);
    assert.ok(output.findings.length > 0);
    assert.ok(
      output.findings.every(
        (finding) => finding.ruleId.startsWith("RSA-DEP-") || finding.ruleId.startsWith("RSA-BUILD-")
      )
    );
    assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-BUILD-COMMAND"));
    assert.equal(output.findings.some((finding) => finding.ruleId.startsWith("RSA-UNSAFE-")), false);
  });

  it("rust_review_current_diff returns findings for diff-affected files", async () => {
    const tempRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-mcp-"));
    const repoPath = join(tempRoot, "repo");

    try {
      await cp(vulnerableFixturePath, repoPath, { recursive: true });
      await runShellCommandOrThrow("git", ["init"], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["config", "user.email", "tester@example.com"], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["config", "user.name", "Rust Security Auditor Test"], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["add", "."], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["commit", "-m", "initial fixture"], { cwd: repoPath });
      await appendFile(join(repoPath, "src/lib.rs"), "\n// touch unsafe review file\n", "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath
      });

      assert.equal(output.error, undefined);
      assert.deepEqual(output.diffAffectedFiles, ["src/lib.rs"]);
      assert.ok(output.findings.length > 0);
      assert.ok(output.findings.every((finding) => finding.file === "src/lib.rs"));
      assert.equal(output.findings.some((finding) => finding.file === "Cargo.toml"), false);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("returns a clear error for invalid projectPath", async () => {
    const output = await rustAuditProject({
      projectPath: resolve("test/fixtures/does-not-exist")
    });

    assert.equal(output.tool, "rust_audit_project");
    assert.equal(output.summary.findingCount, 0);
    assert.equal(output.findings.length, 0);
    assert.equal(output.error?.code, "PROJECT_PATH_NOT_FOUND");
    assert.match(output.error?.message ?? "", /projectPath does not exist/);
  });

  it("returns a clear error when projectPath is not a Rust project", async () => {
    const tempRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-not-rust-"));

    try {
      const output = await rustAuditProject({
        projectPath: tempRoot
      });

      assert.equal(output.tool, "rust_audit_project");
      assert.equal(output.summary.findingCount, 0);
      assert.equal(output.findings.length, 0);
      assert.equal(output.error?.code, "PROJECT_PATH_NOT_RUST_PROJECT");
      assert.match(output.error?.message ?? "", /not a Rust project/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("returns a readable warning when git diff is unavailable", async () => {
    const tempRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-no-git-"));
    const projectPath = join(tempRoot, "repo");

    try {
      await cp(vulnerableFixturePath, projectPath, { recursive: true });

      const output = await rustReviewCurrentDiff({
        projectPath
      });

      assert.equal(output.error, undefined);
      assert.deepEqual(output.diffAffectedFiles, []);
      assert.equal(output.findings.length, 0);
      assert.match(output.warnings?.join("\n") ?? "", /git diff is unavailable/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });
});

async function withMcpClient(callback: (client: Client) => Promise<void>): Promise<void> {
  const server = createRustSecurityAuditorMcpServer();
  const client = new Client({
    name: "rust-security-auditor-smoke-test",
    version: "0.0.0"
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  try {
    await callback(client);
  } finally {
    await client.close();
    await server.close();
  }
}

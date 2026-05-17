import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
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

  it("rust_review_current_diff classifies introduced, nearby, and pre-existing findings", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown"
      });

      assert.equal(output.error, undefined);
      assert.deepEqual(output.diffAffectedFiles, ["src/lib.rs"]);
      assert.ok(output.diff?.files[0]?.hunks.some((hunk) => hunk.addedLines.length > 0));
      assert.equal(output.diffReview?.mode, "working_tree");
      assert.equal(output.diffReview?.includePreExisting, false);
      assert.ok((output.diffReview?.relationCounts.introduced_by_diff ?? 0) >= 2);
      assert.ok((output.diffReview?.relationCounts.near_changed_lines ?? 0) >= 2);
      assert.ok((output.diffReview?.relationCounts.pre_existing_in_changed_file ?? 0) >= 2);
      assert.ok((output.diffReview?.hiddenPreExistingCount ?? 0) >= 2);
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "introduced_by_diff"));
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "near_changed_lines"));
      assert.equal(
        output.enrichedFindings?.some((item) => item.diffContext.relation === "pre_existing_in_changed_file"),
        false
      );
      assert.equal(output.findings.some((finding) => finding.evidence.join("\n").includes("legacy_far")), false);
      assert.match(output.reportMarkdown ?? "", /## Introduced by this diff/);
      assert.match(output.reportMarkdown ?? "", /## Near changed lines/);
      assert.match(output.reportMarkdown ?? "", /Hidden pre-existing findings/);
      assert.match(output.reportMarkdown ?? "", /Conclusion: Needs attention/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff can include pre-existing findings in changed files", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        includePreExisting: true
      });

      assert.equal(output.error, undefined);
      assert.equal(output.diffReview?.includePreExisting, true);
      assert.equal(output.diffReview?.hiddenPreExistingCount, 0);
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "pre_existing_in_changed_file"));
      assert.ok(output.findings.some((finding) => finding.evidence.join("\n").includes("legacy_far")));
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff supports staged diffs", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");
      await runShellCommandOrThrow("git", ["add", "src/lib.rs"], { cwd: repoPath });

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        staged: true
      });

      assert.equal(output.error, undefined);
      assert.equal(output.diffReview?.mode, "staged");
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "introduced_by_diff"));
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff supports baseRef/headRef diffs", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");
      await runShellCommandOrThrow("git", ["add", "src/lib.rs"], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["commit", "-m", "introduce unsafe diff"], { cwd: repoPath });

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        baseRef: "HEAD~1",
        headRef: "HEAD"
      });

      assert.equal(output.error, undefined);
      assert.equal(output.diffReview?.mode, "range");
      assert.deepEqual(output.diffAffectedFiles, ["src/lib.rs"]);
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "introduced_by_diff"));
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

  it("returns a clear error when current diff review runs outside a git repo", async () => {
    const tempRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-no-git-"));
    const projectPath = join(tempRoot, "repo");

    try {
      await cp(vulnerableFixturePath, projectPath, { recursive: true });

      const output = await rustReviewCurrentDiff({
        projectPath
      });

      assert.equal(output.error?.code, "PROJECT_PATH_NOT_GIT_REPO");
      assert.equal(output.findings.length, 0);
      assert.match(output.error?.message ?? "", /Git work tree/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });
});

async function createDiffReviewRepo(): Promise<{ tempRoot: string; repoPath: string }> {
  const tempRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-diff-"));
  const repoPath = join(tempRoot, "repo");

  await mkdir(join(repoPath, "src"), { recursive: true });
  await writeFile(
    join(repoPath, "Cargo.toml"),
    `[package]
name = "diff_review_fixture"
version = "0.1.0"
edition = "2021"
`,
    "utf8"
  );
  await writeFile(join(repoPath, "src/lib.rs"), initialDiffReviewLibSource(), "utf8");
  await runShellCommandOrThrow("git", ["init"], { cwd: repoPath });
  await runShellCommandOrThrow("git", ["config", "user.email", "tester@example.com"], { cwd: repoPath });
  await runShellCommandOrThrow("git", ["config", "user.name", "Rust Security Auditor Test"], { cwd: repoPath });
  await runShellCommandOrThrow("git", ["add", "."], { cwd: repoPath });
  await runShellCommandOrThrow("git", ["commit", "-m", "initial fixture"], { cwd: repoPath });

  return { tempRoot, repoPath };
}

function initialDiffReviewLibSource(): string {
  return `${[
    "pub fn stable() -> u8 {",
    "    1",
    "}",
    "",
    "pub unsafe fn legacy_near(ptr: *const u8) -> u8 {",
    "    unsafe { *ptr }",
    "}",
    "",
    "pub fn padding_01() -> u8 { 1 }",
    "pub fn padding_02() -> u8 { 2 }",
    "pub fn padding_03() -> u8 { 3 }",
    "pub fn padding_04() -> u8 { 4 }",
    "pub fn padding_05() -> u8 { 5 }",
    "pub fn padding_06() -> u8 { 6 }",
    "pub fn padding_07() -> u8 { 7 }",
    "pub fn padding_08() -> u8 { 8 }",
    "pub fn padding_09() -> u8 { 9 }",
    "pub fn padding_10() -> u8 { 10 }",
    "",
    "pub unsafe fn legacy_far(ptr: *const u8) -> u8 {",
    "    unsafe { *ptr }",
    "}",
    "",
    "pub fn tail_01() -> u8 { 1 }",
    "pub fn tail_02() -> u8 { 2 }",
    "pub fn tail_03() -> u8 { 3 }",
    "pub fn tail_04() -> u8 { 4 }",
    "pub fn tail_05() -> u8 { 5 }",
    "pub fn tail_06() -> u8 { 6 }",
    "pub fn tail_07() -> u8 { 7 }",
    "pub fn tail_08() -> u8 { 8 }",
    "pub fn tail_09() -> u8 { 9 }",
    "pub fn tail_10() -> u8 { 10 }",
    "pub fn tail_11() -> u8 { 11 }",
    "pub fn tail_12() -> u8 { 12 }"
  ].join("\n")}\n`;
}

function changedLineAwareLibSource(): string {
  const lines = initialDiffReviewLibSource().trimEnd().split("\n");
  lines.splice(7, 0, "// touched near legacy unsafe");
  lines.push(
    "",
    "pub unsafe fn introduced(ptr: *const u8) -> u8 {",
    "    unsafe { *ptr }",
    "}"
  );
  return `${lines.join("\n")}\n`;
}

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

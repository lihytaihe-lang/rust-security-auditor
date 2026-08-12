#!/usr/bin/env node
/**
 * Regenerates the sanitized sample outputs in examples/reports/.
 *
 * The samples are captured through the real stdio MCP server so they show what
 * a client actually receives, not what an internal helper returns. Absolute
 * paths are rewritten to `<repo>` before anything is written to disk.
 *
 * Usage: npm run build && node scripts/regenerate-examples.mjs
 */
import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { sanitizeArtifactValue } from "../dist/src/release/artifactPrivacy.js";

const repoRoot = resolve(".");
const serverPath = join(repoRoot, "dist/src/mcp/server.js");
const outputDirectory = join(repoRoot, "examples/reports");

const SAMPLES = [
  {
    file: "rust_audit_project.json",
    tool: "rust_audit_project",
    args: { projectPath: "test/fixtures/vulnerable-rust-project", outputFormat: "markdown", pathMode: "relative" }
  },
  {
    file: "rust_audit_unsafe.json",
    tool: "rust_audit_unsafe",
    args: {
      projectPath: "test/fixtures/vulnerable-rust-project",
      includeDocumentedUnsafe: true,
      outputFormat: "markdown",
      pathMode: "relative"
    }
  },
  {
    file: "rust_audit_dependencies.json",
    tool: "rust_audit_dependencies",
    args: { projectPath: "test/fixtures/dependency-risk", outputFormat: "markdown", pathMode: "relative" }
  },
  {
    file: "rust_list_accepted_risks.json",
    tool: "rust_list_accepted_risks",
    args: {
      projectPath: "test/fixtures/suppressed-rust-project",
      includeExpired: true,
      includeInvalid: true,
      outputFormat: "markdown",
      pathMode: "relative"
    }
  }
];

const MARKDOWN_SAMPLES = [
  { file: "rust_audit_project.md", from: "rust_audit_project.json" },
  { file: "rust_list_accepted_risks.md", from: "rust_list_accepted_risks.json" }
];

function sanitize(value) {
  return sanitizeArtifactValue(value, [repoRoot]);
}

class McpClient {
  constructor() {
    this.child = spawn(process.execPath, [serverPath], { stdio: ["pipe", "pipe", "inherit"] });
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = "";

    this.child.stdout.on("data", (chunk) => {
      this.buffer += chunk.toString();
      let newline;
      while ((newline = this.buffer.indexOf("\n")) !== -1) {
        const line = this.buffer.slice(0, newline).trim();
        this.buffer = this.buffer.slice(newline + 1);
        if (line.length === 0) continue;

        const message = JSON.parse(line);
        const resolvePending = this.pending.get(message.id);
        if (resolvePending !== undefined) {
          this.pending.delete(message.id);
          resolvePending(message);
        }
      }
    });
  }

  request(method, params) {
    const id = this.nextId++;
    const promise = new Promise((resolvePending) => this.pending.set(id, resolvePending));
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    return promise;
  }

  notify(method, params) {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  }

  close() {
    this.child.kill();
  }
}

const client = new McpClient();

await client.request("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "regenerate-examples", version: "1.0.0" }
});
client.notify("notifications/initialized", {});

const toolList = await client.request("tools/list", {});
await writeFile(
  join(outputDirectory, "mcp-tool-list.json"),
  `${JSON.stringify(sanitize({ tools: toolList.result.tools }), null, 2)}\n`
);
console.log("wrote mcp-tool-list.json");

const captured = new Map();

for (const sample of SAMPLES) {
  const response = await client.request("tools/call", {
    name: sample.tool,
    arguments: { ...sample.args, projectPath: join(repoRoot, sample.args.projectPath) }
  });

  const envelope = sanitize({
    tool: sample.tool,
    isError: response.result.isError === true,
    structuredContent: response.result.structuredContent
  });

  captured.set(sample.file, envelope);
  await writeFile(join(outputDirectory, sample.file), `${JSON.stringify(envelope, null, 2)}\n`);
  console.log(`wrote ${sample.file}`);
}

for (const sample of MARKDOWN_SAMPLES) {
  const markdown = captured.get(sample.from)?.structuredContent?.reportMarkdown;
  if (typeof markdown !== "string") {
    console.error(`no reportMarkdown captured for ${sample.from}; skipped ${sample.file}`);
    continue;
  }

  await writeFile(join(outputDirectory, sample.file), markdown.endsWith("\n") ? markdown : `${markdown}\n`);
  console.log(`wrote ${sample.file}`);
}

client.close();
console.log("\nReview the diff before committing: samples must not contain local paths.");

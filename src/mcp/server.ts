#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import * as z from "zod/v4";
import {
  rustAuditDependencies,
  rustAuditProject,
  rustAuditUnsafe,
  rustListAcceptedRisks,
  rustReviewCurrentDiff
} from "./tools.js";
import type { McpToolOutput } from "./types.js";
import { isEntryPointModule } from "../utils/paths.js";
import { serverVersion } from "../version.js";

const outputFormatSchema = z.enum(["json", "markdown"]);
const pathModeSchema = z.enum(["relative", "absolute"]);
const reportModeSchema = z.enum(["full", "compact"]);
const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
};

export function createRustSecurityAuditorMcpServer(): McpServer {
  const server = new McpServer({
    name: "rust-security-auditor",
    version: serverVersion
  });

  server.registerTool(
    "rust_audit_project",
    {
      title: "Audit Rust project before release",
      description:
        "Use before a release or when the user asks for a full-project Rust security health check. Scans an entire local Cargo project or workspace and returns security findings across unsafe/FFI, dependencies, build scripts, filesystem, input-boundary, secrets, panic/DoS, and manual-review categories.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        projectPath: z
          .string()
          .min(1)
          .describe("Absolute or relative local directory for a Rust Cargo project or workspace; it must contain at least one Cargo.toml."),
        outputFormat: outputFormatSchema
          .optional()
          .describe("Omit or set to json for structured JSON; set to markdown to also include reportMarkdown text for display."),
        pathMode: pathModeSchema
          .optional()
          .describe("Controls paths in reportMarkdown. Defaults to relative to avoid leaking local absolute paths."),
        reportMode: reportModeSchema
          .optional()
          .describe("Controls reportMarkdown detail. Defaults to compact for developer handoff; use full for complete finding details."),
        includeSuppressed: z
          .boolean()
          .optional()
          .describe("When true, include findings that were hidden by inline rust-security-auditor suppression comments.")
      }
    },
    async (input) => toCallToolResult(await rustAuditProject(input))
  );

  server.registerTool(
    "rust_audit_unsafe",
    {
      title: "Audit Rust unsafe and FFI",
      description:
        "Use for specialized unsafe / FFI review, especially when code touches unsafe blocks, unsafe fn, raw pointers, MaybeUninit, transmute, from_raw_parts, set_len, Box::from_raw, extern \"C\", or unsafe Send/Sync impls. Returns only unsafe, raw-memory, concurrency unsafe impl, and FFI findings.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        projectPath: z
          .string()
          .min(1)
          .describe("Absolute or relative local directory for a Rust Cargo project or workspace; it must contain at least one Cargo.toml."),
        includeDocumentedUnsafe: z
          .boolean()
          .optional()
          .describe("When false, omit unsafe block findings that already have nearby SAFETY or Safety comments."),
        outputFormat: outputFormatSchema
          .optional()
          .describe("Omit or set to json for structured JSON; set to markdown to also include reportMarkdown text for display."),
        pathMode: pathModeSchema
          .optional()
          .describe("Controls paths in reportMarkdown. Defaults to relative to avoid leaking local absolute paths."),
        reportMode: reportModeSchema
          .optional()
          .describe("Controls reportMarkdown detail. Defaults to compact unsafe-review checklist; use full for complete finding details.")
      }
    },
    async (input) => toCallToolResult(await rustAuditUnsafe(input))
  );

  server.registerTool(
    "rust_audit_dependencies",
    {
      title: "Audit Rust Cargo dependencies",
      description:
        "Use for Cargo dependency and supply-chain review, especially when Cargo.toml, Cargo.lock, build.rs, build-dependencies, proc macros, git dependencies, or path dependencies change. Returns only Cargo, lockfile, build script, and build-time supply-chain findings.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        projectPath: z
          .string()
          .min(1)
          .describe("Absolute or relative local directory for a Rust Cargo project or workspace; it must contain at least one Cargo.toml."),
        outputFormat: outputFormatSchema
          .optional()
          .describe("Omit or set to json for structured JSON; set to markdown to also include reportMarkdown text for display."),
        pathMode: pathModeSchema
          .optional()
          .describe("Controls paths in reportMarkdown. Defaults to relative to avoid leaking local absolute paths."),
        reportMode: reportModeSchema
          .optional()
          .describe("Controls reportMarkdown detail. Defaults to compact supply-chain checklist; use full for complete finding details.")
      }
    },
    async (input) => toCallToolResult(await rustAuditDependencies(input))
  );

  server.registerTool(
    "rust_review_current_diff",
    {
      title: "Review current Rust diff before commit",
      description:
        "Use before commit, before opening a PR, after Codex generated code, or after touching unsafe Rust, dependencies, or build.rs. Parses git diff hunks, scans only changed files in the local Cargo project or workspace, returns reviewDecision, suppressionSummary, and suggestedFixPrompt values, and never automatically modifies code or adds suppressions.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        projectPath: z
          .string()
          .min(1)
          .describe("Absolute or relative local directory for a Rust Cargo project or workspace inside a Git work tree."),
        baseRef: z
          .string()
          .optional()
          .describe("Optional Git base ref for explicit diff review, for example main or origin/main."),
        headRef: z
          .string()
          .optional()
          .describe("Optional Git head ref for explicit diff review, for example HEAD or a feature branch."),
        staged: z
          .boolean()
          .optional()
          .describe("When true, review git diff --cached instead of the unstaged working tree diff."),
        includePreExisting: z
          .boolean()
          .optional()
          .describe("When true, include findings in changed files that are not close to added lines."),
        nearChangedLineWindow: z
          .number()
          .int()
          .min(0)
          .max(50)
          .optional()
          .describe("Line window for nearby legacy context classification. Defaults to 3."),
        outputFormat: outputFormatSchema
          .optional()
          .describe("Omit or set to json for structured JSON; set to markdown to also include reportMarkdown text for display."),
        pathMode: pathModeSchema
          .optional()
          .describe("Controls paths in reportMarkdown. Defaults to relative for shareable PR comments."),
        reportMode: reportModeSchema
          .optional()
          .describe("Controls reportMarkdown detail. Defaults to compact for Codex and PR comments; use full for complete details.")
      }
    },
    async (input) => toCallToolResult(await rustReviewCurrentDiff(input))
  );

  server.registerTool(
    "rust_list_accepted_risks",
    {
      title: "List accepted Rust security risks",
      description:
        "Use before release, during security re-review, when checking whether accepted-risk suppressions have expired, or when cleaning up invalid suppression comments. Scans only Rust source files for accepted-risk suppression comments and returns an accepted-risk inventory without running the full scanner and without modifying code.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        projectPath: z
          .string()
          .min(1)
          .describe("Absolute or relative local directory for a Rust Cargo project or workspace; only files under this directory are scanned."),
        includeExpired: z
          .boolean()
          .describe("When true, include expired accepted-risk suppression comments in acceptedRisks and the Markdown report."),
        includeInvalid: z
          .boolean()
          .describe("When true, include invalid accepted-risk suppression comments in acceptedRisks and the Markdown report."),
        outputFormat: outputFormatSchema.describe("Set to json for structured JSON; set to markdown to include reportMarkdown text for display."),
        pathMode: pathModeSchema
          .optional()
          .describe("Controls paths in reportMarkdown. Defaults to relative to avoid leaking local absolute paths.")
      }
    },
    async (input) => toCallToolResult(await rustListAcceptedRisks(input))
  );

  return server;
}

export async function startRustSecurityAuditorMcpServer(): Promise<void> {
  const server = createRustSecurityAuditorMcpServer();
  await server.connect(new StdioServerTransport());
}

function toCallToolResult(output: McpToolOutput): CallToolResult {
  return {
    content: [
      {
        type: "text",
        text: output.reportMarkdown ?? `${JSON.stringify(output, null, 2)}\n`
      }
    ],
    structuredContent: output as unknown as Record<string, unknown>,
    isError: output.error !== undefined
  };
}

function isDirectRun(): boolean {
  return isEntryPointModule(import.meta.url);
}

if (isDirectRun()) {
  startRustSecurityAuditorMcpServer().catch((error: unknown) => {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    console.error(message);
    process.exit(1);
  });
}

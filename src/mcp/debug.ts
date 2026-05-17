#!/usr/bin/env node
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { callRustAuditTool, isMcpToolName } from "./tools.js";
import type { McpToolName, RustAuditToolInput } from "./types.js";

export async function runDebugTool(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  const [toolName, ...args] = argv;

  if (toolName === undefined || !isMcpToolName(toolName)) {
    printUsage();
    return 1;
  }

  const input = parseArgs(args);
  const output = await callRustAuditTool(toolName, input);
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  return output.error === undefined ? 0 : 1;
}

function parseArgs(args: readonly string[]): RustAuditToolInput {
  const input: Record<string, string | boolean> = {};

  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (current === undefined || !current.startsWith("--")) {
      throw new Error(`Unexpected argument: ${current ?? ""}`);
    }

    const key = current.slice(2);
    const next = args[index + 1];

    if (next === "true" || next === "false") {
      input[key] = next === "true";
      index += 1;
      continue;
    }

    if (next !== undefined && !next.startsWith("--")) {
      input[key] = next;
      index += 1;
      continue;
    }

    input[key] = true;
  }

  if (typeof input.projectPath !== "string") {
    input.projectPath = process.cwd();
  }

  return input as unknown as RustAuditToolInput;
}

function printUsage(): void {
  process.stderr.write(`Usage:
  node dist/src/mcp/debug.js <tool> --projectPath <path> [--outputFormat json|markdown]

Tools:
  rust_audit_project [--includeSuppressed true]
  rust_audit_unsafe [--includeDocumentedUnsafe false]
  rust_audit_dependencies
  rust_review_current_diff [--baseRef <ref>] [--headRef <ref>] [--staged true] [--includePreExisting true]
  rust_list_accepted_risks --includeExpired true --includeInvalid true [--outputFormat markdown]
`);
}

function isDirectRun(): boolean {
  return process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isDirectRun()) {
  runDebugTool().then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`${message}\n`);
      process.exitCode = 1;
    }
  );
}

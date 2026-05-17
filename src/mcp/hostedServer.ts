#!/usr/bin/env node
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  createHostedRustSecurityAuditorMcpServer,
  hostedMcpToolNames
} from "./hostedTools.js";

export interface HostedMcpHttpServerOptions {
  mcpPath?: string | undefined;
  allowedHosts?: readonly string[] | undefined;
  allowedOrigins?: readonly string[] | undefined;
}

const defaultMcpPath = "/mcp";
const defaultAllowedHosts = ["localhost", "127.0.0.1", "[::1]", "::1"] as const;
const defaultAllowedOrigins = ["https://chatgpt.com", "https://chat.openai.com"] as const;
const mcpMethods = new Set(["POST", "GET", "DELETE"]);

export function createHostedMcpHttpServer(options: HostedMcpHttpServerOptions = {}): Server {
  const mcpPath = options.mcpPath ?? defaultMcpPath;
  const allowedHosts = normalizeAllowedHosts([
    ...defaultAllowedHosts,
    ...parseCsv(process.env.HOSTED_MCP_ALLOWED_HOSTS),
    ...(options.allowedHosts ?? [])
  ]);
  const allowedOrigins = normalizeAllowedOrigins([
    ...defaultAllowedOrigins,
    ...parseCsv(process.env.HOSTED_MCP_ALLOWED_ORIGINS),
    ...(options.allowedOrigins ?? [])
  ]);

  return createServer(async (req, res) => {
    const url = requestUrl(req);
    if (url === undefined) {
      writeJson(res, 400, { error: "Missing or invalid request URL." });
      return;
    }

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/healthz")) {
      writeJson(res, 200, {
        status: "ok",
        name: "rust-security-auditor-hosted-demo",
        transport: "streamable_http",
        mode: "fixture_safe_stateless",
        mcpEndpoint: mcpPath,
        tools: hostedMcpToolNames,
        inputPolicy: "fixture_id, short pasted snippets, and public demo metadata only"
      });
      return;
    }

    if (url.pathname !== mcpPath) {
      writeJson(res, 404, { error: "Not Found" });
      return;
    }

    const hostError = validateHost(req, allowedHosts);
    if (hostError !== undefined) {
      writeJson(res, 403, { jsonrpc: "2.0", error: { code: -32000, message: hostError }, id: null });
      return;
    }

    const originError = validateOrigin(req, allowedOrigins);
    if (originError !== undefined) {
      writeJson(res, 403, { jsonrpc: "2.0", error: { code: -32000, message: originError }, id: null });
      return;
    }

    applyCorsHeaders(req, res, allowedOrigins);

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === undefined || !mcpMethods.has(req.method)) {
      writeJson(res, 405, { jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null }, {
        Allow: "GET, POST, DELETE, OPTIONS"
      });
      return;
    }

    const mcpServer = createHostedRustSecurityAuditorMcpServer();
    const transport = new StreamableHTTPServerTransport({
      enableJsonResponse: true
    });

    res.on("close", () => {
      void transport.close();
      void mcpServer.close();
    });

    try {
      await mcpServer.connect(transport as unknown as Transport);
      await transport.handleRequest(req, res);
    } catch (error) {
      console.error(`Hosted MCP request failed: ${sanitizeErrorMessage(error)}`);
      if (!res.headersSent) {
        writeJson(res, 500, {
          jsonrpc: "2.0",
          error: {
            code: -32603,
            message: "Internal server error"
          },
          id: null
        });
      }
    }
  });
}

function requestUrl(req: IncomingMessage): URL | undefined {
  if (req.url === undefined) return undefined;

  try {
    return new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
  } catch {
    return undefined;
  }
}

function validateHost(req: IncomingMessage, allowedHosts: readonly string[]): string | undefined {
  const hostHeader = headerValue(req.headers.host);
  if (hostHeader === undefined) {
    return "Forbidden: missing Host header.";
  }

  const host = normalizeHost(hostHeader);
  if (allowedHosts.includes("*") || allowedHosts.some((allowed) => hostMatches(host, allowed))) {
    return undefined;
  }

  return "Forbidden: Host header is not allowed for this hosted MCP server.";
}

function validateOrigin(req: IncomingMessage, allowedOrigins: readonly string[]): string | undefined {
  const origin = headerValue(req.headers.origin);
  if (origin === undefined) return undefined;
  if (allowedOrigins.includes("*")) return undefined;

  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return "Forbidden: invalid Origin header.";
  }

  if (isLocalHostname(parsed.hostname)) return undefined;

  const normalizedOrigin = normalizeOrigin(origin);
  if (allowedOrigins.includes(normalizedOrigin)) return undefined;

  return "Forbidden: Origin header is not allowed for this hosted MCP server.";
}

function applyCorsHeaders(req: IncomingMessage, res: ServerResponse, allowedOrigins: readonly string[]): void {
  const origin = headerValue(req.headers.origin);

  if (origin !== undefined && (allowedOrigins.includes("*") || validateOrigin(req, allowedOrigins) === undefined)) {
    res.setHeader("Access-Control-Allow-Origin", allowedOrigins.includes("*") ? "*" : normalizeOrigin(origin));
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Accept, Content-Type, MCP-Protocol-Version, Mcp-Session-Id, Last-Event-ID"
  );
  res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
}

function writeJson(
  res: ServerResponse,
  statusCode: number,
  body: unknown,
  headers: Record<string, string> = {}
): void {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    ...headers
  });
  res.end(`${JSON.stringify(body)}\n`);
}

function normalizeAllowedHosts(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => normalizeHost(value)).filter((value) => value.length > 0))];
}

function normalizeAllowedOrigins(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => normalizeOrigin(value)).filter((value) => value.length > 0))];
}

function normalizeOrigin(value: string): string {
  const trimmed = value.trim().replace(/\/$/, "");
  if (trimmed === "*") return "*";

  try {
    const url = new URL(trimmed);
    const port = url.port.length === 0 ? "" : `:${url.port}`;
    return `${url.protocol}//${url.hostname}${port}`;
  } catch {
    return trimmed;
  }
}

function normalizeHost(value: string): string {
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "*") return "*";
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    try {
      return normalizeHost(new URL(trimmed).host);
    } catch {
      return trimmed;
    }
  }

  if (trimmed.startsWith("[")) {
    const bracketEnd = trimmed.indexOf("]");
    return bracketEnd === -1 ? trimmed : trimmed.slice(0, bracketEnd + 1);
  }

  const colonIndex = trimmed.lastIndexOf(":");
  if (colonIndex > -1 && /^\d+$/.test(trimmed.slice(colonIndex + 1))) {
    return trimmed.slice(0, colonIndex);
  }

  return trimmed;
}

function hostMatches(host: string, allowed: string): boolean {
  if (allowed === "*") return true;
  if (allowed.startsWith(".")) return host === allowed.slice(1) || host.endsWith(allowed);
  return host === allowed;
}

function isLocalHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1" || normalized === "[::1]";
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function parseCsv(value: string | undefined): string[] {
  if (value === undefined) return [];
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function sanitizeErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/\/(?:Users|Volumes|home|private|var|tmp|etc|opt|mnt|workspace)\/[^\s)'"`]+/g, "<redacted-path>")
    .replace(/[A-Za-z]:\\[^\s)'"`]+/g, "<redacted-path>")
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}\b/g, "<redacted-token>")
    .replace(/\bgithub_pat_[A-Za-z0-9_]{8,}\b/g, "<redacted-token>")
    .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{8,}\b/g, "<redacted-token>");
}

function isDirectRun(): boolean {
  return process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isDirectRun()) {
  const port = Number.parseInt(process.env.PORT ?? "8787", 10);
  const host = process.env.HOST ?? "127.0.0.1";
  const server = createHostedMcpHttpServer();

  server.listen(port, host, () => {
    console.error(`Rust Security Auditor hosted MCP listening on http://${host}:${port}${defaultMcpPath}`);
  });
}

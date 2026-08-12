#!/usr/bin/env node
/**
 * Release-local verification only: creates a real npm tarball in a temporary
 * directory, inspects its unpacked entries, installs it fresh, and exercises
 * the installed stdio binary. It never publishes or touches a registry.
 */
import { spawn } from "node:child_process";
import { gunzipSync } from "node:zlib";
import { lstat, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { findArtifactPathLeaks } from "../dist/src/release/artifactPrivacy.js";

const repoRoot = resolve(".");
const temporaryRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-package-"));
const packDirectory = join(temporaryRoot, "pack");
const installDirectory = join(temporaryRoot, "install");

try {
  await mkdir(packDirectory, { recursive: true });
  const pack = await run(npmCommand(), ["pack", "--json", "--pack-destination", packDirectory], { cwd: repoRoot });
  const packed = JSON.parse(pack.stdout);
  const filename = packed[0]?.filename;
  if (typeof filename !== "string" || filename.length === 0) throw new Error("npm pack did not return a tarball filename.");
  const tarballPath = join(packDirectory, filename);
  const entries = unpackTarGz(await readFile(tarballPath));
  assertPublicPackageBoundary(entries);

  await run(npmCommand(), ["install", "--ignore-scripts", "--no-package-lock", "--prefix", installDirectory, tarballPath], {
    cwd: temporaryRoot
  });
  const binPath = join(installDirectory, "node_modules", ".bin", process.platform === "win32" ? "rust-security-auditor.cmd" : "rust-security-auditor");
  const binStat = await lstat(binPath);
  if (process.platform !== "win32" && !binStat.isSymbolicLink()) {
    throw new Error("Installed primary MCP bin is not the expected node_modules/.bin symbolic link.");
  }

  await verifyInstalledMcp(binPath);
  process.stdout.write(`verified ${filename}: tarball boundary, fresh install, .bin launch, and stdio MCP handshake passed\n`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

function assertPublicPackageBoundary(entries) {
  const names = entries.map((entry) => entry.name);
  const forbiddenNames = ["hosted", "docs/internal", "PUBLIC_READINESS_SECURITY_REMEDIATION_PLAN"];
  for (const name of names) {
    if (forbiddenNames.some((forbidden) => name.toLowerCase().includes(forbidden.toLowerCase()))) {
      throw new Error(`Forbidden release artifact entry: ${name}`);
    }
  }

  const packageJson = entries.find((entry) => entry.name === "package/package.json");
  if (packageJson === undefined) throw new Error("npm tarball is missing package/package.json.");
  const packageMetadata = JSON.parse(packageJson.content.toString("utf8"));
  if (Object.keys(packageMetadata.bin ?? {}).some((name) => name.includes("hosted"))) {
    throw new Error("Tarball package metadata still exposes a hosted bin.");
  }
  if (Object.keys(packageMetadata.exports ?? {}).some((name) => name.includes("hosted"))) {
    throw new Error("Tarball package metadata still exposes a hosted export.");
  }

  for (const entry of entries) {
    const text = entry.content.toString("utf8");
    const leaks = findArtifactPathLeaks(`${entry.name}\n${entry.linkname}\n${text}`, [repoRoot]);
    if (leaks.length > 0) throw new Error(`Path leak in ${entry.name}: ${leaks.join(", ")}`);
    if (/rust-security-auditor-hosted|hostedServer|hostedTools|hostedFixtures/i.test(`${entry.name}\n${text}`)) {
      throw new Error(`Hosted runtime leaked into tarball: ${entry.name}`);
    }
  }
}

async function verifyInstalledMcp(binPath) {
  const child = spawn(binPath, [], { cwd: repoRoot, stdio: ["pipe", "pipe", "pipe"] });
  const pending = new Map();
  const stdoutLines = [];
  let buffer = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    buffer += chunk.toString();
    let newline;
    while ((newline = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line.length === 0) continue;
      stdoutLines.push(line);
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        rejectAll(new Error(`Installed MCP bin wrote non-JSON data to stdout: ${line}`));
        return;
      }
      const resolvePending = pending.get(message.id);
      if (resolvePending !== undefined) {
        pending.delete(message.id);
        resolvePending(message);
      }
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  let nextId = 1;
  const request = (method, params) => {
    const id = nextId++;
    const response = new Promise((resolveResponse, rejectResponse) => {
      const timeout = setTimeout(() => {
        pending.delete(id);
        rejectResponse(new Error(`Timed out waiting for ${method}; stderr: ${stderr}`));
      }, 10_000);
      pending.set(id, (message) => {
        clearTimeout(timeout);
        resolveResponse(message);
      });
    });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    return response;
  };
  const notify = (method, params) => child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  const rejectAll = (error) => {
    for (const resolvePending of pending.values()) resolvePending(Promise.reject(error));
    pending.clear();
  };

  try {
    const initialized = await request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "package-verifier", version: "1.0.0" }
    });
    if (initialized.result?.serverInfo?.name !== "rust-security-auditor") throw new Error("Installed bin did not complete initialize.");
    notify("notifications/initialized", {});
    const list = await request("tools/list", {});
    if (!Array.isArray(list.result?.tools) || !list.result.tools.some((tool) => tool.name === "rust_audit_project")) {
      throw new Error("Installed bin did not return the local audit tools from tools/list.");
    }
    const called = await request("tools/call", {
      name: "rust_audit_project",
      arguments: { projectPath: join(repoRoot, "test/fixtures/safe-rust-project"), outputFormat: "json" }
    });
    if (called.result?.isError === true || called.result?.structuredContent?.tool !== "rust_audit_project") {
      throw new Error("Installed bin did not complete the required tools/call.");
    }
    if (stdoutLines.some((line) => !line.startsWith("{"))) throw new Error("Installed bin wrote a non-JSON-RPC frame to stdout.");
  } finally {
    child.kill();
  }
}

function unpackTarGz(buffer) {
  const tar = gunzipSync(buffer);
  const entries = [];
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = readTarText(header, 0, 100);
    const prefix = readTarText(header, 345, 155);
    const fullName = prefix.length > 0 ? `${prefix}/${name}` : name;
    const sizeText = readTarText(header, 124, 12).trim();
    const size = sizeText.length === 0 ? 0 : Number.parseInt(sizeText, 8);
    if (!Number.isSafeInteger(size) || size < 0) throw new Error(`Invalid tar size for ${fullName}`);
    const linkname = readTarText(header, 157, 100);
    const start = offset + 512;
    const end = start + size;
    if (end > tar.length) throw new Error(`Truncated tar entry: ${fullName}`);
    entries.push({ name: fullName, linkname, content: tar.subarray(start, end) });
    offset = start + Math.ceil(size / 512) * 512;
  }
  return entries;
}

function readTarText(buffer, start, length) {
  const end = buffer.subarray(start, start + length).indexOf(0);
  return buffer.subarray(start, start + (end === -1 ? length : end)).toString("utf8");
}

function npmCommand() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

function run(command, args, options) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
    child.on("error", rejectRun);
    child.on("close", (code) => {
      if (code === 0) resolveRun({ stdout, stderr });
      else rejectRun(new Error(`${command} ${args.join(" ")} failed (${code}): ${stderr || stdout}`));
    });
  });
}

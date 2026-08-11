import { readdir, readFile, stat } from "node:fs/promises";
import { basename, dirname, join, relative, sep } from "node:path";

const ignoredDirectoryNames = new Set([
  ".git",
  ".hg",
  ".svn",
  ".idea",
  ".vscode",
  "dist",
  "node_modules",
  "target"
]);

/** Files larger than this are skipped; generated or vendored blobs are not review material. */
export const defaultMaxFileBytes = 2 * 1024 * 1024;

/** Upper bound on discovered files, so a mistargeted path cannot stall the MCP client. */
export const defaultMaxFiles = 50_000;

export interface WorkspaceFileScanOptions {
  maxFileBytes?: number;
  maxFiles?: number;
}

export interface WorkspaceFileScan {
  files: string[];
  warnings: string[];
}

export async function collectWorkspaceFiles(
  rootPath: string,
  options: WorkspaceFileScanOptions = {}
): Promise<WorkspaceFileScan> {
  const maxFileBytes = options.maxFileBytes ?? defaultMaxFileBytes;
  const maxFiles = options.maxFiles ?? defaultMaxFiles;
  const state: CollectState = {
    files: [],
    maxFileBytes,
    maxFiles,
    skippedLargeFiles: 0,
    skippedSymlinks: 0,
    unreadableDirectories: 0,
    truncated: false
  };

  await collect(rootPath, state);
  state.files.sort((left, right) => left.localeCompare(right));

  const warnings: string[] = [];

  if (state.truncated) {
    warnings.push(
      `File discovery stopped at ${maxFiles} files; scan results are incomplete. Point the scan at a narrower directory.`
    );
  }

  if (state.skippedLargeFiles > 0) {
    warnings.push(
      `${state.skippedLargeFiles} file(s) larger than ${Math.round(maxFileBytes / 1024)} KiB were skipped and not scanned.`
    );
  }

  if (state.skippedSymlinks > 0) {
    warnings.push(
      `${state.skippedSymlinks} symbolic link(s) were not followed; linked code outside the project was not scanned.`
    );
  }

  if (state.unreadableDirectories > 0) {
    warnings.push(`${state.unreadableDirectories} directory/directories could not be read and were skipped.`);
  }

  return { files: state.files, warnings };
}

export async function readTextLines(absolutePath: string): Promise<string[]> {
  const text = await readFile(absolutePath, "utf8");
  return text.split(/\r?\n/);
}

export function toRelativeFile(rootPath: string, absolutePath: string): string {
  const path = relative(rootPath, absolutePath);
  return path.split(sep).join("/");
}

export function firstMeaningfulLine(lines: readonly string[]): number {
  const index = lines.findIndex((line) => line.trim().length > 0);
  return index === -1 ? 1 : index + 1;
}

export function isCommentOnlyLine(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.length === 0 ||
    trimmed.startsWith("//") ||
    trimmed.startsWith("///") ||
    trimmed.startsWith("//!") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("/*") ||
    trimmed.startsWith("*")
  );
}

/**
 * Removes a TOML `#` comment, ignoring `#` characters inside quoted strings so
 * that values such as a git URL fragment survive.
 */
export function stripTomlComment(line: string): string {
  let inString = false;
  let quote = "";

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];

    if (inString) {
      if (char === "\\") {
        index += 1;
        continue;
      }
      if (char === quote) inString = false;
      continue;
    }

    if (char === '"' || char === "'") {
      inString = true;
      quote = char;
      continue;
    }

    if (char === "#") {
      return line.slice(0, index);
    }
  }

  return line;
}

export function quotedTomlStrings(value: string): string[] {
  return [...value.matchAll(/"([^"]+)"/g)].map((match) => match[1]).filter((item): item is string => item !== undefined);
}

export function isCargoTomlPath(path: string): boolean {
  return basename(path) === "Cargo.toml";
}

export function isCargoLockPath(path: string): boolean {
  return basename(path) === "Cargo.lock";
}

export function isBuildScriptPath(path: string): boolean {
  return basename(path) === "build.rs";
}

export function isRustSourcePath(path: string): boolean {
  return path.endsWith(".rs");
}

/** Matches `.cargo/config.toml` and the legacy extension-less `.cargo/config`. */
export function isCargoConfigPath(path: string): boolean {
  const name = basename(path);
  if (name !== "config.toml" && name !== "config") return false;
  return basename(dirname(path)) === ".cargo";
}

interface CollectState {
  files: string[];
  maxFileBytes: number;
  maxFiles: number;
  skippedLargeFiles: number;
  skippedSymlinks: number;
  unreadableDirectories: number;
  truncated: boolean;
}

async function collect(directory: string, state: CollectState): Promise<void> {
  if (state.truncated) return;

  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    state.unreadableDirectories += 1;
    return;
  }

  for (const entry of entries) {
    if (state.truncated) return;

    const absolutePath = join(directory, entry.name);

    if (entry.isSymbolicLink()) {
      state.skippedSymlinks += 1;
      continue;
    }

    if (entry.isDirectory()) {
      if (!ignoredDirectoryNames.has(entry.name)) {
        await collect(absolutePath, state);
      }
      continue;
    }

    if (!entry.isFile()) continue;

    if (!(await isWithinSizeLimit(absolutePath, state))) continue;

    if (state.files.length >= state.maxFiles) {
      state.truncated = true;
      return;
    }

    state.files.push(absolutePath);
  }
}

async function isWithinSizeLimit(absolutePath: string, state: CollectState): Promise<boolean> {
  // Only files the scanners actually read need a size check.
  if (
    !isRustSourcePath(absolutePath) &&
    !isCargoTomlPath(absolutePath) &&
    !isCargoLockPath(absolutePath) &&
    !isCargoConfigPath(absolutePath)
  ) {
    return true;
  }

  try {
    const stats = await stat(absolutePath);
    if (stats.size > state.maxFileBytes) {
      state.skippedLargeFiles += 1;
      return false;
    }
  } catch {
    return false;
  }

  return true;
}
